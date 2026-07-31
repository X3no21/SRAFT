/* =============================
 * File: auth_join.c
 * Description: Implements the definitive, synchronized, multi-verifier node join protocol.
 * ============================= */

#include "auth_join.h"
#include "rest_api.h"
#include "discovery.h"
#include "connection_pool.h"
#include "integrity_verification.h"
#include "raft_state.h"
#include "raft.h"
#include "auth_db.h"
#include "auth_puf.h"
#include "auth_remove.h"
#include "utility.h"
#include "nonce_manager.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <errno.h>
#include <cJSON.h>

static const char *TAG = "AUTH_JOIN";

static char legitimate_verifier_ips[MAX_VERIFIERS][INET_ADDRSTRLEN];
static int legitimate_verifier_count = 0;
static SemaphoreHandle_t new_node_state_mutex = NULL;

static JoinProcess pending_join;
static SemaphoreHandle_t join_mutex = NULL;

static JoinProcess pending_heal_jobs[MAX_PARALLEL_HEALS];
static SemaphoreHandle_t heal_pool_mutex = NULL;
static SemaphoreHandle_t worker_sync_sem = NULL;
static SemaphoreHandle_t bootstrap_completed_sem = NULL;

SemaphoreHandle_t join_result_semaphore = NULL;
bool join_result_success = false;

SemaphoreHandle_t caller_sync_sem = NULL;
volatile uint32_t parallel_job_failure_count = 0;
portMUX_TYPE parallel_job_failure_mux = portMUX_INITIALIZER_UNLOCKED;
QueueHandle_t join_request_queue = NULL;

static uint32_t last_transaction_id = 0;
static bool healing_mode_on_startup = false;
static bool is_healing_task_running = false;
static TaskHandle_t healing_task_handle = NULL;
static int expected_cluster_size = 0;

static TaskHandle_t join_watchdog_task_handle = NULL;
static TaskHandle_t join_manager_task_handle = NULL;

static portMUX_TYPE join_init_spinlock = portMUX_INITIALIZER_UNLOCKED;

#define TAKE_JOIN_MUTEX(func_name) do { \
    ESP_LOGD("JOIN_MUTEX", "Attempting to take lock in %s", func_name); \
    xSemaphoreTake(join_mutex, portMAX_DELAY); \
    ESP_LOGD("JOIN_MUTEX", ">> Lock TAKEN in %s", func_name); \
} while(0)

#define GIVE_JOIN_MUTEX(func_name) do { \
    ESP_LOGD("JOIN_MUTEX", "<< Lock GIVEN in %s", func_name); \
    xSemaphoreGive(join_mutex); \
} while(0)

#define TAKE_NEW_NODE_STATE_MUTEX(func_name) do { \
    ESP_LOGD("NEW_NODE_STATE_MUTEX", "Attempting to take lock in %s", func_name); \
    xSemaphoreTake(new_node_state_mutex, portMAX_DELAY); \
    ESP_LOGD("NEW_NODE_STATE_MUTEX", ">> Lock TAKEN in %s", func_name); \
} while(0)

#define GIVE_NEW_NODE_STATE_MUTEX(func_name) do { \
    ESP_LOGD("NEW_NODE_STATE_MUTEX", "<< Lock GIVEN in %s", func_name); \
    xSemaphoreGive(new_node_state_mutex); \
} while(0)

static void master_trigger_join_rollback(JoinProcess* job);
static void join_watchdog_task(void *pvParameters);
static bool is_ip_in_verifier_list(JoinProcess* job, const char *ip);
void master_assign_new_verifiers(JoinProcess* job, const char *target_ip, int num_to_add, uint32_t transaction_id);
void node_master_handle_join_request(const char *target_ip, join_request_type_t type, join_request_t request);
static char *merge_cnode_json(const char *base_json, const char *delta_json);
static void master_finalize_and_commit_join(JoinProcess* job);
void finalize_join_process(JoinProcess* job, bool is_success);
static void leader_finalize_commit(JoinProcess* job);
static void leader_delegate_genesis_credentials(JoinProcess* job, const char *new_follower_ip, cJSON *cnodes_delta_obj);
static void leader_heal_task_runner(void *pvParameters);
static void join_manager_task(void *pvParameters);
static void leader_initiate_full_cluster_join();


/**
 * @brief (Leader-only) Triggers a rollback of the current join process.
 * @details This function is called on timeout or vo unerification failure. It notifies all participants
 * (verifiers and the new node) to abort the transaction and cleans up the leader's state.
 */
static void master_trigger_join_rollback(JoinProcess* job) {
    if (!job || !job->in_use) {
        return;
    }

    ESP_LOGW(TAG, "[JoinID: %lu] Triggering join rollback for node %s.", job->transaction_id, job->new_node_ip);

    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

    char abort_msg[128];
    snprintf(abort_msg, sizeof(abort_msg), "%s:%lu:%s:%s\n", MSG_JOIN_ABORT, job->transaction_id, job->new_node_ip, nonce_hex);
    ESP_LOGI(TAG, "[JoinID: %lu] Notifying %d verifiers to abort transaction.", job->transaction_id, job->verifier_count);
    for (int i = 0; i < job->verifier_count; i++) {
        connection_pool_send(job->verifier_ips[i], abort_msg);
    }

    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
    char fail_msg[128];
    snprintf(fail_msg, sizeof(fail_msg), "%s:%lu:0:%s\n", MSG_JOIN_FINALIZE, job->transaction_id, nonce_hex);
    ESP_LOGI(TAG, "[JoinID: %lu] Notifying new node %s of join failure.", job->transaction_id, job->new_node_ip);
    connection_pool_send(job->new_node_ip, fail_msg);

    if (job->type == JOIN_TYPE_HEAL_NODE) {
        ESP_LOGD(TAG, "[JoinID: %lu] HEAL job clearing tmp DB...", job->transaction_id);
        db_join_tmp_clear_by_tid(job->transaction_id);
    } else {
        db_join_tmp_clear();
    }

    if (!raft_state_is_peer(job->new_node_ip)) {
        connection_pool_remove_peer(job->new_node_ip);
    } else {
        ESP_LOGW(TAG, "Node %s is a valid Raft peer. The join/heal failed, but it will NOT be removed from the connection pool.", job->new_node_ip);
    }
    
    char *event_msg = malloc(MAX_MESSAGE_SIZE);
    if (!event_msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for event message.");
    } else {
        if (job->type == JOIN_TYPE_HEAL_NODE) {
            snprintf(event_msg, MAX_MESSAGE_SIZE, "HEAL_FAILED:%s", job->new_node_ip);
        } else {
            snprintf(event_msg, MAX_MESSAGE_SIZE, "JOIN_FAILED:%s", job->new_node_ip);
        }
        send_monitoring_tcp_event(event_msg);
        free(event_msg);
    }

    if (job->type == JOIN_TYPE_HEAL_NODE) {
        if (job->in_use && job->ack_semaphore != NULL) {
            ESP_LOGD(TAG, "Signaling completion (failure) to heal task for %s", job->new_node_ip);
            xSemaphoreGive(job->completion_semaphore);
        }

        portENTER_CRITICAL(&parallel_job_failure_mux);
        parallel_job_failure_count++;
        portEXIT_CRITICAL(&parallel_job_failure_mux);
    } else {
        TAKE_JOIN_MUTEX(__FUNCTION__);
        if (job->in_use) {
            ESP_LOGD(TAG, "Cleaning up sequential JOIN job for %s", job->new_node_ip);
            if (job->ack_semaphore != NULL) {
                vSemaphoreDelete(job->ack_semaphore);
                job->ack_semaphore = NULL;
            }
            memset(job, 0, sizeof(JoinProcess));
        }
        GIVE_JOIN_MUTEX(__FUNCTION__);
        xSemaphoreGive(worker_sync_sem);
    }
}

/**
 * @brief A watchdog task that monitors the join process for timeouts.
 * @details This task waits on a semaphore that is given when a join process starts.
 * If the join does not complete within the `JOIN_PROCESS_TIMEOUT_MS`, this task
 * will trigger a rollback to clean up the state and prevent the system from
 * getting stuck.
 * @param pvParameters Unused.
 */
static void join_watchdog_task(void *pvParameters) {
    ESP_LOGI(TAG, "Join watchdog task started.");
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        
        JoinProcess job_to_roll_back_join;
        bool needs_rollback_join = false;

        TAKE_JOIN_MUTEX(__FUNCTION__);
        if (pending_join.in_use) {
            uint32_t elapsed_time_ms = (xTaskGetTickCount() * portTICK_PERIOD_MS) - pending_join.start_time_ms;
            if (elapsed_time_ms > JOIN_PROCESS_TIMEOUT_MS) {
                ESP_LOGE(TAG, "[JoinID: %lu] Sequential Join process for node %s timed out. Staging rollback.",
                         pending_join.transaction_id, pending_join.new_node_ip);
                memcpy(&job_to_roll_back_join, &pending_join, sizeof(JoinProcess));
                needs_rollback_join = true;
            }
        }
        GIVE_JOIN_MUTEX(__FUNCTION__);

        if (needs_rollback_join) {
            master_trigger_join_rollback(&job_to_roll_back_join);
        }

        xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
        for (int i = 0; i < MAX_PARALLEL_HEALS; i++) {
            JoinProcess* job = &pending_heal_jobs[i];
            if (job->in_use) {
                uint32_t elapsed_time_ms = (xTaskGetTickCount() * portTICK_PERIOD_MS) - job->start_time_ms;
                if (elapsed_time_ms > JOIN_PROCESS_TIMEOUT_MS) {
                     ESP_LOGE(TAG, "[JoinID: %lu] HEAL job for node %s (slot %d) timed out. Staging rollback.",
                              job->transaction_id, job->new_node_ip, i);
                    master_trigger_join_rollback(job);
                    if (job->in_use) {
                        ESP_LOGD(TAG, "Watchdog cleaning up HEAL job slot for %s", job->new_node_ip);
                    }
                }
            }
        }

        xSemaphoreGive(heal_pool_mutex);
    }
}

/**
 * @brief Initializes the join module's mutex.
 * @details This function ensures the primary mutex for protecting the join state machine is created.
 * It uses a lazy initialization pattern, creating the mutex only on its first required use.
 */
void auth_join_init(void) {
    ESP_LOGI(TAG, "Initializing Node JOIN Module...");
    if (join_mutex == NULL || new_node_state_mutex == NULL || join_request_queue == NULL || worker_sync_sem == NULL || 
        join_result_semaphore == NULL || bootstrap_completed_sem == NULL || heal_pool_mutex == NULL
        || caller_sync_sem == NULL) {

        taskENTER_CRITICAL(&join_init_spinlock);
        if (join_mutex == NULL) {
            join_mutex = xSemaphoreCreateMutex();
        }
        if (new_node_state_mutex == NULL) {
            new_node_state_mutex = xSemaphoreCreateMutex();
        }
        if (join_request_queue == NULL) {
            join_request_queue = xQueueCreate(10, sizeof(join_request_t));
        }
        if (worker_sync_sem == NULL) {
            worker_sync_sem = xSemaphoreCreateBinary();
        }
        if (join_result_semaphore == NULL) {
            join_result_semaphore = xSemaphoreCreateBinary();
        }
        if (caller_sync_sem == NULL) {
            caller_sync_sem = xSemaphoreCreateCounting(MAX_PARALLEL_HEALS, 0);
        }

        if (bootstrap_completed_sem == NULL) {
            bootstrap_completed_sem = xSemaphoreCreateBinary();
        }

        if (heal_pool_mutex == NULL) {
            heal_pool_mutex = xSemaphoreCreateMutex();
        }

        taskEXIT_CRITICAL(&join_init_spinlock);
    }

    if (join_mutex == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create JOIN mutex!");
        return;
    }

    if (new_node_state_mutex == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create NEW_NODE_STATE mutex!");
        return;
    }

    if (worker_sync_sem == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create COMPLETION mutex!");
        return;
    }

    if (join_result_semaphore == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create RESULT mutex!");
        return;
    }

    if (heal_pool_mutex == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create HEAL_POOL mutex!");
        return;
    }

    if (bootstrap_completed_sem == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create BOOTSRAP_COMPLETED mutex!");
        return;
    } else {
        xSemaphoreGive(bootstrap_completed_sem);
    }

    ESP_LOGD(TAG, "Attempting to take JOIN mutex for initialization...");
    if (xSemaphoreTake(join_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "FATAL: Failed to create JOIN mutex!");
        return;
    } else {
        xSemaphoreGive(join_mutex);
    }

    ESP_LOGD(TAG, "Attempting to take NEW_NODE_STATE mutex for initialization...");
    if (xSemaphoreTake(new_node_state_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "FATAL: Failed to create NEW_NODE_STATE mutex!");
        return;
    } else {
        xSemaphoreGive(new_node_state_mutex);
    }

    if (last_transaction_id == 0) {
        last_transaction_id = esp_random();
    }

    xTaskCreate(join_watchdog_task, "join_watchdog", 5120, NULL, 5, &join_watchdog_task_handle);
    xTaskCreate(join_manager_task, "join_manager", 8192, NULL, 6, &join_manager_task_handle);

    xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
    memset(pending_heal_jobs, 0, sizeof(pending_heal_jobs));
    xSemaphoreGive(heal_pool_mutex);
    ESP_LOGI(TAG, "Join module initialized.");
}

/**
 * @brief Sends a join request from a new node to the cluster's leader.
 * @details This function is called by a node that wishes to join the cluster. It formats
 * a JOIN_REQ message and queues it for transmission to the current leader.
 * @param my_node_id The ID (typically IP address) of the node sending the request.
 * @param master_ip The IP address of the current cluster leader.
 */
void node_to_add_send_join_request(const char *my_node_id, const char *master_ip) {
    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

    int required_size = snprintf(NULL, 0, "%s:%s:%s\n", MSG_JOIN_REQ, my_node_id, nonce_hex);
    if (required_size < 0) {
        ESP_LOGE(TAG, "Failed to calculate size for join request message.");
        return;
    }

    char *msg = malloc(required_size + 1);
    if (!msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for join request message.");
        return;
    }

    snprintf(msg, required_size + 1, "%s:%s:%s\n", MSG_JOIN_REQ, my_node_id, nonce_hex);

    ESP_LOGI(TAG, "Queueing join request to master %s", master_ip);
    connection_pool_send(master_ip, msg);
    free(msg);
}

/**
 * @brief (Leader-only) Checks if a given IP belongs to the list of currently assigned verifiers.
 * @param ip The IP address to check.
 * @return true If the IP is in the list of active verifiers for the current join process.
 * @return false If the IP is not in the list or the input is invalid.
 */
static bool is_ip_in_verifier_list(JoinProcess* job, const char *ip) {
    if (!job || !ip)
        return false;
    for (int i = 0; i < job->verifier_count; i++) {
        if (strcmp(job->verifier_ips[i], ip) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * @brief (Leader-only) Selects followers to act as verifiers and notifies all parties.
 * @details This function orchestrates the core verification phase. It selects a percentage
 * of followers to act as verifiers, sends them a request to generate challenges
 * for the new node, and waits for their consolidated results.
 * @param target_ip The IP of the node to be verified.
 * @param num_to_add The number of verifiers to assign.
 * @param transaction_id The unique ID for the current join process.
 */
void master_assign_new_verifiers(JoinProcess* job, const char *target_ip, int num_to_add, uint32_t transaction_id) {
    if (num_to_add <= 0) {
        finalize_join_process(job, true);
        return;
    }
    
    ESP_LOGI(TAG, "[JoinID: %lu] Starting sequential assignment of %d verifiers to node %s", transaction_id, num_to_add, target_ip);

    char existing_verifiers[MAX_VERIFIERS][INET_ADDRSTRLEN];
    int existing_verifiers_count = db_get_verifiers_for_node(target_ip, existing_verifiers, MAX_VERIFIERS);
    if (existing_verifiers_count > 0) {
        ESP_LOGI(TAG, "Node %s already has %d verifiers.", target_ip, existing_verifiers_count);
    }

    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    int follower_count = db_get_follower_count();

    char *verifier_list_str = malloc(1024);
    if (!verifier_list_str) {
        ESP_LOGE(TAG, "Failed to allocate memory for verifier list!");
        master_trigger_join_rollback(job);
        return;
    }
    memset(verifier_list_str, 0, 1024);

    char selected_followers[MAX_VERIFIERS][INET_ADDRSTRLEN];
    int selected_count = 0;
    char *string_buffer_position = verifier_list_str;
    size_t remaining_buffer_space = 1024;

    if (follower_count > 0) {
        int attempts = 0;
        while (selected_count < num_to_add && attempts < (follower_count * 2)) {
            char follower_ip_buffer[INET_ADDRSTRLEN];
            if (db_get_random_follower_ip(follower_ip_buffer, sizeof(follower_ip_buffer))) {
                bool already_a_verifier = false;
                for (int j = 0; j < existing_verifiers_count; j++) {
                    if (strcmp(existing_verifiers[j], follower_ip_buffer) == 0) {
                        already_a_verifier = true;
                        break;
                    }
                }
                if (already_a_verifier) {
                    attempts++;
                    continue;
                }

                bool already_selected_this_round = false;
                for (int j = 0; j < selected_count; j++) {
                    if (strcmp(selected_followers[j], follower_ip_buffer) == 0) {
                        already_selected_this_round = true;
                        break;
                    }
                }

                if (!already_selected_this_round) {
                    strncpy(selected_followers[selected_count], follower_ip_buffer, INET_ADDRSTRLEN - 1);
                    selected_followers[selected_count][INET_ADDRSTRLEN - 1] = '\0';
                    
                    const char *separator = (selected_count > 0) ? "," : "";
                    int chars_written = snprintf(string_buffer_position, remaining_buffer_space, "%s%s", separator, follower_ip_buffer);
                    
                    if (chars_written > 0 && chars_written < remaining_buffer_space) {
                        string_buffer_position += chars_written;
                        remaining_buffer_space -= chars_written;
                        selected_count++;
                    } else {
                        break;
                    }
                }
            }
            attempts++;
        }
    }

    SemaphoreHandle_t correct_mutex = NULL;
    if (job->type == JOIN_TYPE_HEAL_NODE) {
        correct_mutex = heal_pool_mutex;
    } else {
        correct_mutex = join_mutex;
    }

    if (correct_mutex) {
        xSemaphoreTake(correct_mutex, portMAX_DELAY);
    }

    job->verifier_count = 0;
    if (follower_count > 0) {
        for (int i = 0; i < selected_count; i++) {
            strncpy(job->verifier_ips[job->verifier_count], selected_followers[i], INET_ADDRSTRLEN - 1);
            job->verifier_ips[job->verifier_count][INET_ADDRSTRLEN - 1] = '\0';
            job->verifier_count++;
        }
    } else {
        ESP_LOGW(TAG, "[JoinID: %lu] No followers found. Bootstrapping with self as the only verifier.", transaction_id);
        job->verifier_count = 1;
        strncpy(job->verifier_ips[0], my_ip, INET_ADDRSTRLEN - 1);
        strncpy(verifier_list_str, my_ip, 1023);
    }

    if (job->verifier_count == 0) {
        ESP_LOGE(TAG, "[JoinID: %lu] Could not find any new, unique verifiers to assign.", transaction_id);
        free(verifier_list_str);
        
        if (correct_mutex) {
            xSemaphoreGive(correct_mutex);
        }
        
        master_trigger_join_rollback(job);
        return;
    }

    job->expected_verifier_results = job->verifier_count;
    job->received_verifier_results = 0;
    job->failed_verifier_results = 0;

    if (correct_mutex) {
        xSemaphoreGive(correct_mutex);
    }

    char nonce_hex_update[NONCE_HEX_SIZE];
    uint8_t nonce_update[NONCE_SIZE];
    generate_nonce(nonce_update, NONCE_SIZE);
    bytes_to_hex(nonce_update, nonce_hex_update, NONCE_SIZE);
    int update_msg_size = snprintf(NULL, 0, "%s:%lu:%s:%s\n", MSG_VERIFIER_UPDATE, transaction_id, verifier_list_str, nonce_hex_update);
    if (update_msg_size > 0) {
        xSemaphoreTake(job->ack_semaphore, 0);
        char *update_msg = malloc(update_msg_size + 1);
        if (update_msg) {
            snprintf(update_msg, update_msg_size + 1, "%s:%lu:%s:%s\n", MSG_VERIFIER_UPDATE, transaction_id, verifier_list_str, nonce_hex_update);
            ESP_LOGI(TAG, "[JoinID: %lu] Notifying new node %s with its verifier list.", transaction_id, target_ip);
            connection_pool_send(target_ip, update_msg);
            free(update_msg);
        }
    }

    char *event_msg = malloc(MAX_MESSAGE_SIZE);
    if (!event_msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
        free(verifier_list_str);
        return;
    }

    snprintf(event_msg, MAX_MESSAGE_SIZE, "JOIN_VERIFIERS:%s:%s", target_ip, verifier_list_str);
    send_monitoring_tcp_event(event_msg);
    free(event_msg);
    free(verifier_list_str);

    ESP_LOGI(TAG, "[JoinID: %lu] Waiting for VERIFIER_UPDATE_ACK from %s...", transaction_id, target_ip);
    
    if (xSemaphoreTake(job->ack_semaphore, pdMS_TO_TICKS(60000)) != pdTRUE) {
        ESP_LOGE(TAG, "[JoinID: %lu] Timed out waiting for VERIFIER_UPDATE_ACK from %s. Rolling back.", transaction_id, target_ip);
        master_trigger_join_rollback(job);
        return;
    }

    if (job->type == JOIN_TYPE_HEAL_NODE) {
        xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
        if (!job->in_use || job->transaction_id != transaction_id) {
            ESP_LOGE(TAG, "[JoinID: %lu] Job invalidated during ACK wait. Aborting.", transaction_id);
            xSemaphoreGive(heal_pool_mutex);
            return;
        }
        xSemaphoreGive(heal_pool_mutex);
    }

    ESP_LOGI(TAG, "[JoinID: %lu] Sending challenge requests to all %d verifiers.", transaction_id, job->verifier_count);


    for (int i = 0; i < job->verifier_count; i++) {
        const char* current_verifier_ip = job->verifier_ips[i];
        int num_challenges_for_verifier = (esp_random() % MAX_CHALLENGES_PER_VERIFIER) + 1;

        char challenges_list_str[1024] = {0};
        char *ptr = challenges_list_str;
        size_t remaining = sizeof(challenges_list_str);

        for (int k = 0; k < num_challenges_for_verifier; k++) {
            char challenge[64];
            int attempts = 0;
            do {
                uint32_t random_part = esp_random();
                snprintf(challenge, sizeof(challenge), "CHL_%lu_%lu_%d", transaction_id, random_part, k);
                attempts++;
            } while (db_challenge_exists_globally(challenge) && attempts < 10);

            if (attempts >= 10) {
                ESP_LOGW(TAG, "Could not generate unique challenge after 10 attempts. Using last generated.");
            }

            int written = snprintf(ptr, remaining, "%s%s", (k > 0) ? "," : "", challenge);
            if (written > 0 && written < remaining) {
                ptr += written;
                remaining -= written;
            }
        }

        char nonce_hex_req[NONCE_HEX_SIZE];
        uint8_t nonce_req[NONCE_SIZE];
        generate_nonce(nonce_req, NONCE_SIZE);
        bytes_to_hex(nonce_req, nonce_hex_req, NONCE_SIZE);

        int req_msg_size = snprintf(NULL, 0, "%s:%lu:%s:%d:%s:%s\n", MSG_REQ_CHL_GEN, transaction_id, target_ip, num_challenges_for_verifier, challenges_list_str, nonce_hex_req);
        if (req_msg_size > 0) {
            char *req_msg = malloc(req_msg_size + 1);
            if (req_msg) {
                snprintf(req_msg, req_msg_size + 1, "%s:%lu:%s:%d:%s:%s\n", MSG_REQ_CHL_GEN, transaction_id, target_ip, num_challenges_for_verifier, challenges_list_str, nonce_hex_req);
                ESP_LOGI(TAG, "[JoinID: %lu] Sending %d pre-generated challenges to verifier %s", transaction_id, num_challenges_for_verifier, current_verifier_ip);
                connection_pool_send(current_verifier_ip, req_msg);
                free(req_msg);
            } else {
                ESP_LOGE(TAG, "Failed to allocate memory for REQ_CHL_GEN message.");
            }
        }
    }

    if (job->type == JOIN_TYPE_HEAL_NODE) {
        uint8_t nonce_delegate[NONCE_SIZE];
        char nonce_hex_delegate[NONCE_HEX_SIZE];
        generate_nonce(nonce_delegate, NONCE_SIZE);
        bytes_to_hex(nonce_delegate, nonce_hex_delegate, NONCE_SIZE);

        int delegate_msg_size = snprintf(NULL, 0, "%s:[]:%s\n", MSG_DELEGATE_CRPS, nonce_hex_delegate);
        if (delegate_msg_size > 0) {
            char *delegate_msg = malloc(delegate_msg_size + 1);
            if (delegate_msg) {
                snprintf(delegate_msg, delegate_msg_size + 1, "%s:[]:%s\n", MSG_DELEGATE_CRPS, nonce_hex_delegate);
                ESP_LOGI(TAG, "[JoinID: %lu] Sending empty DELEGATE_CRPS to %s (HEAL mode).", transaction_id, target_ip);
                connection_pool_send(target_ip, delegate_msg);
                free(delegate_msg);
            }
        }
    }
}

/**
 * @brief (Leader-only) Handles an initial join request from a new node.
 * @details This function is the entry point for the leader when it receives a JOIN_REQ.
 * It initializes the JoinProcess state, calculates the required number of verifiers,
 * and kicks off the verification process by assigning verifiers.
 * @param target_ip The IP address of the node requesting to join.
 * @param type The type of join request (e.g., a new node or a node rejoining).
 */
void node_master_handle_join_request(const char *target_ip, join_request_type_t type, join_request_t request) {
    xSemaphoreTake(worker_sync_sem, 0);
    TAKE_JOIN_MUTEX(__FUNCTION__);

    if (pending_join.in_use) {
        ESP_LOGE(TAG, "Cannot handle join for %s, another join is already in progress for %s.", target_ip, pending_join.new_node_ip);
        GIVE_JOIN_MUTEX(__FUNCTION__);
        xSemaphoreGive(worker_sync_sem); 
        return;
    }
    GIVE_JOIN_MUTEX(__FUNCTION__);

    char effective_target_ip[INET_ADDRSTRLEN];
    if (type == JOIN_TYPE_GENESIS) {
        char my_ip[INET_ADDRSTRLEN];
        char my_mac[MAC_ADDR_STR_LEN];
        raft_state_get_self_info(my_ip, sizeof(my_ip), my_mac, sizeof(my_mac));

        char event_msg[64];
        snprintf(event_msg, sizeof(event_msg), "JOIN_START:%s", my_mac);
        send_monitoring_tcp_event(event_msg);

        leader_bootstrap_self_join();
        db_insert_node(my_ip, my_ip);

        snprintf(event_msg, sizeof(event_msg), "JOIN_COMPLETE:%s", my_mac);
        send_monitoring_tcp_event(event_msg);

        return;
    } else {
        if (target_ip == NULL || strlen(target_ip) == 0) {
            ESP_LOGE(TAG, "Join request type %d requires a valid target IP.", type);
            xSemaphoreGive(worker_sync_sem);
            return;
        }
        strncpy(effective_target_ip, target_ip, INET_ADDRSTRLEN);
    }

    if (type == JOIN_TYPE_NEW_NODE) {
        ESP_LOGI(TAG, "Handling NEW_NODE join request for %s. Performing initial integrity check...", effective_target_ip);

        char actual_mac[MAC_ADDR_STR_LEN];
        bool mac_found = discovery_get_mac_for_ip(effective_target_ip, actual_mac, sizeof(actual_mac));

        if (!mac_found) {
            ESP_LOGE(TAG, "Could not find MAC address for new node %s in discovery list. Rejecting join.", effective_target_ip);
            char *event_msg = malloc(MAX_MESSAGE_SIZE);
            if (event_msg) {
                snprintf(event_msg, MAX_MESSAGE_SIZE, "JOIN_FAILED_DISCOVERY_MAC:%s", effective_target_ip);
                send_monitoring_tcp_event(event_msg);
                free(event_msg);
            }

            xSemaphoreGive(worker_sync_sem);
            return;
        }

        ESP_LOGI(TAG, "Found MAC %s for IP %s. Proceeding with integrity check.", actual_mac, effective_target_ip);
        bool is_honest = integrity_verification_run_single(effective_target_ip, actual_mac);

        if (!is_honest) {
            ESP_LOGE(TAG, "Initial integrity check FAILED for new node %s (MAC: %s). Rejecting join.", effective_target_ip, actual_mac);

            char nonce_hex_fail[NONCE_HEX_SIZE];
            uint8_t nonce_fail[NONCE_SIZE];
            generate_nonce(nonce_fail, NONCE_SIZE);
            bytes_to_hex(nonce_fail, nonce_hex_fail, NONCE_SIZE);
            char fail_msg[128];
            snprintf(fail_msg, sizeof(fail_msg), "%s:0:0:%s\n", MSG_JOIN_FINALIZE, nonce_hex_fail);
            connection_pool_send(effective_target_ip, fail_msg);

            char *event_msg = malloc(MAX_MESSAGE_SIZE);
            if (event_msg) {
                snprintf(event_msg, MAX_MESSAGE_SIZE, "JOIN_FAILED_INTEGRITY:%s", effective_target_ip);
                send_monitoring_tcp_event(event_msg);
                free(event_msg);
            }

            xSemaphoreGive(worker_sync_sem);
            return;
        } else {
             ESP_LOGI(TAG, "Initial integrity check PASSED for %s.", effective_target_ip);
        }

        if (db_node_exists(effective_target_ip)) {
            ESP_LOGW(TAG, "Join request from node %s which is already in DB. Ignoring.", effective_target_ip);
            xSemaphoreGive(worker_sync_sem);
            return;
        }

        char event_msg[64];
        snprintf(event_msg, sizeof(event_msg), "JOIN_START:%s", actual_mac);
        send_monitoring_tcp_event(event_msg);
    } else {
        ESP_LOGI(TAG, "Skipping initial integrity check for %s (Type: %d - not NEW_NODE).", effective_target_ip, type);
    }

    TAKE_JOIN_MUTEX(__FUNCTION__);
    memset(&pending_join, 0, sizeof(JoinProcess));
    pending_join.in_use = true;
    pending_join.start_time_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    pending_join.transaction_id = __atomic_add_fetch(&last_transaction_id, 1, __ATOMIC_SEQ_CST);
    strncpy(pending_join.new_node_ip, effective_target_ip, INET_ADDRSTRLEN - 1);
    pending_join.new_node_ip[INET_ADDRSTRLEN - 1] = '\0';
    pending_join.type = type;

    pending_join.ack_semaphore = xSemaphoreCreateBinary();
    if (pending_join.ack_semaphore == NULL) {
        ESP_LOGE(TAG, "Failed to create ack_semaphore for sequential job!");
        GIVE_JOIN_MUTEX(__FUNCTION__);
        xSemaphoreGive(worker_sync_sem);
        return;
    }
    int num_verifiers_to_add = 0;
    if (type == JOIN_TYPE_HEAL_NODE) {
        num_verifiers_to_add = request.num_verifiers_to_add; 
        ESP_LOGI(TAG, "HEAL request: Adding exactly %d new verifiers for %s.", num_verifiers_to_add, effective_target_ip);
    } else {
        int follower_count = db_get_follower_count();
        int network_size = follower_count + 1;
        num_verifiers_to_add = (int)ceil(network_size * VERIFIER_PERCENTAGE);
        
        if (num_verifiers_to_add == 0 && network_size > 0)
            num_verifiers_to_add = 1;
        if (num_verifiers_to_add > MAX_VERIFIERS)
            num_verifiers_to_add = MAX_VERIFIERS;
        if (follower_count > 0 && num_verifiers_to_add > follower_count) {
            num_verifiers_to_add = follower_count;
        }
    }

    GIVE_JOIN_MUTEX(__FUNCTION__);

    master_assign_new_verifiers(&pending_join, effective_target_ip, num_verifiers_to_add, pending_join.transaction_id);

    if (xSemaphoreTake(worker_sync_sem, pdMS_TO_TICKS(JOIN_PROCESS_TIMEOUT_MS + 5000)) != pdTRUE) {
        ESP_LOGE(TAG, "FATAL: Join process for %s timed out, but completion was not signaled!", target_ip);
        JoinProcess job_copy;
        TAKE_JOIN_MUTEX(__FUNCTION__);
        memcpy(&job_copy, &pending_join, sizeof(JoinProcess));
        GIVE_JOIN_MUTEX(__FUNCTION__);
        
        master_trigger_join_rollback(&job_copy);
    }

    TAKE_JOIN_MUTEX(__FUNCTION__);
    if (pending_join.ack_semaphore != NULL) {
        vSemaphoreDelete(pending_join.ack_semaphore);
        pending_join.ack_semaphore = NULL;
    }
    memset(&pending_join, 0, sizeof(JoinProcess));
    GIVE_JOIN_MUTEX(__FUNCTION__);
}

/**
 * @brief (Leader-only) Merges two CNode JSON array strings into a single one.
 * @param base_json A string containing the base JSON array.
 * @param delta_json A string containing the new items to add.
 * @return A dynamically allocated string with the merged JSON. The caller must free this string. Returns NULL on failure.
 */
static char *merge_cnode_json(const char *base_json, const char *delta_json) {
    if (!base_json && !delta_json)
        return NULL;
    if (!delta_json)
        return strdup(base_json);
    if (!base_json)
        return strdup(delta_json);

    cJSON *base_array = cJSON_Parse(base_json);
    if (!cJSON_IsArray(base_array)) {
        if (base_array)
            cJSON_Delete(base_array);
        base_array = cJSON_CreateArray();
    }

    cJSON *delta_array = cJSON_Parse(delta_json);
    if (!cJSON_IsArray(delta_array)) {
        if (delta_array)
            cJSON_Delete(delta_array);
        char *result = cJSON_PrintUnformatted(base_array);
        cJSON_Delete(base_array);
        return result;
    }

    cJSON *item_to_move;
    while ((item_to_move = cJSON_DetachItemFromArray(delta_array, 0))) {
        cJSON_AddItemToArray(base_array, item_to_move);
    }

    char *merged_string = cJSON_PrintUnformatted(base_array);

    cJSON_Delete(base_array);
    cJSON_Delete(delta_array);

    return merged_string;
}

/**
 * @brief (Leader-only) Creates and stages the leader's own genesis credentials.
 */
void leader_bootstrap_self_join() {
    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    ESP_LOGI(TAG, "Leader %s is performing genesis self-join to create initial credentials.", my_ip);

    const int num_challenges_for_genesis = 5;
    for (int i = 0; i < num_challenges_for_genesis; i++) {
        char challenge[64], response[64];
        uint32_t random_part = esp_random();
        snprintf(challenge, sizeof(challenge), "GENESIS_%s_%lu_%d", my_ip, random_part, i);
        simulate_puf_response((const uint8_t *)challenge, strlen(challenge), response);

        CRPNode crp = {0};
        strncpy(crp.challenge, challenge, sizeof(crp.challenge) - 1);
        strncpy(crp.response, response, sizeof(crp.response) - 1);
        strncpy(crp.target_ip, my_ip, sizeof(crp.target_ip) - 1);

        db_insert_crp(&crp);
        db_insert_cnode(challenge, my_ip, my_ip);
    }
    ESP_LOGI(TAG, "Staged %d genesis CRPs/CNodes for leader %s.", num_challenges_for_genesis, my_ip);
}

/**
 * @brief (Leader-only) Stages genesis credentials for the first leader.
 * @details This function is called only once when a node becomes the first leader
 * to generate and delegate the initial set of CRPs and CNodes.
 * @param new_follower_ip The IP address of the first follower, which will become the new holder of the credentials.
 * @param cnodes_delta_json A pointer to the cJSON array where the new CNode entries will be added.
 */
static void leader_delegate_genesis_credentials(JoinProcess* job, const char *new_follower_ip, cJSON *cnodes_delta_obj) {
    ESP_LOGI(TAG, "This is the first follower. Delegating my genesis credentials to %s.", new_follower_ip);

    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);

    cJSON *crps_to_delegate_json = cJSON_CreateArray();
    if (!crps_to_delegate_json) {
        ESP_LOGE(TAG, "Failed to create cJSON array for CRP delegation.");
        return;
    }

    cJSON *cnode_item;
    cJSON_ArrayForEach(cnode_item, cnodes_delta_obj) {
        cJSON *target_item = cJSON_GetObjectItem(cnode_item, "t");
        cJSON *holder_item = cJSON_GetObjectItem(cnode_item, "h");

        if (cJSON_IsString(target_item) && strcmp(target_item->valuestring, my_ip) == 0 &&
            cJSON_IsString(holder_item) && strcmp(holder_item->valuestring, my_ip) == 0) {
            
            cJSON *challenge_item = cJSON_GetObjectItem(cnode_item, "c");
            if (cJSON_IsString(challenge_item)) {
                CRPNode* crp = db_get_crp_by_challenge(challenge_item->valuestring);
                if (crp) {
                    cJSON *crp_json = cJSON_CreateObject();
                    cJSON_AddStringToObject(crp_json, "c", crp->challenge);
                    cJSON_AddStringToObject(crp_json, "r", crp->response);
                    cJSON_AddStringToObject(crp_json, "t", crp->target_ip);
                    cJSON_AddItemToArray(crps_to_delegate_json, crp_json);
                    free(crp);
                }
                cJSON_ReplaceItemInObject(cnode_item, "h", cJSON_CreateString(new_follower_ip));
                db_join_tmp_update_cnode_holder(job->transaction_id, challenge_item->valuestring, my_ip, new_follower_ip);
            }
        }
    }

    char *crps_str = cJSON_PrintUnformatted(crps_to_delegate_json);
    if (crps_str) {
        char nonce_hex[NONCE_HEX_SIZE];
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

        int delegate_msg_size = snprintf(NULL, 0, "%s:%s:%s\n", MSG_DELEGATE_CRPS, crps_str, nonce_hex);
        if(delegate_msg_size > 0) {
            char* delegate_msg = malloc(delegate_msg_size + 1);
            if(delegate_msg) {
                snprintf(delegate_msg, delegate_msg_size + 1, "%s:%s:%s\n", MSG_DELEGATE_CRPS, crps_str, nonce_hex);
                connection_pool_send(new_follower_ip, delegate_msg);
                free(delegate_msg);
            }
        }
        free(crps_str);
    }
    cJSON_Delete(crps_to_delegate_json);
}

/**
 * @brief (Leader-only) Delegates genesis credentials to the first follower.
 * @details This function is called during the finalization of the first follower's join.
 * It reads the leader's self-referential credentials from staging, sends the CRPs to the
 * new follower for custody, and updates the corresponding CNode entries in the provided
 * delta JSON object to reflect the new holder. This ensures the delegation is part of
 * the atomic commit of the join transaction.
 * @param new_follower_ip The IP address of the first follower who will become the new holder.
 * @param cnodes_delta_obj A pointer to the cJSON array object containing the staged
 * CNode delta. This object will be modified in-place to update the holder IPs of the
 * leader's genesis CNodes.
 * @return void
 */
static void master_finalize_and_commit_join(JoinProcess* job) {
    if (!job->in_use) {
        return;
    }

    uint32_t transaction_id = job->transaction_id;
    ESP_LOGI(TAG, "[JoinID: %lu] Join for %s SUCCEEDED. Starting commit phase.", transaction_id, job->new_node_ip);

    if (job->type == JOIN_TYPE_GENESIS) {
        leader_finalize_commit(job);
        return;
    }

    if (job->type == JOIN_TYPE_HEAL_NODE) {
        char *cnodes_json_delta_str = db_join_tmp_export_cnodes_json(job->transaction_id);
        cJSON *cnodes_delta_obj = cJSON_Parse(cnodes_json_delta_str);
        if (!cnodes_delta_obj)
            cnodes_delta_obj = cJSON_CreateArray();
        char *final_delta_str = cJSON_PrintUnformatted(cnodes_delta_obj);
        const char *delta_to_broadcast_str = final_delta_str ? final_delta_str : "[]";

        char nonce_hex_commit[NONCE_HEX_SIZE];
        uint8_t nonce_commit[NONCE_SIZE];
        generate_nonce(nonce_commit, NONCE_SIZE);
        bytes_to_hex(nonce_commit, nonce_hex_commit, NONCE_SIZE);

        int broadcast_msg_size = snprintf(NULL, 0, "%s:%lu:%s:%s:%s\n", MSG_NODE_HEALED_COMMIT, job->transaction_id, job->new_node_ip, delta_to_broadcast_str, nonce_hex_commit);
        if (broadcast_msg_size > 0) {
            char *msg_broadcast = malloc(broadcast_msg_size + 1);
            if (msg_broadcast) {
                snprintf(msg_broadcast, broadcast_msg_size + 1, "%s:%lu:%s:%s:%s\n", MSG_NODE_HEALED_COMMIT, job->transaction_id, job->new_node_ip, delta_to_broadcast_str, nonce_hex_commit);     
                int follower_count = db_get_follower_count();
                int nodes_to_notify = 0;
                for (int i = 0; i < follower_count; i++) {
                    char follower_ip_buffer[INET_ADDRSTRLEN];
                    if (db_get_follower_ip(i, follower_ip_buffer, sizeof(follower_ip_buffer))) {
                        connection_pool_send(follower_ip_buffer, msg_broadcast);
                        nodes_to_notify++;
                    }
                }
                free(msg_broadcast);
                job->commit_ack_count = 0;
                job->expected_commit_acks = nodes_to_notify;

                ESP_LOGD(TAG, "[TID: %lu] HEAL job (master_finalize) sent NODE_HEALED_COMMIT to %d followers", job->transaction_id, nodes_to_notify);
            }
        }
        
        if (cnodes_json_delta_str) free(cnodes_json_delta_str);
        if (cnodes_delta_obj) cJSON_Delete(cnodes_delta_obj);
        if (final_delta_str) free(final_delta_str);

        bool wait_for_acks = (job->expected_commit_acks > 0);
        if (!wait_for_acks) {
            ESP_LOGI(TAG, "Heal: No other followers to notify. Committing immediately.");
        }

        if (wait_for_acks) {
            ESP_LOGI(TAG, "[JoinID: %lu] (Heal) Awaiting %d commit ACKs.", transaction_id, job->expected_commit_acks);
        } else {
            ESP_LOGI(TAG, "No other followers to notify. Finalizing heal for %s.", job->new_node_ip);
            leader_finalize_commit(job);
        }

        return;
    }

    bool is_first_follower = (db_get_follower_count() == 0);

    char *nodes_json_full = db_export_nodes_json();
    char *cnodes_json_base_str = db_export_cnode_json();
    char *cnodes_json_delta_str = db_join_tmp_export_cnodes_json(job->transaction_id);
    cJSON *cnodes_delta_obj = cJSON_Parse(cnodes_json_delta_str);
    if (!cnodes_delta_obj)
        cnodes_delta_obj = cJSON_CreateArray();

    if (is_first_follower) {
        leader_delegate_genesis_credentials(job, job->new_node_ip, cnodes_delta_obj);
    }

    char *final_delta_str = cJSON_PrintUnformatted(cnodes_delta_obj);
    char *cnodes_final_for_new_node_str = merge_cnode_json(cnodes_json_base_str, final_delta_str);

    const char *nodes_str = nodes_json_full ? nodes_json_full : "[]";
    const char *cnodes_final_str = cnodes_final_for_new_node_str ? cnodes_final_for_new_node_str : "[]";
    const char *delta_to_broadcast_str = final_delta_str ? final_delta_str : "[]";

    char nonce_hex_finalize[NONCE_HEX_SIZE];
    uint8_t nonce_finalize[NONCE_SIZE];
    generate_nonce(nonce_finalize, NONCE_SIZE);
    bytes_to_hex(nonce_finalize, nonce_hex_finalize, NONCE_SIZE);
    int finalize_msg_size = snprintf(NULL, 0, "%s:%lu:1:%s:%s:%s\n", MSG_JOIN_FINALIZE, job->transaction_id, nodes_str, cnodes_final_str, nonce_hex_finalize);
    if (finalize_msg_size > 0) {
        char *msg_finalize = malloc(finalize_msg_size + 1);
        if (msg_finalize) {
            snprintf(msg_finalize, finalize_msg_size + 1, "%s:%lu:1:%s:%s:%s\n", MSG_JOIN_FINALIZE, job->transaction_id, nodes_str, cnodes_final_str, nonce_hex_finalize);
            connection_pool_send(job->new_node_ip, msg_finalize);
            free(msg_finalize);
        }
    }

    char nonce_hex_commit[NONCE_HEX_SIZE];
    uint8_t nonce_commit[NONCE_SIZE];
    generate_nonce(nonce_commit, NONCE_SIZE);
    bytes_to_hex(nonce_commit, nonce_hex_commit, NONCE_SIZE);
    int broadcast_msg_size = snprintf(NULL, 0, "%s:%lu:%s:%s:%s\n", MSG_NODE_ADDED_COMMIT, job->transaction_id, job->new_node_ip, delta_to_broadcast_str, nonce_hex_commit);
    if (broadcast_msg_size > 0) {
        char *msg_broadcast = malloc(broadcast_msg_size + 1);
        if (msg_broadcast) {
            snprintf(msg_broadcast, broadcast_msg_size + 1, "%s:%lu:%s:%s:%s\n", MSG_NODE_ADDED_COMMIT, job->transaction_id, job->new_node_ip, delta_to_broadcast_str, nonce_hex_commit);
            int follower_count = db_get_follower_count();
            int nodes_to_notify = 0;
            char follower_ip_buffer[INET_ADDRSTRLEN];
            for (int i = 0; i < follower_count; i++) {
                if (db_get_follower_ip(i, follower_ip_buffer, sizeof(follower_ip_buffer))) {
                    if (strcmp(follower_ip_buffer, job->new_node_ip) != 0) {
                        connection_pool_send(follower_ip_buffer, msg_broadcast);
                        nodes_to_notify++;
                    }
                }
            }
            free(msg_broadcast);
            job->commit_ack_count = 0;
            job->expected_commit_acks = nodes_to_notify;
        }
    }

    bool wait_for_acks = (job->expected_commit_acks > 0);

    if (!wait_for_acks) {
        ESP_LOGI(TAG, "No existing followers to notify. Committing immediately.");
        db_insert_node(job->new_node_ip, job->new_node_ip);
        raft_state_add_peer(job->new_node_ip);
    }

    if (nodes_json_full) free(nodes_json_full);
    if (cnodes_json_base_str) free(cnodes_json_base_str);
    if (cnodes_json_delta_str) free(cnodes_json_delta_str);
    if (cnodes_delta_obj) cJSON_Delete(cnodes_delta_obj);
    if (final_delta_str) free(final_delta_str);
    if (cnodes_final_for_new_node_str) free(cnodes_final_for_new_node_str);

    if (wait_for_acks) {
        ESP_LOGI(TAG, "[JoinID: %lu] Awaiting %d commit ACKs.", transaction_id, job->expected_commit_acks);
    } else {
        ESP_LOGI(TAG, "No existing followers to notify. Finalizing join for %s.", job->new_node_ip);
        leader_finalize_commit(job);
    }
}

/**
 * @brief (Leader-only) Finalizes the join process after verification is complete.
 * @details Based on the success or failure of the verification phase, this function
 * either triggers a commit (notifying all nodes of the new member) or a
 * rollback (notifying all participants to discard the transaction).
 * @param is_success True if the join was successful, false otherwise.
 */
void finalize_join_process(JoinProcess* job, bool is_success) {
    if (is_success) {
        master_finalize_and_commit_join(job);
    } else {
        master_trigger_join_rollback(job);
    }
}

/**
 * @brief (Leader-only) Finalizes the commit phase of a successful join.
 * @details This function is the final step of a join process. It commits the
 * staged data from the temporary DB to the main DB, notifies verifiers to
 * do the same, cleans up the global pending_join state, and signals that the
 * overall join process is complete.
 * @param transaction_id The ID of the transaction to finalize.
 */
static void leader_finalize_commit(JoinProcess* job) {
    ESP_LOGI(TAG, "[JoinID: %lu] All ACKs received or not required. Finalizing leader's commit.", job->transaction_id);
    if (job->type != JOIN_TYPE_HEAL_NODE) {
        db_join_commit(job->transaction_id);
    }

    char cleanup_msg[128];
    char nonce_hex_cleanup[NONCE_HEX_SIZE];
    uint8_t nonce_cleanup[NONCE_SIZE];
    generate_nonce(nonce_cleanup, NONCE_SIZE);
    bytes_to_hex(nonce_cleanup, nonce_hex_cleanup, NONCE_SIZE);
    snprintf(cleanup_msg, sizeof(cleanup_msg), "%s:%lu:%s\n", MSG_CLEANUP_COMMIT, job->transaction_id, nonce_hex_cleanup);

    for (int i = 0; i < job->verifier_count; i++) {
        connection_pool_send(job->verifier_ips[i], cleanup_msg);
    }

    if (job->in_use && job->type == JOIN_TYPE_NEW_NODE) {
        char event_msg[64];
        snprintf(event_msg, sizeof(event_msg), "JOIN_COMPLETE:%s", job->new_node_ip);
        send_monitoring_tcp_event(event_msg);
    } else if (job->type == JOIN_TYPE_HEAL_NODE) {
        char event_msg[64];
        snprintf(event_msg, sizeof(event_msg), "HEAL_COMPLETE:%s", job->new_node_ip);
        send_monitoring_tcp_event(event_msg);
    }

    if (job->type == JOIN_TYPE_HEAL_NODE) {
        xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
        if (job->in_use && job->completion_semaphore != NULL) {
            ESP_LOGD(TAG, "Signaling completion (success) to heal task for %s", job->new_node_ip);
            xSemaphoreGive(job->completion_semaphore);
        }

        xSemaphoreGive(heal_pool_mutex);
    } else {
        TAKE_JOIN_MUTEX(__FUNCTION__);
        if (job->in_use) {
            ESP_LOGD(TAG, "Cleaning up sequential JOIN job for %s", job->new_node_ip);
            if (job->ack_semaphore != NULL) {
                xSemaphoreGive(job->ack_semaphore);
            }
        }
        GIVE_JOIN_MUTEX(__FUNCTION__);
        xSemaphoreGive(worker_sync_sem);
    }
}

/**
 * @brief Central message handler for the synchronized join protocol.
 * @details This function is the main router for all incoming messages related to the join protocol.
 * It parses the command and, based on the node's role (Leader, Follower, New Node),
 * dispatches the message to the appropriate handling logic. It is designed to be
 * called from the main server task that receives network messages.
 * @param message The raw, null-terminated message string received from a peer.
 * @param from_ip The IP address of the node that sent the message.
 */
void join_handle_message(char *message, const char *from_ip) {
    char my_ip[INET_ADDRSTRLEN];
    char leader_ip[INET_ADDRSTRLEN];
    bool has_leader, is_leader, is_from_leader;
    char *local_message_copy = NULL;
    char *payload = NULL;
    char *command = NULL;
    char *first_colon = NULL;
    char original_first_char = ':';
    char *last_colon = NULL;
    char original_last_char = ':';

    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    has_leader = raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0);
    is_leader = has_leader && (strcmp(my_ip, leader_ip) == 0);
    is_from_leader = has_leader && (strcmp(from_ip, leader_ip) == 0);

    local_message_copy = strdup(message);
    if (!local_message_copy) {
        ESP_LOGE(TAG, "Failed to allocate memory for local message copy.");
        return;
    }

    first_colon = strchr(local_message_copy, ':');
    if (first_colon) {
        original_first_char = *first_colon;
        *first_colon = '\0';
        payload = first_colon + 1;
    }
    command = local_message_copy;

    if (!payload) {
        if (strcmp(command, MSG_JOIN_FAIL_MASTER_CORRUPT) == 0) {
            ESP_LOGE(TAG, "Join failed: Verifier %s reported master corruption.", from_ip);
        } else {
            ESP_LOGW(TAG, "Received malformed message (no payload) from %s: %s", from_ip, command);
        }
        goto cleanup;
    }

    if (strcmp(command, MSG_JOIN_REQ) == 0) {
        if (is_leader) {
            char *saveptr;
            char *node_id = strtok_r(payload, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);
            if (!node_id || !nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Malformed or replayed %s from %s", MSG_JOIN_REQ, from_ip);
                goto cleanup;
            }
            ESP_LOGI(TAG, "Join request for %s has been queued.", from_ip);
            join_request_t join_req = {.type = JOIN_TYPE_NEW_NODE};
            strncpy(join_req.target_ip, from_ip, INET_ADDRSTRLEN);
            if (xQueueSend(join_request_queue, &join_req, pdMS_TO_TICKS(100)) != pdPASS) {
                ESP_LOGE(TAG, "Could not queue join request for %s. Queue is full.", from_ip);
            }
        }
    } else if (strcmp(command, MSG_CHL_RESULT) == 0) {
        if (is_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *target_ip = strtok_r(NULL, ":", &saveptr);
            char *correct_str = strtok_r(NULL, ":", &saveptr);
            char *total_str = strtok_r(NULL, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);
            if (!transaction_id_str || !target_ip || !correct_str || !total_str || !nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Malformed or replayed %s from %s", MSG_CHL_RESULT, from_ip);
                goto cleanup;
            }
            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);
            
            bool do_finalize = false;
            bool do_rollback = false;
            bool handled = false;

            TAKE_JOIN_MUTEX(__FUNCTION__);
            if (pending_join.in_use && transaction_id == pending_join.transaction_id && is_ip_in_verifier_list(&pending_join, from_ip)) {
                pending_join.received_verifier_results++;
                int correct = atoi(correct_str);
                int total = atoi(total_str);

                if (correct != total) {
                    ESP_LOGE(TAG, "[JoinID: %lu] Verifier %s reported failure (%d/%d).", transaction_id, from_ip, correct, total);
                    pending_join.failed_verifier_results++;
                } else {
                    ESP_LOGI(TAG, "[JoinID: %lu] Verifier %s reported success (%d/%d).", transaction_id, from_ip, correct, total);
                }

                if (pending_join.failed_verifier_results > 0) {
                    ESP_LOGW(TAG, "[JoinID: %lu] A verifier failed. Rolling back immediately.", transaction_id);
                    do_rollback = true;
                } else if (pending_join.received_verifier_results == pending_join.expected_verifier_results) {
                    ESP_LOGI(TAG, "[JoinID: %lu] All %d verifiers reported success. Finalizing join.", transaction_id, pending_join.expected_verifier_results);
                    do_finalize = true;
                } else {
                    ESP_LOGI(TAG, "[JoinID: %lu] Received %d/%d verifier results.", transaction_id, pending_join.received_verifier_results, pending_join.expected_verifier_results);
                }
                handled = true;
            }
            GIVE_JOIN_MUTEX(__FUNCTION__);

            if (do_rollback) {
                master_trigger_join_rollback(&pending_join); 
            } else if (do_finalize) {
                finalize_join_process(&pending_join, true);
            }

            if (handled) goto cleanup;

            xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
            for (int i = 0; i < MAX_PARALLEL_HEALS; i++) {
                JoinProcess* job = &pending_heal_jobs[i];
                if (job->in_use && transaction_id == job->transaction_id && is_ip_in_verifier_list(job, from_ip)) {
                    int correct = atoi(correct_str);
                    int total = atoi(total_str);
                    bool is_correct = (correct == total);

                    if (is_correct) {
                        job->received_verifier_results++;
                        ESP_LOGD(TAG, "[TID: %lu] Received CHL_RESULT from verifier %s (%d/%d). Status: %d/%d received, %d failed.",
                                 transaction_id, from_ip, job->received_verifier_results, job->expected_verifier_results,
                                 job->received_verifier_results, job->expected_verifier_results, job->failed_verifier_results);
                    } else {
                        job->received_verifier_results++;
                        job->failed_verifier_results++;
                        ESP_LOGW(TAG, "[TID: %lu] Received FAILED CHL_RESULT from verifier %s. Status: %d/%d received, %d failed.",
                                 transaction_id, from_ip, job->received_verifier_results, job->expected_verifier_results, job->failed_verifier_results);
                    }

                    if (job->failed_verifier_results > 0) {
                        master_trigger_join_rollback(job);
                    } else if (job->received_verifier_results == job->expected_verifier_results) {
                        ESP_LOGD(TAG, "[TID: %lu] All CHL_RESULTs received. Finalizing.", transaction_id);
                        finalize_join_process(job, true);
                    }
                    handled = true;
                    break;
                }
            }
            xSemaphoreGive(heal_pool_mutex);
        }
    } else if (strcmp(command, MSG_VERIFIER_UPDATE) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *verifier_list_and_nonce = payload + strlen(transaction_id_str) + 1;
            char *last_colon = strrchr(verifier_list_and_nonce, ':');
            if (!transaction_id_str || !last_colon) {
                ESP_LOGE(TAG, "Malformed %s from %s: missing fields or corrupted payload.", MSG_VERIFIER_UPDATE, from_ip);
                goto cleanup;
            }
            *last_colon = '\0';
            char *verifier_list_str = verifier_list_and_nonce;
            char* nonce = last_colon + 1;
            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);
            if (nonce_is_valid_and_store(nonce)) {
                ESP_LOGI(TAG, "[JoinID: %lu] Received verifier list: %s", transaction_id, verifier_list_str);
                TAKE_NEW_NODE_STATE_MUTEX(__FUNCTION__);
                legitimate_verifier_count = 0;
                char *saveptr_list;
                char *token = strtok_r(verifier_list_str, ",", &saveptr_list);
                while (token != NULL && legitimate_verifier_count < MAX_VERIFIERS) {
                    strncpy(legitimate_verifier_ips[legitimate_verifier_count], token, INET_ADDRSTRLEN - 1);
                    legitimate_verifier_ips[legitimate_verifier_count][INET_ADDRSTRLEN - 1] = '\0';
                    legitimate_verifier_count++;
                    token = strtok_r(NULL, ",", &saveptr_list);
                }
                GIVE_NEW_NODE_STATE_MUTEX(__FUNCTION__);
            }

            char leader_ip[INET_ADDRSTRLEN];
            if (raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0)) {
                char ack_msg[128];
                char ack_nonce_hex[NONCE_HEX_SIZE];
                uint8_t ack_nonce[NONCE_SIZE];
                generate_nonce(ack_nonce, NONCE_SIZE);
                bytes_to_hex(ack_nonce, ack_nonce_hex, NONCE_SIZE);

                snprintf(ack_msg, sizeof(ack_msg), "%s:%lu:%s\n", MSG_VERIFIER_UPDATE_ACK, transaction_id, ack_nonce_hex);
                connection_pool_send(leader_ip, ack_msg);
            }

            goto cleanup;
        }
    } else if (strcmp(command, MSG_VERIFIER_UPDATE_ACK) == 0) {
        if (is_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);

            if (!transaction_id_str || !nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGE(TAG, "Malformed %s from %s", MSG_VERIFIER_UPDATE_ACK, from_ip);
                goto cleanup;
            }

            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);
            if (pending_join.in_use && pending_join.transaction_id == transaction_id) {
                xSemaphoreGive(pending_join.ack_semaphore);
            }
            
            xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
            for (int i = 0; i < MAX_PARALLEL_HEALS; i++) {
                 if (pending_heal_jobs[i].in_use && pending_heal_jobs[i].transaction_id == transaction_id) {
                     xSemaphoreGive(pending_heal_jobs[i].ack_semaphore);
                     break; 
                 }
            }
            xSemaphoreGive(heal_pool_mutex);
        }
    } else if (strcmp(command, MSG_REQ_CHL_GEN) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *target_ip = strtok_r(NULL, ":", &saveptr);
            char *num_challenges_str = strtok_r(NULL, ":", &saveptr);
            char *challenges_list_str = strtok_r(NULL, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);

            if (!transaction_id_str || !target_ip || !num_challenges_str || !challenges_list_str || !nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGE(TAG, "Malformed %s from %s", MSG_REQ_CHL_GEN, from_ip);
                goto cleanup;
            }
            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);
            int num_challenges = atoi(num_challenges_str);
            ESP_LOGI(TAG, "Verifier temporarily adding new node %s to connection pool.", target_ip);
            connection_pool_add_peer(target_ip);

            char leader_mac[MAC_ADDR_STR_LEN];
            raft_state_get_leader_info(leader_ip, sizeof(leader_ip), leader_mac, sizeof(leader_mac));

            if (strcmp(my_ip, leader_ip) != 0) {
                ESP_LOGI(TAG, "[JoinID: %lu] Verifying leader integrity before generating challenges for %s.", transaction_id, target_ip);
                bool is_leader_honest = integrity_verification_run_single(leader_ip, leader_mac);

                if (!is_leader_honest) {
                    ESP_LOGE(TAG, "[JoinID: %lu] Leader verification FAILED. Notifying new node %s.", transaction_id, target_ip);
                    char fail_msg[64];
                    snprintf(fail_msg, sizeof(fail_msg), "%s\n", MSG_JOIN_FAIL_MASTER_CORRUPT);
                    connection_pool_send(target_ip, fail_msg);
                    char *event_msg = malloc(MAX_MESSAGE_SIZE);
                    if (event_msg) {
                        snprintf(event_msg, MAX_MESSAGE_SIZE, "%s:%s:%s", MSG_JOIN_FAIL_MASTER_CORRUPT, leader_ip, my_ip);
                        send_monitoring_tcp_event(event_msg);
                        free(event_msg);
                    }
                    goto cleanup;
                }
            } else {
                ESP_LOGI(TAG, "[JoinID: %lu] Skipping self-integrity check as the sole verifier.", transaction_id);
            }
            ESP_LOGI(TAG, "[JoinID: %lu] Received request from leader with %d pre-generated challenges for %s.", transaction_id, num_challenges, target_ip);
            
            cJSON *batch_chl_json = cJSON_CreateArray();
            cJSON *batch_gen_json = cJSON_CreateArray();
            
            char *chl_saveptr;
            char *challenge_token = strtok_r(challenges_list_str, ",", &chl_saveptr);
            
            for (int i = 0; i < num_challenges; i++) {
                if (!challenge_token) {
                     ESP_LOGW(TAG, "Fewer challenges provided than expected (%d vs %d)", i, num_challenges);
                     break;
                }

                char challenge[64], response[64], nonce_hex[NONCE_HEX_SIZE];

                uint8_t nonce_bytes[NONCE_SIZE];
                generate_nonce(nonce_bytes, NONCE_SIZE);
                bytes_to_hex(nonce_bytes, nonce_hex, NONCE_SIZE);

                    strncpy(challenge, challenge_token, sizeof(challenge) - 1);
                    challenge[sizeof(challenge) - 1] = '\0';

                simulate_puf_response((const uint8_t *)challenge, strlen(challenge), response);
                CRPNode crp = {0};
                snprintf(crp.challenge, sizeof(crp.challenge), "%s", challenge);
                snprintf(crp.response, sizeof(crp.response), "%s", response);
                snprintf(crp.target_ip, sizeof(crp.target_ip), "%s", target_ip);
                db_join_tmp_insert_crp(transaction_id, &crp);

                cJSON *chl_item = cJSON_CreateObject();
                cJSON_AddStringToObject(chl_item, "c", challenge);
                cJSON_AddStringToObject(chl_item, "n", nonce_hex);
                cJSON_AddItemToArray(batch_chl_json, chl_item);
                cJSON *gen_item = cJSON_CreateObject();
                cJSON_AddStringToObject(gen_item, "c", challenge);
                cJSON_AddStringToObject(gen_item, "t", target_ip);
                cJSON_AddStringToObject(gen_item, "h", my_ip);
                cJSON_AddItemToArray(batch_gen_json, gen_item);

                challenge_token = strtok_r(NULL, ",", &chl_saveptr);
            }
            char *batch_chl_str = cJSON_PrintUnformatted(batch_chl_json);
            char nonce_hex_batch_chl[NONCE_HEX_SIZE];
            uint8_t nonce_batch_chl[NONCE_SIZE];
            generate_nonce(nonce_batch_chl, NONCE_SIZE);
            bytes_to_hex(nonce_batch_chl, nonce_hex_batch_chl, NONCE_SIZE);
            int msg_size_prover = snprintf(NULL, 0, "%s:%s:%s:%s\n", MSG_JOIN_CHL, transaction_id_str, batch_chl_str, nonce_hex_batch_chl);
            if (msg_size_prover > 0) {
                char *msg_to_prover = malloc(msg_size_prover + 1);
                if (msg_to_prover && batch_chl_str) {
                    snprintf(msg_to_prover, msg_size_prover + 1, "%s:%s:%s:%s\n", MSG_JOIN_CHL, transaction_id_str, batch_chl_str, nonce_hex_batch_chl);
                    connection_pool_send(target_ip, msg_to_prover);
                    free(msg_to_prover);
                }
            }
            if (batch_chl_str)
                free(batch_chl_str);
            cJSON_Delete(batch_chl_json);
            char *batch_gen_str = cJSON_PrintUnformatted(batch_gen_json);
            char nonce_hex_batch_gen[NONCE_HEX_SIZE];
            uint8_t nonce_batch_gen[NONCE_SIZE];
            generate_nonce(nonce_batch_gen, NONCE_SIZE);
            bytes_to_hex(nonce_batch_gen, nonce_hex_batch_gen, NONCE_SIZE);
            int msg_size_leader = snprintf(NULL, 0, "%s:%s:%s:%s\n", MSG_CHALLENGE_GENERATED, transaction_id_str, batch_gen_str, nonce_hex_batch_gen);
            if (msg_size_leader > 0) {
                char *msg_to_leader = malloc(msg_size_leader + 1);
                if (msg_to_leader && batch_gen_str) {
                    snprintf(msg_to_leader, msg_size_leader + 1, "%s:%s:%s:%s\n", MSG_CHALLENGE_GENERATED, transaction_id_str, batch_gen_str, nonce_hex_batch_gen);
                    connection_pool_send(leader_ip, msg_to_leader);
                    free(msg_to_leader);
                }
            }
            if (batch_gen_str)
                free(batch_gen_str);
            cJSON_Delete(batch_gen_json);
        }
    } else if (strcmp(command, MSG_JOIN_CHL) == 0) {
        char *first_colon = strchr(payload, ':');
        if (!first_colon) {
            ESP_LOGE(TAG, "Malformed %s: missing transaction ID from %s.", command, from_ip);
            goto cleanup;
        }
        *first_colon = '\0';
        char *transaction_id_str = payload;
        char *json_and_nonce = first_colon + 1;

        char *last_colon = strrchr(json_and_nonce, ':');
        if (!last_colon) {
            ESP_LOGE(TAG, "Malformed %s: nonce separator not found from %s.", command, from_ip);
            goto cleanup;
        }
        *last_colon = '\0';
        char *json_payload = json_and_nonce;
        char *nonce = last_colon + 1;

        if (!nonce_is_valid_and_store(nonce)) {
            ESP_LOGW(TAG, "Invalid nonce for %s", command);
            goto cleanup;
        }

        TAKE_NEW_NODE_STATE_MUTEX(__FUNCTION__);
        bool is_legit = false;
        for (int i = 0; i < legitimate_verifier_count; i++) {
            if (strcmp(from_ip, legitimate_verifier_ips[i]) == 0) {
                is_legit = true;
                break;
            }
        }
        GIVE_NEW_NODE_STATE_MUTEX(__FUNCTION__);
        if (is_legit) {
            cJSON *req_root = cJSON_Parse(json_payload);
            cJSON *resp_root = cJSON_CreateArray();
            if (!req_root || !cJSON_IsArray(req_root) || !resp_root) {
                ESP_LOGE(TAG, "Failed to parse JSON challenge array or create response array.");
            } else {
                cJSON *item;
                cJSON_ArrayForEach(item, req_root) {
                    char *challenge = cJSON_GetObjectItem(item, "c")->valuestring;
                    cJSON *nonce_item = cJSON_GetObjectItem(item, "n");

                    if (!cJSON_IsString(nonce_item) || !nonce_is_valid_and_store(nonce_item->valuestring)) {
                        ESP_LOGE(TAG, "Invalid or replayed nonce received for challenge. Skipping.");
                        continue;
                    }
                    char response[64];
                    simulate_puf_response((const uint8_t *)challenge, strlen(challenge), response);
                    cJSON *resp_item = cJSON_CreateObject();
                    cJSON_AddStringToObject(resp_item, "c", challenge);
                    cJSON_AddStringToObject(resp_item, "r", response);
                    cJSON_AddItemToArray(resp_root, resp_item);
                }
                char *resp_json_str = cJSON_PrintUnformatted(resp_root);
                char nonce_hex[NONCE_HEX_SIZE];
                uint8_t new_nonce[NONCE_SIZE];
                generate_nonce(new_nonce, NONCE_SIZE);
                bytes_to_hex(new_nonce, nonce_hex, NONCE_SIZE);
                int msg_size = snprintf(NULL, 0, "%s:%s:%s:%s\n", MSG_JOIN_RESPONSE, transaction_id_str, resp_json_str, nonce_hex);
                if (msg_size > 0) {
                    char *msg_to_verifier = malloc(msg_size + 1);
                    if (msg_to_verifier && resp_json_str) {
                        snprintf(msg_to_verifier, msg_size + 1, "%s:%s:%s:%s\n", MSG_JOIN_RESPONSE, transaction_id_str, resp_json_str, nonce_hex);
                        connection_pool_send(from_ip, msg_to_verifier);
                        free(msg_to_verifier);
                    }
                }
                if (resp_json_str)
                    free(resp_json_str);
            }
            if (req_root)
                cJSON_Delete(req_root);
            if (resp_root)
                cJSON_Delete(resp_root);
            if (first_colon) {
                *first_colon = original_first_char;
            }
            if (last_colon) {
                *last_colon = original_last_char;
            }
        }
    } else if (strcmp(command, MSG_JOIN_RESPONSE) == 0) {
        char *first_colon = strchr(payload, ':');
        if (!first_colon) {
            ESP_LOGE(TAG, "Malformed %s: missing transaction ID from %s.", command, from_ip);
            goto cleanup;
        }
        char original_first_char = *first_colon;
        *first_colon = '\0';
        char *transaction_id_str = payload;
        int transaction_id = strtoul(transaction_id_str, NULL, 10);
        char *json_and_nonce = first_colon + 1;

        char *last_colon = strrchr(json_and_nonce, ':');
        if (!last_colon) {
            ESP_LOGE(TAG, "Malformed %s: nonce separator not found from %s.", command, from_ip);
            *first_colon = ':';
            goto cleanup;
        }
        char original_last_char = *last_colon;
        *last_colon = '\0';
        char *json_payload = json_and_nonce;
        char *nonce = last_colon + 1;

        if (!nonce_is_valid_and_store(nonce)) {
            ESP_LOGW(TAG, "Invalid nonce for %s", command);
            *first_colon = ':';
            goto cleanup;
        }

        cJSON *root = cJSON_Parse(json_payload);
        if (!root || !cJSON_IsArray(root)) {
            ESP_LOGE(TAG, "Failed to parse response JSON array from %s.", from_ip);
        } else {
            int correct_count = 0;
            int total_count = 0;
            cJSON *item;
            cJSON_ArrayForEach(item, root) {
                total_count++;
                char *challenge = cJSON_GetObjectItem(item, "c")->valuestring;
                char *response = cJSON_GetObjectItem(item, "r")->valuestring;
                CRPNode *expected_crp = db_join_tmp_get_crp_by_challenge(transaction_id, challenge);
                if (expected_crp) {                    
                    ESP_LOGI("DEBUG_CMP", "Enrolling CRP for challenge: %s", challenge);
                    ESP_LOGI("DEBUG_CMP", "  - Received Response: '%s'", response);

                    strncpy(expected_crp->response, response, sizeof(expected_crp->response) - 1);
                    db_join_tmp_insert_crp(transaction_id, expected_crp);
                    correct_count++;
                    free(expected_crp);
                } else {
                    ESP_LOGE("DEBUG_CMP", "Challenge '%s' not found in temporary DB!", challenge);
                }
            }
            if (has_leader) {
                char result_msg[256];
                char nonce_hex[NONCE_HEX_SIZE];
                uint8_t new_nonce[NONCE_SIZE];
                generate_nonce(new_nonce, NONCE_SIZE);
                bytes_to_hex(new_nonce, nonce_hex, NONCE_SIZE);
                snprintf(result_msg, sizeof(result_msg), "%s:%s:%s:%d:%d:%s\n", MSG_CHL_RESULT, transaction_id_str, from_ip, correct_count, total_count, nonce_hex);
                connection_pool_send(leader_ip, result_msg);
            }
        }
        if (root)
            cJSON_Delete(root);
        if (first_colon) {
            *first_colon = original_first_char;
        }
        if (last_colon) {
            *last_colon = original_last_char;
        }
    } else if (strcmp(command, MSG_CHALLENGE_GENERATED) == 0) {
        if (is_leader) {
            char *first_colon = strchr(payload, ':');
            if (!first_colon) {
                ESP_LOGE(TAG, "Malformed %s: missing transaction ID from %s.", command, from_ip);
                goto cleanup;
            }
            char original_first_char = *first_colon;
            *first_colon = '\0';

            char *transaction_id_str = payload;
            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);
            char *json_and_nonce = first_colon + 1;

            char *last_colon = strrchr(json_and_nonce, ':');
            if (!last_colon) {
                ESP_LOGE(TAG, "Malformed %s: nonce separator not found from %s.", command, from_ip);
                *first_colon = ':';
                goto cleanup;
            }
            char original_last_char = *last_colon;
            *last_colon = '\0';
            char *json_payload = json_and_nonce;
            char *nonce = last_colon + 1;

            if (!nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Invalid nonce for %s", command);
                *first_colon = ':';
                goto cleanup;
            }

            cJSON *root = cJSON_Parse(json_payload);
            if (root && cJSON_IsArray(root)) {
                cJSON *item;
                cJSON_ArrayForEach(item, root) {
                    char *c = cJSON_GetObjectItem(item, "c")->valuestring;
                    char *t = cJSON_GetObjectItem(item, "t")->valuestring;
                    char *h = cJSON_GetObjectItem(item, "h")->valuestring;
                    db_join_tmp_insert_cnode(transaction_id, c, t, h);
                }
            }
            if (root)
                cJSON_Delete(root);
            if (first_colon) {
                *first_colon = original_first_char;
            }
            if (last_colon) {
                *last_colon = original_last_char;
            }
        }
    } else if (strcmp(command, MSG_JOIN_FINALIZE) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *result_str = strtok_r(NULL, ":", &saveptr);

            if (!transaction_id_str || !result_str) {
                ESP_LOGE(TAG, "Malformed %s from leader.", command);
                goto cleanup;
            }

            char *json_start = payload + strlen(transaction_id_str) + 1 + strlen(result_str) + 1;

            if (atoi(result_str) == 1) {
                char *nodes_json_end = strstr(json_start, "]:");
                if (!nodes_json_end) {
                    ESP_LOGE(TAG, "Malformed %s: separator ']:' not found.", command);
                    goto cleanup;
                }
                *(nodes_json_end + 1) = '\0';
                char *nodes_json_str = json_start;

                char *cnodes_and_nonce = nodes_json_end + 2;
                char *last_colon = strrchr(cnodes_and_nonce, ':');
                if (!last_colon) {
                    ESP_LOGE(TAG, "Malformed %s: nonce separator not found.", command);
                    goto cleanup;
                }
                *last_colon = '\0';
                char *cnodes_json_str = cnodes_and_nonce;
                char *nonce = last_colon + 1;

                if (!nonce_is_valid_and_store(nonce)) {
                    ESP_LOGW(TAG, "Invalid or replayed nonce for successful %s from %s", MSG_JOIN_FINALIZE, from_ip);
                    xSemaphoreGive(join_result_semaphore);
                    goto cleanup;
                }

                ESP_LOGI(TAG, "Join successful. Importing network state.");
                db_import_nodes_json(nodes_json_str);
                db_import_cnode_json(cnodes_json_str);

                ESP_LOGW(TAG, "Starting Raft protocol as a new cluster member...");

                cJSON *nodes_root = cJSON_Parse(nodes_json_str);
                if (nodes_root && cJSON_IsArray(nodes_root)) {
                    int peer_count = cJSON_GetArraySize(nodes_root);
                    char **peer_list = malloc(sizeof(char *) * peer_count);
                    if (peer_list) {
                        int i = 0;
                        cJSON *node_item;

                        ESP_LOGI(TAG, "Populating connection pool and Raft peer list...");
                        cJSON_ArrayForEach(node_item, nodes_root) {
                            char *ip_str = cJSON_GetObjectItem(node_item, "ip")->valuestring;
                            peer_list[i] = strdup(ip_str);
                            if (peer_list[i] == NULL) {
                                ESP_LOGE(TAG, "Memory allocation failed for peer list. Aborting join process.");
                                for (int j = 0; j < i; j++) {
                                    free(peer_list[j]);
                                }
                                free(peer_list);
                                peer_list = NULL;
                                break;
                            }
                            i++;
                        }

                        if (peer_list != NULL) {
                            if (!is_raft_running()) {
                                ESP_LOGW(TAG, "Raft not running. Starting Raft protocol as a new cluster member...");
                                for (i = 0; i < peer_count; i++) {
                                    if (strcmp(peer_list[i], my_ip) != 0) {
                                        connection_pool_add_peer(peer_list[i]);
                                    }
                                }

                                raft_state_init();
                                raft_init_with_peers(peer_list, peer_count);
                            } else {
                                ESP_LOGI(TAG, "Raft already running. Updating peer list and connection pool.");
                                raft_state_update_peers(peer_list, peer_count);
                                for (i = 0; i < peer_count; i++) {
                                    if (strcmp(peer_list[i], my_ip) != 0) {
                                        connection_pool_add_peer(peer_list[i]);
                                    }
                                }
                            }

                            for (i = 0; i < peer_count; i++) {
                                if (peer_list[i])
                                    free(peer_list[i]);
                            }
                            free(peer_list);
                        }
                    }
                    cJSON_Delete(nodes_root);
                } else {
                    ESP_LOGE(TAG, "JSON parsing of nodes failed, cannot start Raft protocol.");
                    if (nodes_root)
                        cJSON_Delete(nodes_root);
                    xSemaphoreGive(join_result_semaphore);
                    goto cleanup;
                }

                *last_colon = ':';
            } else {
                join_result_success = false;
                char *nonce = strtok_r(NULL, "", &saveptr);
                if (!nonce || !nonce_is_valid_and_store(nonce)) {
                    ESP_LOGW(TAG, "Invalid or replayed nonce for failed %s from %s", MSG_JOIN_FINALIZE, from_ip);
                    xSemaphoreGive(join_result_semaphore);
                    goto cleanup;
                }
                ESP_LOGW(TAG, "Join process failed by leader's decision.");
                TAKE_NEW_NODE_STATE_MUTEX(__FUNCTION__);
                legitimate_verifier_count = 0;
                GIVE_NEW_NODE_STATE_MUTEX(__FUNCTION__);
            }

            xSemaphoreGive(join_result_semaphore);
        }
    } else if (strcmp(command, MSG_NODE_ADDED_COMMIT) == 0 || strcmp(command, MSG_NODE_HEALED_COMMIT) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *ip_str = strtok_r(NULL, ":", &saveptr);

            char *json_and_nonce = payload + strlen(transaction_id_str) + 1 + strlen(ip_str) + 1;
            char *last_colon = strrchr(json_and_nonce, ':');

            if (transaction_id_str && ip_str && last_colon) {
                *last_colon = '\0';
                char *cnode_json_delta = json_and_nonce;
                char *nonce = last_colon + 1;
                uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);

                if (nonce_is_valid_and_store(nonce)) {
                    if (strcmp(command, MSG_NODE_ADDED_COMMIT) == 0) {
                        ESP_LOGI(TAG, "[JoinID: %lu] Received commit order for new node %s. Updating local DB.", transaction_id, ip_str);
                        db_insert_node(ip_str, ip_str);
                        raft_state_add_peer(ip_str);
                        db_import_cnode_json(cnode_json_delta);
                        connection_pool_add_peer(ip_str);
                    } else {
                        ESP_LOGI(TAG, "[JoinID: %lu] Received heal commit for node %s. Updating CNodes.", transaction_id, ip_str);
                        db_import_cnode_json(cnode_json_delta);
                    }

                    char ack_msg[128];
                    char nonce_hex_ack[NONCE_HEX_SIZE];
                    uint8_t nonce_ack[NONCE_SIZE];
                    generate_nonce(nonce_ack, NONCE_SIZE);
                    bytes_to_hex(nonce_ack, nonce_hex_ack, NONCE_SIZE);
                    snprintf(ack_msg, sizeof(ack_msg), "%s:%lu:%s\n", MSG_COMMIT_ACK, transaction_id, nonce_hex_ack);
                    connection_pool_send(leader_ip, ack_msg);
                }
            }
        }
    } else if (strcmp(command, MSG_COMMIT_ACK) == 0) {
        if (is_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);

            if (!nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Invalid or replayed nonce for %s from %s", MSG_COMMIT_ACK, from_ip);
                goto cleanup;
            }

            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);

            bool do_finalize_join = false;
            bool handled = false;
            bool do_finalize_heal = false;
            int heal_slot_to_action = -1;

            xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
            for (int i = 0; i < MAX_PARALLEL_HEALS; i++) {
                JoinProcess* job = &pending_heal_jobs[i];
                if (job->in_use && transaction_id == job->transaction_id) {
                    job->commit_ack_count++;

                    ESP_LOGD(TAG, "[TID: %lu] Received COMMIT_ACK from follower %s. Status: %d/%d received.", transaction_id, from_ip, job->commit_ack_count, job->expected_commit_acks);

                    if (job->commit_ack_count >= job->expected_commit_acks) {
                        ESP_LOGI(TAG, "All commit ACKs received. Finalizing heal for %s.", job->new_node_ip);
                        ESP_LOGD(TAG, "[TID: %lu] All COMMIT_ACKs received. Calling leader_finalize_commit.", transaction_id);
                        do_finalize_heal = true;
                        heal_slot_to_action = i;
                    }
                    handled = true;
                    break;
                }
            }
            xSemaphoreGive(heal_pool_mutex);

            if (do_finalize_heal) {
                leader_finalize_commit(&pending_heal_jobs[heal_slot_to_action]);
            }

            if (handled) goto cleanup;

            TAKE_JOIN_MUTEX(__FUNCTION__);
            if (pending_join.in_use && transaction_id == pending_join.transaction_id) {
                pending_join.commit_ack_count++;
                if (pending_join.commit_ack_count >= pending_join.expected_commit_acks) {
                    ESP_LOGI(TAG, "All commit ACKs received. Finalizing join for %s.", pending_join.new_node_ip);
                    db_insert_node(pending_join.new_node_ip, pending_join.new_node_ip);
                    raft_state_add_peer(pending_join.new_node_ip);
                    do_finalize_join = true;
                }
                handled = true;
            }
            GIVE_JOIN_MUTEX(__FUNCTION__);

            if (do_finalize_join) {
                leader_finalize_commit(&pending_join);
            }
        }
    } else if (strcmp(command, MSG_JOIN_ABORT) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);

            if (!nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Invalid or replayed nonce for %s from %s", command, from_ip);
                goto cleanup;
            }

            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);

            ESP_LOGW(TAG, "[JoinID: %lu] Received join abort command from leader.", transaction_id);
            db_join_tmp_clear_by_tid(transaction_id);
            connection_pool_remove_peer(from_ip);
        }
    } else if (strcmp(command, MSG_CLEANUP_COMMIT) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);

            if (!nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Invalid or replayed nonce for %s from %s", command, from_ip);
                goto cleanup;
            }

            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);

            ESP_LOGI(TAG, "[JoinID: %lu] Received cleanup commit command from leader.", transaction_id);
            db_join_tmp_commit_crps(transaction_id);
            db_join_tmp_clear_by_tid(transaction_id);
        }
    } else if (strcmp(command, MSG_DELEGATE_CRPS) == 0) {
        if (is_from_leader) {
            char *last_colon = strrchr(payload, ':');
            if (!last_colon) {
                ESP_LOGE(TAG, "Malformed %s: nonce separator not found from %s.", command, from_ip);
                goto cleanup;
            }

            *last_colon = '\0';
            char *json_payload = payload;
            char *nonce = last_colon + 1;

            if (!nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Invalid nonce for %s", command);
                goto cleanup;
            }

            ESP_LOGW(TAG, "Received genesis credential delegation from leader. Storing CRPs.");
            cJSON *root = cJSON_Parse(json_payload);
            if (root && cJSON_IsArray(root)) {
                cJSON *item;
                int imported_count = 0;
                cJSON_ArrayForEach(item, root) {
                    cJSON *c = cJSON_GetObjectItem(item, "c");
                    cJSON *r = cJSON_GetObjectItem(item, "r");
                    cJSON *t = cJSON_GetObjectItem(item, "t");

                    if (cJSON_IsString(c) && cJSON_IsString(r) && cJSON_IsString(t)) {
                        CRPNode crp = {0};
                        strncpy(crp.challenge, c->valuestring, sizeof(crp.challenge) - 1);
                        strncpy(crp.response, r->valuestring, sizeof(crp.response) - 1);
                        strncpy(crp.target_ip, t->valuestring, sizeof(crp.target_ip) - 1);
                        db_insert_crp(&crp);
                        imported_count++;
                    }
                }
                ESP_LOGI(TAG, "Successfully stored %d delegated CRPs.", imported_count);

                char my_ip[INET_ADDRSTRLEN];
                raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
            } else {
                ESP_LOGE(TAG, "Failed to parse delegated CRPs JSON payload from leader.");
            }
            if (root)
                cJSON_Delete(root);
        }
    } else if (strcmp(command, MSG_JOIN_FAIL_MASTER_CORRUPT) == 0) {
        ESP_LOGE(TAG, "Join failed: Verifier %s reported that the master is corrupt. Waiting for new leader.", from_ip);
    } else {
        ESP_LOGW(TAG, "Received unknown command '%s' from %s.", command, from_ip);
    }

cleanup:
    if (first_colon) {
        *first_colon = original_first_char;
    }
    if (last_colon) {
        *last_colon = original_last_char;
    }
    if (local_message_copy) {
        free(local_message_copy);
    }
    return;
}

/**
 * @brief (Leader-only) Triggers the network healing process if the healing mode flag is set.
 * @details This is designed to be called at startup, after a node becomes leader.
 * It checks the `healing_mode_on_startup` flag, and if set, initiates the healing
 * process to discover and add any missing nodes to the cluster.
 */
void leader_heal_if_needed(void) {
    if (healing_mode_on_startup) {
        if (bootstrap_completed_sem != NULL) {
            ESP_LOGI(TAG, "Bootstrap mode detected.");
            if (xSemaphoreTake(bootstrap_completed_sem, 0) == pdTRUE) {
                ESP_LOGI(TAG, "Starting background heal task runner first.");
                leader_start_network_heal(); 
                
                ESP_LOGI(TAG, "Queueing GENESIS self-join as the first bootstrap job.");
                join_request_t genesis_req = {.type = JOIN_TYPE_GENESIS};
                if (xQueueSend(join_request_queue, &genesis_req, pdMS_TO_TICKS(100)) != pdPASS) {
                    ESP_LOGE(TAG, "CRITICAL: Could not queue GENESIS join request!");
                    xSemaphoreGive(caller_sync_sem); 
                    xSemaphoreGive(bootstrap_completed_sem);
                }
            }
        }
    }
}

/**
 * @brief (Leader-only) Starts the network self-healing process.
 * @details This function is the public-facing entry point for the healing mechanism.
 * It sends a `HEAL_START` monitoring event and, if in bootstrap mode, creates the
 * `leader_heal_task_runner` task to wait for all nodes to join.
 */
void leader_start_network_heal(void) {
    if (is_healing_task_running) {
        ESP_LOGD(TAG, "Healing task is already running, skipping.");
        return;
    }

    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));

    char *event_msg = malloc(MAX_MESSAGE_SIZE);
    if (event_msg) {
        snprintf(event_msg, MAX_MESSAGE_SIZE, "BOOTSTRAP_START:%s", my_mac);
        send_monitoring_tcp_event(event_msg);
        free(event_msg);
    }

    if (healing_mode_on_startup) {
        is_healing_task_running = true;
        xTaskCreate(leader_heal_task_runner, "leader_heal_task", 4096, NULL, 5, &healing_task_handle);
    }
}

/**
 * @brief A dedicated task to process join requests sequentially from a queue.
 * @details This task ensures that the leader handles only one join request at a time,
 * preventing race conditions on the shared 'pending_join' state. It waits for
 * a request, processes it completely by calling the main handler, and then waits
 * for the completion signal before processing the next one. This serializes
 * the entire join workflow.
 * @param pvParameters Unused.
 */
static void join_manager_task(void *pvParameters) {
    join_request_t request;
    ESP_LOGI(TAG, "Join Manager task started, waiting for requests.");

    while (1) {
        if (xQueueReceive(join_request_queue, &request, portMAX_DELAY) == pdTRUE) {
            ESP_LOGI(TAG, "Join Manager: Dequeued request for %s. Starting process...", request.target_ip);

            if (request.type == JOIN_TYPE_BOOTSTRAP_SYNC) {
                ESP_LOGI(TAG, "Join Manager: Received BOOTSTRAP_SYNC job. Notifying leader_heal_task.");
                if (healing_task_handle != NULL) {
                    xTaskNotifyGive(healing_task_handle);
                }
                continue;
            }
            
            node_master_handle_join_request(request.target_ip, request.type, request);
            ESP_LOGI(TAG, "Join Manager: Process for %s completed. Ready for next request.", request.target_ip);
        }
    }
}

/**
 * @brief Sets a flag indicating that the node was started in a mode that requires an automatic network heal.
 * @param enabled True to enable the one-time healing check after an election, false otherwise.
 * @param cluster_size The total number of nodes expected in the cluster during bootstrap.
 */
void auth_join_set_healing_mode(bool enabled, int cluster_size) {
    healing_mode_on_startup = enabled;
    expected_cluster_size = cluster_size;
    ESP_LOGI(TAG, "Healing mode set to %s with expected cluster size %d", enabled ? "ON" : "OFF", cluster_size);
}

/**
 * @brief (Leader-only) A background task that waits for all nodes in a bootstrap
 * scenario to come online and then orchestrates their sequential joining.
 * @details This task is created only when the leader starts in 'bootstrap' mode.
 * It waits until the number of nodes in the database matches the expected
 * cluster size. Once all nodes are present, it triggers the `leader_initiate_full_cluster_join`
 * function to formally add each one to the authentication database.
 * @param pvParameters Unused.
 */
static void leader_heal_task_runner(void *pvParameters) {
    ESP_LOGI(TAG, "Bootstrap healing task started. Waiting for %d peers in Raft state...", expected_cluster_size);

    int peer_count = 0;
    while (true) {
        char** peers = raft_state_get_peers_copy(&peer_count);
        if (peers) {
            for (int i = 0; i < peer_count; i++) { free(peers[i]); }
            free(peers);
        }
        if (peer_count >= expected_cluster_size) break;
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    ESP_LOGI(TAG, "Bootstrap: All peers are in Raft state. Queuing join requests.");
    leader_initiate_full_cluster_join();

    ESP_LOGI(TAG, "Bootstrap: Waiting for join_manager to complete all queued join tasks...");
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "Bootstrap: SYNC notification received. All nodes have completed their join process.");

    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));

    char *event_msg = malloc(MAX_MESSAGE_SIZE);
    if (event_msg) {
        snprintf(event_msg, MAX_MESSAGE_SIZE, "BOOTSTRAP_COMPLETE:%s", my_mac);
        send_monitoring_tcp_event(event_msg);
        free(event_msg);
    }
    
    is_healing_task_running = false;
    healing_mode_on_startup = false; 
    healing_task_handle = NULL;
    xSemaphoreGive(bootstrap_completed_sem);
    vTaskDelete(NULL);
}

/**
 * @brief (Leader-only) Delegates genesis credentials to the first follower.
 * @details This function is called during the finalization of the first follower's join.
 * It reads the leader's self-referential credentials from staging, sends the CRPs to the
 * new follower for custody, and updates the corresponding CNode entries in the provided
 * delta JSON object to reflect the new holder. This ensures the delegation is part of
 * the atomic commit of the join transaction.
 * @param new_follower_ip The IP address of the first follower who will become the new holder.
 * @param cnodes_delta_obj A pointer to the cJSON array object containing the staged
 * CNode delta. This object will be modified in-place to update the holder IPs of the
 * leader's genesis CNodes.
 * @return void
 */
static void leader_initiate_full_cluster_join() {
    ESP_LOGI(TAG, "Leader is now initiating full cluster join process...");

    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);

    if (!db_node_exists(my_ip)) {
         ESP_LOGE(TAG, "CRITICAL: Leader self-join incomplete before starting follower joins!");
    }

    int peer_count = 0;
    char **peer_ips = raft_state_get_peers_copy(&peer_count);
    if (!peer_ips) {
        ESP_LOGE(TAG, "Failed to get peer list for follower join initiation.");
        if (healing_task_handle != NULL) {
           xTaskNotifyGive(healing_task_handle);
        }
        return;
    }

    ESP_LOGI(TAG, "Starting to queue join requests for %d other peers.", peer_count - 1);

    for (int i = 0; i < peer_count; i++) {
        char *node_ip = peer_ips[i];
        if (strcmp(node_ip, my_ip) == 0) continue;

        if (!db_node_exists(node_ip)) {
            ESP_LOGI(TAG, "[BOOTSTRAP_JOIN] Starting synchronous join for node: %s", node_ip);
            
            join_request_t join_req = {.type = JOIN_TYPE_NEW_NODE};
            strncpy(join_req.target_ip, node_ip, INET_ADDRSTRLEN);

            if (xQueueSend(join_request_queue, &join_req, pdMS_TO_TICKS(1000)) == pdPASS) {
                ESP_LOGI(TAG, "[BOOTSTRAP_JOIN] Job queued for %s.", node_ip);
            } else {
                ESP_LOGE(TAG, "[BOOTSTRAP_JOIN] Could not queue join request for %s.", node_ip);
                break;
            }
        }
    }

    ESP_LOGI(TAG, "All bootstrap join requests have been queued. Adding final SYNC job.");
    join_request_t sync_req = {.type = JOIN_TYPE_BOOTSTRAP_SYNC};
    if (xQueueSend(join_request_queue, &sync_req, pdMS_TO_TICKS(100)) != pdPASS) {
        ESP_LOGE(TAG, "Could not queue the final bootstrap SYNC job!");
    }

    for (int i = 0; i < peer_count; i++) free(peer_ips[i]);
    free(peer_ips);
    ESP_LOGI(TAG, "All bootstrap join requests have been queued.");
}

/**
 * @brief (Leader-only) A parallel worker task to execute a single HEAL job.
 * @details This task is spawned by `auth_join_run_heal_job_async` to handle
 * a HEAL process concurrently without blocking the main `join_manager_task`.
 * It finds a free slot in the `pending_heal_jobs` array, populates it,
 * and then executes the blocking `master_assign_new_verifiers` function.
 * This task manages its own lifecycle, including cleaning up its job slot
 * in the pool and signaling `caller_sync_sem` upon completion or failure.
 * @param pvParameters A pointer to a dynamically allocated `join_request_t`.
 * This task takes ownership of the pointer and is responsible for freeing it
 * before exiting.
 */
static void auth_join_heal_task(void *pvParameters) {
    join_request_t* request = (join_request_t*)pvParameters;
    if (!request) {
        ESP_LOGE(TAG, "auth_join_heal_task started with NULL parameters!");
        vTaskDelete(NULL);
        return;
    }

    xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
    int job_slot = -1;
    for (int i = 0; i < MAX_PARALLEL_HEALS; i++) {
        if (!pending_heal_jobs[i].in_use) {
            job_slot = i;
            break;
        }
    }

    if (job_slot == -1) {
        ESP_LOGE(TAG, "No HEAL job slots available for %s. Aborting.", request->target_ip);
        xSemaphoreGive(heal_pool_mutex);
        free(request);
        xSemaphoreGive(caller_sync_sem);
        vTaskDelete(NULL);
        return;
    }
    
    JoinProcess* job = &pending_heal_jobs[job_slot];
    memset(job, 0, sizeof(JoinProcess));
    job->in_use = true;
    job->start_time_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    job->transaction_id = __atomic_add_fetch(&last_transaction_id, 1, __ATOMIC_SEQ_CST);
    strncpy(job->new_node_ip, request->target_ip, INET_ADDRSTRLEN - 1);
    job->type = JOIN_TYPE_HEAL_NODE;

    uint32_t my_tid = job->transaction_id;

    job->ack_semaphore = xSemaphoreCreateBinary();
    job->completion_semaphore = xSemaphoreCreateBinary();

    if (job->ack_semaphore == NULL || job->completion_semaphore == NULL) {
        ESP_LOGE(TAG, "Failed to create semaphores for heal job!");
        memset(job, 0, sizeof(JoinProcess));
        xSemaphoreGive(heal_pool_mutex);
        free(request);
        xSemaphoreGive(caller_sync_sem);
        vTaskDelete(NULL);
        return;
    }

    SemaphoreHandle_t completion_sem_local = job->completion_semaphore;
    xSemaphoreGive(heal_pool_mutex);

    ESP_LOGD(TAG, "[TID: %lu] HEAL task (slot %d) STARTED for %s", job->transaction_id, job_slot, job->new_node_ip);

    int num_verifiers = request->num_verifiers_to_add;
    
    ESP_LOGD(TAG, "[TID: %lu] HEAL task calling master_assign_new_verifiers", job->transaction_id);
    master_assign_new_verifiers(job, job->new_node_ip, num_verifiers, job->transaction_id);
    ESP_LOGD(TAG, "[TID: %lu] HEAL task returned from master_assign_new_verifiers", job->transaction_id);

    ESP_LOGI(TAG, "HEAL task for %s [JoinID: %lu] waiting for final async result...", job->new_node_ip, job->transaction_id);

    if (xSemaphoreTake(completion_sem_local, pdMS_TO_TICKS(JOIN_PROCESS_TIMEOUT_MS + 2000)) == pdTRUE) {
        ESP_LOGI(TAG, "HEAL task for %s [JoinID: %lu] received final signal.", job->new_node_ip, job->transaction_id);
    } else {
        ESP_LOGE(TAG, "HEAL task for %s [JoinID: %lu] TIMED OUT waiting for final signal!", job->new_node_ip, job->transaction_id);
    }
    
    vSemaphoreDelete(job->ack_semaphore);
    vSemaphoreDelete(completion_sem_local);
    ESP_LOGI(TAG, "HEAL task for %s [JoinID: %lu] has finished.", job->new_node_ip, job->transaction_id);

    xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
    if (job->in_use && job->transaction_id == my_tid) {
        ESP_LOGD(TAG, "Heal task %s [TID: %lu] cleaning up its own job slot.", job->new_node_ip, job->transaction_id);
        memset(job, 0, sizeof(JoinProcess));
    }
    xSemaphoreGive(heal_pool_mutex);
    xSemaphoreGive(caller_sync_sem);
    
    free(request);
    vTaskDelete(NULL);
}

/**
 * @brief (Leader-only) Public function to trigger a parallel HEAL job.
 * @details This function is called by external modules (e.g., `auth_remove`)
 * to initiate a synchronous (from the caller's perspective) but parallel
 * (from the module's perspective) HEAL operation. It allocates a copy of
 * the request and spawns a dedicated `auth_join_heal_task` to manage the
 * job's lifecycle. The caller *must* wait on the `caller_sync_sem` for
 * the operation to complete, as this function returns immediately.
 * @param request The `join_request_t` struct containing the parameters for
 * the HEAL job, including the `target_ip` and `num_verifiers_to_add`.
 */
void auth_join_run_heal_job_async(join_request_t request) {
    join_request_t* req_copy = malloc(sizeof(join_request_t));
    if (!req_copy) {
        ESP_LOGE(TAG, "Failed to allocate memory for heal request. Aborting.");
        xSemaphoreGive(caller_sync_sem);
        return;
    }
    memcpy(req_copy, &request, sizeof(join_request_t));

    if (xTaskCreate(auth_join_heal_task, "heal_job_task", 8192, req_copy, 6, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create heal task for %s. Aborting.", request.target_ip);
        free(req_copy);
        xSemaphoreGive(caller_sync_sem);
    }
}