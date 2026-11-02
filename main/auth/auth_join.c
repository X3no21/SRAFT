/* =============================
 * File: auth_join.c
 * Description: Implements the definitive, synchronized, multi-verifier node join protocol.
 * ============================= */

#include "auth_join.h"
#include "hatt_protocol.h"
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
#include <fcntl.h>
#include <cJSON.h>

static const char *TAG = "AUTH_JOIN";

static char legitimate_verifier_ips[MAX_VERIFIERS][INET_ADDRSTRLEN];

#define MAX_PENDING_ENROLLMENTS 32
#define PENDING_ENROLLMENT_TTL_MS 120000

// (Prover) Challenges answered in an enrollment that is not committed yet, per Verifier.
static struct {
    bool in_use;
    char verifier_ip[INET_ADDRSTRLEN];
    char challenge[64];
    TickType_t created;
} pending_challenges[MAX_PENDING_ENROLLMENTS];

// (Verifier) Enrollments whose responses must arrive encrypted.
static struct {
    bool in_use;
    uint32_t transaction_id;
    char target_ip[INET_ADDRSTRLEN];
    TickType_t created;
} secure_enrollments[MAX_PENDING_ENROLLMENTS];

static portMUX_TYPE pending_enrollment_spinlock = portMUX_INITIALIZER_UNLOCKED;

static void remember_pending_challenge(const char *verifier_ip, const char *challenge) {
    taskENTER_CRITICAL(&pending_enrollment_spinlock);
    TickType_t now = xTaskGetTickCount();
    int slot = 0;
    for (int i = 0; i < MAX_PENDING_ENROLLMENTS; i++) {
        if (!pending_challenges[i].in_use || (now - pending_challenges[i].created) * portTICK_PERIOD_MS > PENDING_ENROLLMENT_TTL_MS ||
            strcmp(pending_challenges[i].verifier_ip, verifier_ip) == 0) {
            slot = i;
            break;
        }
        if (pending_challenges[i].created < pending_challenges[slot].created) slot = i;
    }
    pending_challenges[slot].in_use = true;
    strncpy(pending_challenges[slot].verifier_ip, verifier_ip, INET_ADDRSTRLEN - 1);
    pending_challenges[slot].verifier_ip[INET_ADDRSTRLEN - 1] = '\0';
    strncpy(pending_challenges[slot].challenge, challenge, sizeof(pending_challenges[slot].challenge) - 1);
    pending_challenges[slot].challenge[sizeof(pending_challenges[slot].challenge) - 1] = '\0';
    pending_challenges[slot].created = now;
    taskEXIT_CRITICAL(&pending_enrollment_spinlock);
}

bool join_is_pending_challenge(const char *verifier_ip, const char *challenge) {
    bool found = false;
    taskENTER_CRITICAL(&pending_enrollment_spinlock);
    TickType_t now = xTaskGetTickCount();
    for (int i = 0; i < MAX_PENDING_ENROLLMENTS && !found; i++) {
        found = pending_challenges[i].in_use && (now - pending_challenges[i].created) * portTICK_PERIOD_MS <= PENDING_ENROLLMENT_TTL_MS &&
                strcmp(pending_challenges[i].verifier_ip, verifier_ip) == 0 && strcmp(pending_challenges[i].challenge, challenge) == 0;
    }
    taskEXIT_CRITICAL(&pending_enrollment_spinlock);
    return found;
}

static void expect_secure_enrollment(uint32_t transaction_id, const char *target_ip) {
    taskENTER_CRITICAL(&pending_enrollment_spinlock);
    TickType_t now = xTaskGetTickCount();
    int slot = 0;
    for (int i = 0; i < MAX_PENDING_ENROLLMENTS; i++) {
        if (!secure_enrollments[i].in_use || (now - secure_enrollments[i].created) * portTICK_PERIOD_MS > PENDING_ENROLLMENT_TTL_MS) {
            slot = i;
            break;
        }
        if (secure_enrollments[i].created < secure_enrollments[slot].created) slot = i;
    }
    secure_enrollments[slot].in_use = true;
    secure_enrollments[slot].transaction_id = transaction_id;
    strncpy(secure_enrollments[slot].target_ip, target_ip, INET_ADDRSTRLEN - 1);
    secure_enrollments[slot].target_ip[INET_ADDRSTRLEN - 1] = '\0';
    secure_enrollments[slot].created = now;
    taskEXIT_CRITICAL(&pending_enrollment_spinlock);
}

/**
 * @brief (Verifier) Tells whether the responses of an enrollment must arrive encrypted, and forgets it.
 */
static bool take_secure_enrollment(uint32_t transaction_id, const char *target_ip) {
    bool found = false;
    taskENTER_CRITICAL(&pending_enrollment_spinlock);
    for (int i = 0; i < MAX_PENDING_ENROLLMENTS && !found; i++) {
        if (secure_enrollments[i].in_use && secure_enrollments[i].transaction_id == transaction_id &&
            strcmp(secure_enrollments[i].target_ip, target_ip) == 0) {
            secure_enrollments[i].in_use = false;
            found = true;
        }
    }
    taskEXIT_CRITICAL(&pending_enrollment_spinlock);
    return found;
}
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
 * @brief (Leader-only) Records when the majority of the members acknowledged a commit.
 * @details The members asked are the other ones, so with the Coordinator the majority is reached at
 * (expected + 1) / 2 acknowledgements, as for a removal.
 */
static void note_commit_majority(JoinProcess *job) {
    if (job->commit_majority_ms == 0 && job->expected_commit_acks > 0 &&
        job->commit_ack_count >= (job->expected_commit_acks + 1) / 2) {
        job->commit_majority_ms = (xTaskGetTickCount() * portTICK_PERIOD_MS) | 1;
    }
}

static bool commit_grace_expired(const JoinProcess *job) {
    return job->in_use && job->expected_commit_acks > 0 && job->commit_ack_count < job->expected_commit_acks &&
           job->commit_majority_ms != 0 &&
           (xTaskGetTickCount() * portTICK_PERIOD_MS) - job->commit_majority_ms >= COMMIT_ACK_GRACE_MS;
}

/* Network state received by a joining device in NET_STATE parts, kept until the next join. */
static struct {
    uint32_t tid;
    int parts;
    int received;
    char *buf;
    size_t len;
} net_state = {0};

static void net_state_add(uint32_t tid, int part, int parts, const char *data) {
    if (part == 0 || tid != net_state.tid) {
        free(net_state.buf);
        memset(&net_state, 0, sizeof(net_state));
        net_state.tid = tid;
        net_state.parts = parts;
    }
    if (part != net_state.received || parts != net_state.parts || parts <= 0) {
        ESP_LOGE(TAG, "[JoinID: %lu] Network state part %d/%d out of order.", tid, part, parts);
        net_state.received = -1;
        return;
    }
    size_t n = strlen(data);
    char *grown = realloc(net_state.buf, net_state.len + n + 1);
    if (!grown) { net_state.received = -1; return; }
    net_state.buf = grown;
    memcpy(net_state.buf + net_state.len, data, n + 1);
    net_state.len += n;
    net_state.received++;
}

static bool net_state_complete(uint32_t tid) {
    return net_state.buf && net_state.tid == tid && net_state.parts > 0 && net_state.received == net_state.parts;
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
        
        bool needs_rollback_join = false;

        // Commits acknowledged by the majority are completed without waiting for the members that do not answer.
        bool finalize_join = false;
        TAKE_JOIN_MUTEX(__FUNCTION__);
        if (commit_grace_expired(&pending_join)) {
            ESP_LOGW(TAG, "[JoinID: %lu] Commit acknowledged by %d of %d members: completing the join of %s.",
                     pending_join.transaction_id, pending_join.commit_ack_count, pending_join.expected_commit_acks, pending_join.new_node_ip);
            pending_join.expected_commit_acks = pending_join.commit_ack_count;
            db_insert_node(pending_join.new_node_ip, pending_join.new_node_ip);
            raft_state_add_peer(pending_join.new_node_ip);
            finalize_join = true;
        }
        GIVE_JOIN_MUTEX(__FUNCTION__);
        if (finalize_join) leader_finalize_commit(&pending_join);

        int heal_to_finalize[MAX_PARALLEL_HEALS];
        int heals_to_finalize = 0;
        xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
        for (int i = 0; i < MAX_PARALLEL_HEALS; i++) {
            JoinProcess* job = &pending_heal_jobs[i];
            if (commit_grace_expired(job)) {
                ESP_LOGW(TAG, "[JoinID: %lu] Commit acknowledged by %d of %d members: completing the heal of %s.",
                         job->transaction_id, job->commit_ack_count, job->expected_commit_acks, job->new_node_ip);
                job->expected_commit_acks = job->commit_ack_count;
                heal_to_finalize[heals_to_finalize++] = i;
            }
        }
        xSemaphoreGive(heal_pool_mutex);
        for (int k = 0; k < heals_to_finalize; k++) leader_finalize_commit(&pending_heal_jobs[heal_to_finalize[k]]);

        TAKE_JOIN_MUTEX(__FUNCTION__);
        if (pending_join.in_use) {
            uint32_t elapsed_time_ms = (xTaskGetTickCount() * portTICK_PERIOD_MS) - pending_join.start_time_ms;
            if (elapsed_time_ms > JOIN_PROCESS_TIMEOUT_MS) {
                ESP_LOGE(TAG, "[JoinID: %lu] Sequential Join process for node %s timed out. Staging rollback.",
                         pending_join.transaction_id, pending_join.new_node_ip);
                needs_rollback_join = true;
            }
        }
        GIVE_JOIN_MUTEX(__FUNCTION__);

        // The job itself is rolled back, not a copy: the rollback releases its semaphore and clears it.
        if (needs_rollback_join) {
            master_trigger_join_rollback(&pending_join);
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
/**
 * @brief (Leader-only) Picks a response index of a device that was never assigned before.
 * @details Every challenge addresses its own group of cells of the device, so an index must be
 * used at most once: it is rejected if it appears in the network state, including the challenges
 * of removed Verifiers, which are kept as revoked, or among those drawn in the current operation.
 * @param target_ip The device the challenge is for.
 * @param already_drawn Comma-separated challenges drawn so far for the same Verifier.
 * @param challenge Output buffer for the challenge string.
 * @param challenge_size The size of the output buffer.
 * @return true if an unused index was found.
 */
static bool allocate_puf_challenge(const char *target_ip, const char *already_drawn, char *challenge, size_t challenge_size) {
    int start = esp_random() % PUF_RESPONSE_CAPACITY;
    for (int i = 0; i < PUF_RESPONSE_CAPACITY; i++) {
        puf_format_challenge((start + i) % PUF_RESPONSE_CAPACITY, target_ip, challenge, challenge_size);

        bool drawn = false;
        size_t len = strlen(challenge);
        for (const char *p = strstr(already_drawn, challenge); p != NULL && !drawn; p = strstr(p + 1, challenge)) {
            drawn = (p == already_drawn || p[-1] == ',') && (p[len] == ',' || p[len] == '\0');
        }

        if (!drawn && !db_challenge_exists_globally(challenge)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief (Leader-only) Checks that a device answers before it is given a role in an enrollment.
 * @details A device that has failed may still be listed as a member until its removal, and also its TCP
 * connection may look open for a while, since a device that loses power sends nothing. A connection
 * attempt to its attestation port, which every member keeps open, tells within a short time whether it
 * is reachable, so that a heal is not stalled by a Verifier or intermediary that cannot answer.
 */
bool auth_join_device_reachable(const char *ip) {
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(HATT_PORT) };
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) return false;
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) return false;
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    bool reachable = false;
    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        reachable = true;
    } else if (errno == EINPROGRESS) {
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        struct timeval tv = { .tv_sec = DEVICE_PROBE_TIMEOUT_MS / 1000, .tv_usec = (DEVICE_PROBE_TIMEOUT_MS % 1000) * 1000 };
        if (select(sock + 1, NULL, &write_fds, NULL, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            reachable = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0;
        }
    }
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    close(sock);
    if (!reachable) ESP_LOGW(TAG, "Device %s does not answer: it is not given a role in this enrollment.", ip);
    return reachable;
}

/**
 * @brief (Leader-only) Finds a device that can give a Prover and a candidate Verifier the key of an enrollment.
 * @details The intermediary must hold CRPs of the candidate Verifier and either be the Prover
 * itself or hold CRPs of the Prover as well, so that it shares a PUF-keyed channel with both.
 * @param target_ip The Prover.
 * @param candidate_ip The candidate Verifier.
 * @param target_verifiers The current Verifiers of the Prover.
 * @param broker_ip Output buffer for the intermediary.
 * @return true if an intermediary exists.
 */
static bool find_enrollment_broker(const char *target_ip, const char *candidate_ip, char target_verifiers[][INET_ADDRSTRLEN],
                                   int target_verifier_count, char *broker_ip) {
    char (*candidate_verifiers)[INET_ADDRSTRLEN] = malloc(MAX_VERIFIERS * INET_ADDRSTRLEN);
    if (!candidate_verifiers) return false;

    bool found = false;
    int candidate_verifier_count = db_get_verifiers_for_node(candidate_ip, candidate_verifiers, MAX_VERIFIERS);
    for (int i = 0; i < candidate_verifier_count && !found; i++) {
        if (strcmp(candidate_verifiers[i], target_ip) == 0) {
            found = true;
        }
        for (int j = 0; j < target_verifier_count && !found; j++) {
            found = strcmp(candidate_verifiers[i], target_verifiers[j]) == 0;
        }
        if (found && !auth_join_device_reachable(candidate_verifiers[i])) {
            found = false;
        }
        if (found) {
            strncpy(broker_ip, candidate_verifiers[i], INET_ADDRSTRLEN - 1);
            broker_ip[INET_ADDRSTRLEN - 1] = '\0';
        }
    }
    free(candidate_verifiers);
    return found;
}

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
    char selected_brokers[MAX_VERIFIERS][INET_ADDRSTRLEN];
    int selected_count = 0;
    char *string_buffer_position = verifier_list_str;
    size_t remaining_buffer_space = 1024;
    memset(selected_brokers, 0, sizeof(selected_brokers));

    // A device that is already a member is enrolled at a new Verifier through an intermediary that
    // shares a PUF-keyed channel with both. The first pass accepts only candidates for which one
    // exists; the second pass completes the selection as in the first enrollment of a device.
    int selection_passes = (job->type == JOIN_TYPE_HEAL_NODE) ? 2 : 1;
    for (int pass = 0; pass < selection_passes && follower_count > 0; pass++) {
        bool require_broker = (job->type == JOIN_TYPE_HEAL_NODE) && pass == 0;
        int attempts = 0;
        while (selected_count < num_to_add && attempts < (follower_count * 2)) {
            char follower_ip_buffer[INET_ADDRSTRLEN];
            if (db_get_random_follower_ip(follower_ip_buffer, sizeof(follower_ip_buffer))) {
                char candidate_broker[INET_ADDRSTRLEN] = {0};
                if (strcmp(follower_ip_buffer, target_ip) == 0 ||
                    (require_broker && !find_enrollment_broker(target_ip, follower_ip_buffer, existing_verifiers, existing_verifiers_count, candidate_broker))) {
                    attempts++;
                    continue;
                }

                if (job->type == JOIN_TYPE_HEAL_NODE && !auth_join_device_reachable(follower_ip_buffer)) {
                    attempts++;
                    continue;
                }

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
                    strncpy(selected_brokers[selected_count], candidate_broker, INET_ADDRSTRLEN - 1);
                    
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
            job->broker_addrs[job->verifier_count] = 0;
            if (selected_brokers[i][0] != '\0') {
                inet_pton(AF_INET, selected_brokers[i], &job->broker_addrs[job->verifier_count]);
            }
            job->verifier_count++;
        }
    } else {
        ESP_LOGW(TAG, "[JoinID: %lu] No followers found. Bootstrapping with self as the only verifier.", transaction_id);
        job->verifier_count = 1;
        strncpy(job->verifier_ips[0], my_ip, INET_ADDRSTRLEN - 1);
        job->broker_addrs[0] = 0;
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
    job->wrong_proof_results = 0;
    job->reported_verifiers_mask = 0;

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


    // Challenges drawn in this operation for all the verifiers, so that none is assigned twice.
    const size_t drawn_size = 4096;
    char *drawn_in_operation = calloc(1, drawn_size);
    if (!drawn_in_operation) {
        ESP_LOGE(TAG, "[JoinID: %lu] Failed to allocate memory for the challenge list.", transaction_id);
        finalize_join_process(job, false);
        return;
    }

    for (int i = 0; i < job->verifier_count; i++) {
        const char* current_verifier_ip = job->verifier_ips[i];
        int num_challenges_for_verifier = CRPS_PER_VERIFIER;

        char challenges_list_str[1024] = {0};
        char *ptr = challenges_list_str;
        size_t remaining = sizeof(challenges_list_str);

        int drawn_for_verifier = 0;
        for (int k = 0; k < num_challenges_for_verifier; k++) {
            char challenge[64];
            if (!allocate_puf_challenge(target_ip, drawn_in_operation, challenge, sizeof(challenge))) {
                ESP_LOGE(TAG, "[JoinID: %lu] No unused response index left for %s.", transaction_id, target_ip);
                break;
            }

            size_t drawn_len = strlen(drawn_in_operation);
            snprintf(drawn_in_operation + drawn_len, drawn_size - drawn_len, "%s%s", (drawn_len > 0) ? "," : "", challenge);

            int written = snprintf(ptr, remaining, "%s%s", (k > 0) ? "," : "", challenge);
            if (written > 0 && written < remaining) {
                ptr += written;
                remaining -= written;
            }
            drawn_for_verifier++;
        }
        num_challenges_for_verifier = drawn_for_verifier;

        char nonce_hex_req[NONCE_HEX_SIZE];
        uint8_t nonce_req[NONCE_SIZE];
        generate_nonce(nonce_req, NONCE_SIZE);
        bytes_to_hex(nonce_req, nonce_hex_req, NONCE_SIZE);

        char broker_buf[INET_ADDRSTRLEN];
        const char *broker_ip = ENROLL_NO_BROKER;
        if (job->broker_addrs[i] != 0 && inet_ntop(AF_INET, &job->broker_addrs[i], broker_buf, sizeof(broker_buf))) {
            broker_ip = broker_buf;
        }
        if (strcmp(broker_ip, ENROLL_NO_BROKER) != 0) {
            // The intermediary gives the Prover and this Verifier the key that protects the responses.
            if (strcmp(broker_ip, my_ip) == 0) {
                if (!auth_puf_broker_enrollment(transaction_id, target_ip, current_verifier_ip)) {
                    ESP_LOGE(TAG, "[JoinID: %lu] Could not deliver the enrollment key for %s and %s.", transaction_id, target_ip, current_verifier_ip);
                }
            } else {
                char nonce_hex_broker[NONCE_HEX_SIZE];
                uint8_t nonce_broker[NONCE_SIZE];
                generate_nonce(nonce_broker, NONCE_SIZE);
                bytes_to_hex(nonce_broker, nonce_hex_broker, NONCE_SIZE);

                char broker_msg[160];
                snprintf(broker_msg, sizeof(broker_msg), "%s:%lu:%s:%s:%s\n", MSG_BROKER_REQ, transaction_id, target_ip, current_verifier_ip, nonce_hex_broker);
                connection_pool_send(broker_ip, broker_msg);
            }
        } else if (job->type == JOIN_TYPE_HEAL_NODE) {
            ESP_LOGW(TAG, "[JoinID: %lu] No intermediary shares a channel with %s and %s: enrolling as in a first enrollment.", transaction_id, target_ip, current_verifier_ip);
            char unprotected_event[96];
            snprintf(unprotected_event, sizeof(unprotected_event), "HEAL_UNPROTECTED:%s:%s", target_ip, current_verifier_ip);
            send_monitoring_tcp_event(unprotected_event);
        }

        int req_msg_size = snprintf(NULL, 0, "%s:%lu:%s:%d:%s:%s:%s\n", MSG_REQ_CHL_GEN, transaction_id, target_ip, num_challenges_for_verifier, challenges_list_str, broker_ip, nonce_hex_req);
        if (req_msg_size > 0) {
            char *req_msg = malloc(req_msg_size + 1);
            if (req_msg) {
                snprintf(req_msg, req_msg_size + 1, "%s:%lu:%s:%d:%s:%s:%s\n", MSG_REQ_CHL_GEN, transaction_id, target_ip, num_challenges_for_verifier, challenges_list_str, broker_ip, nonce_hex_req);
                ESP_LOGI(TAG, "[JoinID: %lu] Sending %d pre-generated challenges to verifier %s", transaction_id, num_challenges_for_verifier, current_verifier_ip);
                connection_pool_send(current_verifier_ip, req_msg);
                free(req_msg);
            } else {
                ESP_LOGE(TAG, "Failed to allocate memory for REQ_CHL_GEN message.");
            }
        }
    }
    free(drawn_in_operation);

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

        if (raft_state_is_blacklisted(actual_mac)) {
            // A device that failed an integrity check is excluded for good.
            ESP_LOGE(TAG, "Join request from excluded device %s (MAC: %s). Rejecting join.", effective_target_ip, actual_mac);
            char nonce_hex_excl[NONCE_HEX_SIZE];
            uint8_t nonce_excl[NONCE_SIZE];
            generate_nonce(nonce_excl, NONCE_SIZE);
            bytes_to_hex(nonce_excl, nonce_hex_excl, NONCE_SIZE);

            char excl_msg[128];
            snprintf(excl_msg, sizeof(excl_msg), "%s:0:0:%s\n", MSG_JOIN_FINALIZE, nonce_hex_excl);
            connection_pool_send(effective_target_ip, excl_msg);

            char *excl_event = malloc(MAX_MESSAGE_SIZE);
            if (excl_event) {
                snprintf(excl_event, MAX_MESSAGE_SIZE, "JOIN_FAILED_BLACKLISTED:%s", effective_target_ip);
                send_monitoring_tcp_event(excl_event);
                free(excl_event);
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
 * @brief (Leader-only) Creates and stages the leader's own genesis credentials.
 */
void leader_bootstrap_self_join() {
    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    ESP_LOGI(TAG, "Leader %s is performing genesis self-join to create initial credentials.", my_ip);

    const int num_challenges_for_genesis = CRPS_PER_VERIFIER;
    for (int i = 0; i < num_challenges_for_genesis; i++) {
        char challenge[64], response[64];
        puf_format_challenge(i, my_ip, challenge, sizeof(challenge));
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
    (void)job;
    (void)cnodes_delta_obj;
    ESP_LOGI(TAG, "This is the first follower. Delegating my genesis credentials to %s.", new_follower_ip);

    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);

    cJSON *crps_to_delegate_json = cJSON_CreateArray();
    if (!crps_to_delegate_json) {
        ESP_LOGE(TAG, "Failed to create cJSON array for CRP delegation.");
        return;
    }

    // The genesis credentials were committed to the network state when the Coordinator was alone, with the
    // Coordinator as their holder. They are moved to the first device before the network state is sent to
    // it, so that from now on the Coordinator, too, is checked by another device.
    char challenges[CRPS_PER_VERIFIER][64];
    int moved = db_reassign_self_cnodes(my_ip, new_follower_ip, challenges, CRPS_PER_VERIFIER);
    for (int i = 0; i < moved; i++) {
        CRPNode* crp = db_get_crp_by_challenge(challenges[i]);
        if (crp) {
            cJSON *crp_json = cJSON_CreateObject();
            cJSON_AddStringToObject(crp_json, "c", crp->challenge);
            cJSON_AddStringToObject(crp_json, "r", crp->response);
            cJSON_AddStringToObject(crp_json, "t", crp->target_ip);
            cJSON_AddItemToArray(crps_to_delegate_json, crp_json);
            free(crp);
        }
    }
    ESP_LOGI(TAG, "Delegated %d genesis CRPs to %s.", cJSON_GetArraySize(crps_to_delegate_json), new_follower_ip);

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
                job->commit_majority_ms = 0;
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
    char *cnodes_json_base_str = NULL;
    char *cnodes_json_delta_str = db_join_tmp_export_cnodes_json(job->transaction_id);
    cJSON *cnodes_delta_obj = cJSON_Parse(cnodes_json_delta_str);
    if (!cnodes_delta_obj)
        cnodes_delta_obj = cJSON_CreateArray();

    if (is_first_follower) {
        leader_delegate_genesis_credentials(job, job->new_node_ip, cnodes_delta_obj);
    }

    char *final_delta_str = cJSON_PrintUnformatted(cnodes_delta_obj);
    // The network state for the new device: the members (JSON) and the challenges (compact form), sent in
    // NET_STATE parts before JOIN_FINALIZE, since with many devices it does not fit in one message.
    char *cnodes_final_for_new_node_str = db_export_state_compact(final_delta_str);

    const char *nodes_str = nodes_json_full ? nodes_json_full : "[]";
    const char *cnodes_final_str = cnodes_final_for_new_node_str ? cnodes_final_for_new_node_str : "#";
    const char *delta_to_broadcast_str = final_delta_str ? final_delta_str : "[]";

    size_t state_len = strlen(nodes_str) + 1 + strlen(cnodes_final_str);
    char *state = malloc(state_len + 1);
    if (state) {
        snprintf(state, state_len + 1, "%s|%s", nodes_str, cnodes_final_str);
        int parts = (int)((state_len + NET_STATE_CHUNK_SIZE - 1) / NET_STATE_CHUNK_SIZE);
        char *msg_part = malloc(NET_STATE_CHUNK_SIZE + 128);
        for (int part = 0; msg_part && part < parts; part++) {
            char nonce_hex_part[NONCE_HEX_SIZE];
            uint8_t nonce_part[NONCE_SIZE];
            generate_nonce(nonce_part, NONCE_SIZE);
            bytes_to_hex(nonce_part, nonce_hex_part, NONCE_SIZE);
            size_t off = (size_t)part * NET_STATE_CHUNK_SIZE;
            int n = (int)((state_len - off) < NET_STATE_CHUNK_SIZE ? (state_len - off) : NET_STATE_CHUNK_SIZE);
            snprintf(msg_part, NET_STATE_CHUNK_SIZE + 128, "%s:%lu:%d:%d:%s:%.*s\n", MSG_NET_STATE, job->transaction_id, part, parts,
                     nonce_hex_part, n, state + off);
            connection_pool_send(job->new_node_ip, msg_part);
        }
        free(msg_part);
        free(state);
    }

    char nonce_hex_finalize[NONCE_HEX_SIZE];
    uint8_t nonce_finalize[NONCE_SIZE];
    generate_nonce(nonce_finalize, NONCE_SIZE);
    bytes_to_hex(nonce_finalize, nonce_hex_finalize, NONCE_SIZE);
    char msg_finalize[128];
    snprintf(msg_finalize, sizeof(msg_finalize), "%s:%lu:1:@:%s\n", MSG_JOIN_FINALIZE, job->transaction_id, nonce_hex_finalize);
    connection_pool_send(job->new_node_ip, msg_finalize);

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
            job->commit_majority_ms = 0;
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
    // A heal is committed at once as well: heals run one at a time, so the next one sees the updated
    // assignments, and the staged data cannot be cleared first by the cleanup order sent below, which
    // also reaches this device when it is one of the new Verifiers.
    db_join_commit(job->transaction_id);

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
        // The new member receives the list of excluded devices, which every member keeps.
        raft_send_blacklist_to(job->new_node_ip);

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
            char excluded_candidate_ip[INET_ADDRSTRLEN] = {0};

            TAKE_JOIN_MUTEX(__FUNCTION__);
            if (pending_join.in_use && transaction_id == pending_join.transaction_id && is_ip_in_verifier_list(&pending_join, from_ip)) {
                // Each Verifier is counted once, so that a single device cannot stand in for the others.
                int verifier_index = -1;
                for (int i = 0; i < pending_join.verifier_count && i < MAX_VERIFIERS; i++) {
                    if (strcmp(pending_join.verifier_ips[i], from_ip) == 0) {
                        verifier_index = i;
                        break;
                    }
                }
                if (verifier_index < 0 || (pending_join.reported_verifiers_mask & (1u << verifier_index))) {
                    ESP_LOGW(TAG, "[JoinID: %lu] Duplicate %s from %s ignored.", transaction_id, MSG_CHL_RESULT, from_ip);
                    GIVE_JOIN_MUTEX(__FUNCTION__);
                    goto cleanup;
                }
                pending_join.reported_verifiers_mask |= (1u << verifier_index);

                pending_join.received_verifier_results++;
                int correct = atoi(correct_str);
                int total = atoi(total_str);
                // A negative count means that the candidate returned a proof different from the reference.
                if (correct < 0 && pending_join.type == JOIN_TYPE_NEW_NODE) {
                    pending_join.wrong_proof_results++;
                }

                if (correct != total) {
                    ESP_LOGE(TAG, "[JoinID: %lu] Verifier %s reported failure (%d/%d).", transaction_id, from_ip, correct, total);
                    pending_join.failed_verifier_results++;
                } else {
                    ESP_LOGI(TAG, "[JoinID: %lu] Verifier %s reported success (%d/%d).", transaction_id, from_ip, correct, total);
                }

                // One Verifier that does not confirm is enough to refuse the candidate. Excluding it for good
                // takes the majority of its Verifiers, so that a single Verifier cannot ban a device.
                int exclusion_quorum = VERIFIER_QUORUM(pending_join.expected_verifier_results);
                if (exclusion_quorum < MIN_VERIFIERS_TO_EXCLUDE) exclusion_quorum = MIN_VERIFIERS_TO_EXCLUDE;
                const bool all_reported = pending_join.received_verifier_results >= pending_join.expected_verifier_results;
                const bool exclude = pending_join.wrong_proof_results >= exclusion_quorum;

                if (exclude) {
                    strncpy(excluded_candidate_ip, pending_join.new_node_ip, INET_ADDRSTRLEN - 1);
                }

                if (pending_join.failed_verifier_results > 0) {
                    if (exclude || all_reported || pending_join.wrong_proof_results == 0) {
                        ESP_LOGW(TAG, "[JoinID: %lu] A verifier failed. Rolling back.", transaction_id);
                        do_rollback = true;
                    } else {
                        // The join is already refused; the other Verifiers are awaited to decide on the exclusion.
                        ESP_LOGW(TAG, "[JoinID: %lu] Wrong proof reported by %d verifier(s). Waiting for the others (%d/%d).", transaction_id,
                                 pending_join.wrong_proof_results, pending_join.received_verifier_results, pending_join.expected_verifier_results);
                    }
                } else if (all_reported) {
                    ESP_LOGI(TAG, "[JoinID: %lu] All %d verifiers reported success. Finalizing join.", transaction_id, pending_join.expected_verifier_results);
                    do_finalize = true;
                } else {
                    ESP_LOGI(TAG, "[JoinID: %lu] Received %d/%d verifier results.", transaction_id, pending_join.received_verifier_results, pending_join.expected_verifier_results);
                }
                handled = true;
            }
            GIVE_JOIN_MUTEX(__FUNCTION__);

            if (excluded_candidate_ip[0] != '\0') {
                char failed_mac[MAC_ADDR_STR_LEN];
                if (discovery_get_mac_for_ip(excluded_candidate_ip, failed_mac, sizeof(failed_mac))) {
                    ESP_LOGE(TAG, "[JoinID: %lu] The majority of the verifiers reported a wrong proof. Excluding %s.", transaction_id, excluded_candidate_ip);
                    raft_state_blacklist_mac(failed_mac);
                    raft_broadcast_blacklist_entry(failed_mac);
                }
            }

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
    } else if (strcmp(command, MSG_BROKER_REQ) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *prover_ip = strtok_r(NULL, ":", &saveptr);
            char *verifier_ip = strtok_r(NULL, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);
            if (!transaction_id_str || !prover_ip || !verifier_ip || !nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGE(TAG, "Malformed %s from %s", MSG_BROKER_REQ, from_ip);
                goto cleanup;
            }

            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);
            if (!auth_puf_broker_enrollment(transaction_id, prover_ip, verifier_ip)) {
                ESP_LOGE(TAG, "[JoinID: %lu] Could not deliver the enrollment key for %s and %s.", transaction_id, prover_ip, verifier_ip);
            }
        }
    } else if (strcmp(command, MSG_REQ_CHL_GEN) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *transaction_id_str = strtok_r(payload, ":", &saveptr);
            char *target_ip = strtok_r(NULL, ":", &saveptr);
            char *num_challenges_str = strtok_r(NULL, ":", &saveptr);
            char *challenges_list_str = strtok_r(NULL, ":", &saveptr);
            char *broker_ip = strtok_r(NULL, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);

            if (!transaction_id_str || !target_ip || !num_challenges_str || !challenges_list_str || !broker_ip || !nonce || !nonce_is_valid_and_store(nonce)) {
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

                // The response is that of the Prover, which arrives with JOIN_RESPONSE.
                snprintf(response, sizeof(response), "%s", DB_PENDING_RESPONSE);
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
            // When an intermediary gives the two parties a key, the responses must come back encrypted.
            bool secure_enrollment = strcmp(broker_ip, ENROLL_NO_BROKER) != 0;
            const char secure_marker[2] = {secure_enrollment ? ENROLL_SECURE_MARKER : '\0', '\0'};
            if (secure_enrollment) {
                expect_secure_enrollment(transaction_id, target_ip);
            }

            int msg_size_prover = snprintf(NULL, 0, "%s:%s:%s%s:%s\n", MSG_JOIN_CHL, transaction_id_str, secure_marker, batch_chl_str, nonce_hex_batch_chl);
            if (msg_size_prover > 0) {
                char *msg_to_prover = malloc(msg_size_prover + 1);
                if (msg_to_prover && batch_chl_str) {
                    snprintf(msg_to_prover, msg_size_prover + 1, "%s:%s:%s%s:%s\n", MSG_JOIN_CHL, transaction_id_str, secure_marker, batch_chl_str, nonce_hex_batch_chl);
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
            bool secure_enrollment = json_payload[0] == ENROLL_SECURE_MARKER;
            if (secure_enrollment) {
                json_payload++;
            }
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
                    remember_pending_challenge(from_ip, challenge);
                    cJSON *resp_item = cJSON_CreateObject();
                    cJSON_AddStringToObject(resp_item, "c", challenge);
                    cJSON_AddStringToObject(resp_item, "r", response);
                    cJSON_AddItemToArray(resp_root, resp_item);
                }
                char *resp_json_str = cJSON_PrintUnformatted(resp_root);

                if (secure_enrollment && resp_json_str) {
                    // The responses leave the device only under the key received from the intermediary.
                    uint32_t secure_tid = strtoul(transaction_id_str, NULL, 10);
                    uint8_t enroll_key[AUTH_KEY_SIZE];
                    char *sealed_str = NULL;
                    if (auth_puf_enroll_key_wait(secure_tid, from_ip, enroll_key, ENROLL_KEY_WAIT_MS)) {
                        size_t sealed_size = strlen(ENROLL_SEALED_PREFIX) + (strlen(resp_json_str) + 28) * 2 + 1;
                        sealed_str = malloc(sealed_size);
                        if (sealed_str) {
                            strcpy(sealed_str, ENROLL_SEALED_PREFIX);
                            if (!auth_puf_seal(enroll_key, transaction_id_str, (const uint8_t *)resp_json_str, strlen(resp_json_str),
                                               sealed_str + strlen(ENROLL_SEALED_PREFIX), sealed_size - strlen(ENROLL_SEALED_PREFIX))) {
                                free(sealed_str);
                                sealed_str = NULL;
                            }
                        }
                        auth_puf_enroll_key_drop(secure_tid, from_ip);
                    } else {
                        ESP_LOGE(TAG, "[JoinID: %s] No enrollment key received for verifier %s. Responses are not sent.", transaction_id_str, from_ip);
                    }
                    memset(enroll_key, 0, sizeof(enroll_key));
                    free(resp_json_str);
                    resp_json_str = sealed_str;
                }
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

        // Responses of a protected enrollment are accepted only if they arrive encrypted.
        char *opened_payload = NULL;
        bool must_be_sealed = take_secure_enrollment(transaction_id, from_ip);
        bool is_sealed = strncmp(json_payload, ENROLL_SEALED_PREFIX, strlen(ENROLL_SEALED_PREFIX)) == 0;
        if (must_be_sealed || is_sealed) {
            uint8_t enroll_key[AUTH_KEY_SIZE];
            const char *sealed_hex = json_payload + strlen(ENROLL_SEALED_PREFIX);
            if (is_sealed && auth_puf_enroll_key_wait(transaction_id, from_ip, enroll_key, ENROLL_KEY_WAIT_MS)) {
                size_t opened_size = strlen(sealed_hex) / 2 + 1;
                opened_payload = calloc(1, opened_size);
                if (opened_payload && auth_puf_open(enroll_key, transaction_id_str, sealed_hex, (uint8_t *)opened_payload, opened_size - 1) < 0) {
                    free(opened_payload);
                    opened_payload = NULL;
                }
                auth_puf_enroll_key_drop(transaction_id, from_ip);
            }
            memset(enroll_key, 0, sizeof(enroll_key));
            if (!opened_payload) {
                ESP_LOGE(TAG, "[JoinID: %s] Responses from %s are not protected as required. Rejected.", transaction_id_str, from_ip);
            }
            json_payload = opened_payload ? opened_payload : "";
        }

        cJSON *root = cJSON_Parse(json_payload);
        if (!root || !cJSON_IsArray(root)) {
            ESP_LOGE(TAG, "Failed to parse response JSON array from %s.", from_ip);
        } else {
            int correct_count = 0;
            int total_count = 0;
            CRPNode enrolled_crp = {0};
            cJSON *item;
            cJSON_ArrayForEach(item, root) {
                total_count++;
                char *challenge = cJSON_GetObjectItem(item, "c")->valuestring;
                char *response = cJSON_GetObjectItem(item, "r")->valuestring;
                CRPNode *expected_crp = db_join_tmp_get_crp_by_challenge(transaction_id, challenge);
                if (expected_crp) {
                    strncpy(enrolled_crp.challenge, challenge, sizeof(enrolled_crp.challenge) - 1);
                    strncpy(enrolled_crp.response, response, sizeof(enrolled_crp.response) - 1);
                    strncpy(enrolled_crp.target_ip, from_ip, sizeof(enrolled_crp.target_ip) - 1);                    
                    ESP_LOGI("DEBUG_CMP", "Enrolling CRP for challenge: %s", challenge);
                    ESP_LOGI("DEBUG_CMP", "  - Received Response: '%s'", response);

                    db_join_tmp_update_crp_response(transaction_id, challenge, response);
                    correct_count++;
                    free(expected_crp);
                } else {
                    ESP_LOGE("DEBUG_CMP", "Challenge '%s' not found in temporary DB!", challenge);
                }
            }
            // The device is attested with a CRP it has just enrolled, so that the attestation is bound
            // to its PUF. A device that fails is reported as a failed enrollment.
            if (total_count == 0) {
                total_count = 1;
            } else if (correct_count == total_count && strcmp(from_ip, my_ip) != 0) {
                hatt_result_t outcome = hatt_verifier_attest(from_ip, &enrolled_crp);
                if (outcome == HATT_FAILED) {
                    ESP_LOGE(TAG, "[JoinID: %s] Device %s failed the attestation bound to its enrolled CRP.", transaction_id_str, from_ip);
                    // A negative count tells the Coordinator that the attestation, not the enrollment, failed.
                    correct_count = -1;
                } else if (outcome == HATT_NO_ANSWER) {
                    ESP_LOGE(TAG, "[JoinID: %s] Device %s did not complete the attestation bound to its enrolled CRP.", transaction_id_str, from_ip);
                    correct_count = 0;
                }
            }
            memset(&enrolled_crp, 0, sizeof(enrolled_crp));

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
        if (opened_payload)
            free(opened_payload);
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
    } else if (strcmp(command, MSG_NET_STATE) == 0) {
        if (is_from_leader) {
            char *saveptr;
            char *tid_str = strtok_r(payload, ":", &saveptr);
            char *part_str = strtok_r(NULL, ":", &saveptr);
            char *parts_str = strtok_r(NULL, ":", &saveptr);
            char *nonce = strtok_r(NULL, ":", &saveptr);
            char *data = strtok_r(NULL, "", &saveptr);
            if (!tid_str || !part_str || !parts_str || !nonce || !data || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Malformed or replayed %s from %s", command, from_ip);
                goto cleanup;
            }
            net_state_add(strtoul(tid_str, NULL, 10), atoi(part_str), atoi(parts_str), data);
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
                // The network state arrived before, in NET_STATE parts: "<members JSON>|<compact challenges>".
                if (strncmp(json_start, "@:", 2) != 0) {
                    ESP_LOGE(TAG, "Malformed %s: network state marker not found.", command);
                    goto cleanup;
                }
                char *nonce = json_start + 2;
                if (!nonce_is_valid_and_store(nonce)) {
                    ESP_LOGW(TAG, "Invalid or replayed nonce for successful %s from %s", MSG_JOIN_FINALIZE, from_ip);
                    xSemaphoreGive(join_result_semaphore);
                    goto cleanup;
                }
                uint32_t finalize_tid = strtoul(transaction_id_str, NULL, 10);
                char *separator = net_state_complete(finalize_tid) ? strchr(net_state.buf, '|') : NULL;
                if (!separator) {
                    ESP_LOGE(TAG, "[JoinID: %lu] The network state was not received completely.", finalize_tid);
                    xSemaphoreGive(join_result_semaphore);
                    goto cleanup;
                }
                *separator = '\0';
                char *nodes_json_str = net_state.buf;

                ESP_LOGI(TAG, "Join successful. Importing network state.");
                db_import_nodes_json(nodes_json_str);
                db_import_state_compact(separator + 1);

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
                    note_commit_majority(job);

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
                note_commit_majority(&pending_join);
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
            char *target_ip = strtok_r(NULL, ":", &saveptr);
            char *nonce = strtok_r(NULL, "", &saveptr);

            if (!transaction_id_str || !target_ip || !nonce || !nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "Invalid or replayed nonce for %s from %s", command, from_ip);
                goto cleanup;
            }

            uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);

            ESP_LOGW(TAG, "[JoinID: %lu] Received join abort command from leader.", transaction_id);
            db_join_tmp_clear_by_tid(transaction_id);
            // Only the candidate, added to the pool for the enrollment, is dropped: the connection to the
            // Coordinator, and to a candidate that is already a Raft peer (a heal), must stay open.
            if (!raft_state_is_peer(target_ip)) {
                connection_pool_remove_peer(target_ip);
            }
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

    // The devices that joined first received fewer Verifiers, because the network was still small:
    // every device is brought to ceil(rho N) Verifiers before the bootstrap is complete.
    if (!auth_remove_heal_network()) {
        ESP_LOGE(TAG, "Bootstrap: the final heal did not complete for every device.");
    }

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

bool auth_join_operation_in_progress(void) {
    bool busy = false;
    TickType_t now = xTaskGetTickCount();
    taskENTER_CRITICAL(&pending_enrollment_spinlock);
    for (int i = 0; i < MAX_PENDING_ENROLLMENTS && !busy; i++) {
        busy = secure_enrollments[i].in_use && (now - secure_enrollments[i].created) * portTICK_PERIOD_MS <= PENDING_ENROLLMENT_TTL_MS;
    }
    taskEXIT_CRITICAL(&pending_enrollment_spinlock);
    if (busy) return true;

    if (join_mutex) {
        TAKE_JOIN_MUTEX(__FUNCTION__);
        busy = pending_join.in_use;
        GIVE_JOIN_MUTEX(__FUNCTION__);
    }
    if (!busy && heal_pool_mutex) {
        xSemaphoreTake(heal_pool_mutex, portMAX_DELAY);
        for (int i = 0; i < MAX_PARALLEL_HEALS && !busy; i++) busy = pending_heal_jobs[i].in_use;
        xSemaphoreGive(heal_pool_mutex);
    }
    return busy;
}
