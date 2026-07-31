/* =============================
 * File: auth_remove.c
 * Description: Implements the self-healing node removal logic.
 * ============================= */

#include "auth_remove.h"
#include "connection_pool.h"
#include "raft_state.h"
#include "raft.h"
#include "integrity_verification.h"
#include "auth_db.h"
#include "utility.h"
#include "auth_join.h" 
#include "nonce_manager.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

static const char *TAG = "AUTH_REMOVE";

static RemovalProcess current_removal;
static SemaphoreHandle_t removal_mutex = NULL;

static portMUX_TYPE remove_init_spinlock = portMUX_INITIALIZER_UNLOCKED;

static TaskHandle_t remove_manager_task_handle = NULL;

QueueHandle_t remove_request_queue = NULL;
SemaphoreHandle_t remove_result_semaphore = NULL;
bool remove_result_success = false;

#define TAKE_REMOVE_MUTEX(func_name) do { \
    ESP_LOGD("REMOVE_MUTEX", "Attempting to take lock in %s", func_name); \
    xSemaphoreTake(removal_mutex, portMAX_DELAY); \
    ESP_LOGD("REMOVE_MUTEX", ">> Lock TAKEN in %s", func_name); \
} while(0)

#define GIVE_REMOVE_MUTEX(func_name) do { \
    ESP_LOGD("REMOVE_MUTEX", "<< Lock GIVEN in %s", func_name); \
    xSemaphoreGive(removal_mutex); \
} while(0)

static void remove_manager_task(void *pvParameters);

/**
 * @brief Initializes the synchronization primitives for the removal module.
 * @details This function is called lazily and must be called from within a
 * mutex-protected block to prevent race conditions during initialization.
 */
void auth_remove_init(void) {
    ESP_LOGI(TAG, "Initializing Node REMOVE Module...");
    if (removal_mutex == NULL || remove_request_queue == NULL || remove_result_semaphore == NULL) {
        taskENTER_CRITICAL(&remove_init_spinlock);
        if (removal_mutex == NULL) {
            removal_mutex = xSemaphoreCreateMutex();
        }

        if (remove_request_queue == NULL) {
            remove_request_queue = xQueueCreate(MAX_PENDING_REMOVALS, sizeof(char[INET_ADDRSTRLEN]));
        }
        
        if (remove_result_semaphore == NULL) {
           remove_result_semaphore = xSemaphoreCreateBinary();
        }
        taskEXIT_CRITICAL(&remove_init_spinlock);
  
        xTaskCreate(remove_manager_task, "remove_manager", 4096, NULL, 6, &remove_manager_task_handle);
    }    

    if (removal_mutex == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create REMOVE mutex!");
        return;
    }

    if (remove_result_semaphore == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create RESULT mutex!");
        return;
    }

    ESP_LOGD(TAG, "Attempting to take REMOVE mutex for initialization...");
    if (xSemaphoreTake(removal_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "FATAL: Failed to create JOIN mutex!");
        return;
    } else {
        xSemaphoreGive(removal_mutex);
    }
}

/**
 * @brief (Leader-only) Handles an incoming acknowledgment for a node removal.
 * @details This function is called by the main message handler when an ACK is received.
 * It safely increments the ACK counter and signals the leader task if a quorum is reached.
 * @param from_ip The IP of the node sending the ACK.
 * @param removed_node_ip The IP of the node being removed, for validation.
 * @param transaction_id The ID of the removal transaction being ACKed.
 */
static void remove_handle_ack(const char* from_ip, const char* removed_node_ip, uint32_t transaction_id) {
    TAKE_REMOVE_MUTEX(__FUNCTION__);
    if (current_removal.is_active && 
        current_removal.transaction_id == transaction_id &&
        strcmp(current_removal.removed_node_ip, removed_node_ip) == 0) {
        
        current_removal.removal_ack_count++;
        ESP_LOGI(TAG, "[RemoveID: %lu] REMOVED_ACK received from %s. Total ACKs now: %d.", transaction_id, from_ip, current_removal.removal_ack_count);
    }
    GIVE_REMOVE_MUTEX(__FUNCTION__);
}

/**
 * @brief A high-priority task dedicated to cleanly decommissioning the node.
 * @details This task performs a full software shutdown by stopping all active processes
 * (Raft logic, timers, managers), wiping the database, and finally shutting down
 * the network layer. Its high priority ensures it preempts other application tasks,
 * preventing race conditions during the shutdown sequence.
 */
static void decommission_task(void *pvParameters) {
    ESP_LOGW(TAG, "Decommission task started. Applying definitive shutdown sequence.");
    raft_shutdown_timers_and_tasks();

    int peer_count = 0;
    char** peer_list = raft_state_get_peers_copy(&peer_count);

    if (peer_list) {
        ESP_LOGI(TAG, "Closing connections to %d peers...", peer_count);
        for (int i = 0; i < peer_count; i++) {
            connection_pool_remove_peer(peer_list[i]);
            free(peer_list[i]);
        }
        free(peer_list);
    }
    ESP_LOGI(TAG, "Network layer de-initialized successfully.");

    ESP_LOGI(TAG, "Wiping all authentication database entries.");
    db_wipe_all_auth_data();
    raft_state_deinit();

    ESP_LOGW(TAG, "Node fully decommissioned. Deleting self.");
    vTaskDelete(NULL);
}

/**
 * @brief Handles incoming node removal commands.
 * @details When a follower receives a removal command, it verifies the leader's integrity
 * before executing the command and sending an acknowledgement.
 * @param message The raw, null-terminated message string received from a peer.
 * @param from_ip The IP address of the node that sent the message.
 */
void remove_handle_message(char *message, const char *from_ip) {
    char* saveptr;
    char* command = strtok_r(message, ":", &saveptr);
    if (!command) return;

    char leader_ip[INET_ADDRSTRLEN];
    char leader_mac[MAC_ADDR_STR_LEN];
    bool has_leader = raft_state_get_leader_info(leader_ip, sizeof(leader_ip), leader_mac, sizeof(leader_mac));

    if (strcmp(command, MSG_NODE_REMOVED) == 0) {
        if (!has_leader || strcmp(from_ip, leader_ip) != 0) return;

        char* transaction_id_str = strtok_r(NULL, ":", &saveptr);
        char* ip_to_remove = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!transaction_id_str || !ip_to_remove || !nonce || !nonce_is_valid_and_store(nonce)) return;

        ESP_LOGW(TAG, "Received notification to remove peer %s. Updating local state.", ip_to_remove);
        db_remove_node(ip_to_remove);
        raft_state_remove_peer(ip_to_remove);

        ESP_LOGI(TAG, "Cleaning up CNode and CRP tables for removed node %s.", ip_to_remove);
        db_remove_cnode_for_node(ip_to_remove);
        db_remove_crp_for_node(ip_to_remove);
        
        char ack_msg[128];
        snprintf(ack_msg, sizeof(ack_msg), "%s:%s:%s:%s\n", MSG_NODE_REMOVED_ACK, transaction_id_str, ip_to_remove, nonce);
        connection_pool_send(leader_ip, ack_msg);
    } else if (strcmp(command, MSG_NODE_REMOVED_ACK) == 0) {
        char* transaction_id_str = strtok_r(NULL, ":", &saveptr);
        char* removed_node_ip = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);

        if (!transaction_id_str || !removed_node_ip || !nonce || !nonce_is_valid_and_store(nonce)) {
            ESP_LOGW(TAG, "Malformed or replayed NODE_REMOVED_ACK from %s", from_ip);
            return;
        }

        uint32_t transaction_id = strtoul(transaction_id_str, NULL, 10);
        remove_handle_ack(from_ip, removed_node_ip, transaction_id);
    } else if (strcmp(command, MSG_NODE_REMOVE_ABORT) == 0) {
        if (!has_leader || strcmp(from_ip, leader_ip) != 0) {
            ESP_LOGW(TAG, "Rejected command '%s' from non-leader IP %s", command, from_ip);
            return;
        }

        char* transaction_id_str = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);

        if (!transaction_id_str || !nonce || !nonce_is_valid_and_store(nonce)) {
            ESP_LOGW(TAG, "Malformed or replayed NODE_REMOVE_ABORT from %s", from_ip);
            return;
        }

        ESP_LOGW(TAG, "Received ABORT for removal transaction %s. No action needed.", transaction_id_str ? transaction_id_str : "N/A");
    } else if (strcmp(command, MSG_PREPARE_FOR_REMOVAL) == 0) {
        if (!has_leader || strcmp(from_ip, leader_ip) != 0) return;

        char* transaction_id_str = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!transaction_id_str || !nonce || !nonce_is_valid_and_store(nonce)) return;

        ESP_LOGW(TAG, "Received PREPARE_FOR_REMOVAL. Spawning high-priority decommission task.");
        xTaskCreate(decommission_task, "decommission_task", 4096, NULL, configMAX_PRIORITIES - 1, NULL);
    } else if (strcmp(command, MSG_PAUSE_HB_ACK) == 0) {
        char* term_str = strtok_r(saveptr, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!term_str || !nonce || !nonce_is_valid_and_store(nonce)) {
            ESP_LOGW(TAG, "Malformed or replayed PAUSE_ACK from %s.", from_ip);
            return;
        }

        uint32_t rpc_term = strtoul(term_str, NULL, 10);

        TAKE_REMOVE_MUTEX(__FUNCTION__);
        if (current_removal.is_active && rpc_term == raft_state_get_current_term()) {
            current_removal.maintenance_ack_count++;
        } else {
            ESP_LOGW(TAG, "PAUSE_TIMERS_ACK command from node %s ignored due to term mismatch. MyTerm: %lu, RpcTerm: %lu",
                        from_ip, raft_state_get_current_term(), rpc_term);
        }
        GIVE_REMOVE_MUTEX(__FUNCTION__);
    }
}

/**
 * @brief (Leader-only) Triggers the removal of a node from the cluster.
 * @details This function, callable only on the leader, initiates the two-phase removal process.
 * It first broadcasts the removal command and waits for a quorum of acknowledgements.
 * If successful, it proceeds to the self-healing phase. On failure, it times out.
 * @param ip_to_remove The IP address of the node to be removed from the cluster.
 */
void trigger_node_removal(const char* ip_to_remove) {
    RemovalProcess process_copy;
    bool all_followers_acked = false;

    TAKE_REMOVE_MUTEX(__FUNCTION__);
    if (current_removal.is_active) {
        ESP_LOGE(TAG, "Cannot trigger removal for %s, another removal for %s is in progress.", ip_to_remove, current_removal.removed_node_ip);
        GIVE_REMOVE_MUTEX(__FUNCTION__);
        remove_result_success = false;
        xSemaphoreGive(remove_result_semaphore);
        return;
    }

    memset(&current_removal, 0, sizeof(RemovalProcess));
    current_removal.is_active = true;
    current_removal.transaction_id = xTaskGetTickCount();
    strncpy(current_removal.removed_node_ip, ip_to_remove, INET_ADDRSTRLEN - 1);
    process_copy = current_removal;
    GIVE_REMOVE_MUTEX(__FUNCTION__);

    remove_result_success = false;

    char *event_msg = malloc(MAX_MESSAGE_SIZE);
    if (event_msg) {
        snprintf(event_msg, MAX_MESSAGE_SIZE, "REMOVE_START:%s", ip_to_remove);
        send_monitoring_tcp_event(event_msg);
        free(event_msg);
    }
    
    ESP_LOGI(TAG, "[RemoveID: %lu] [Master] Initiating removal of node %s", process_copy.transaction_id, ip_to_remove);

    int follower_count = db_get_follower_count();
    char pause_msg[64];
    uint32_t current_term = raft_state_get_current_term();
    snprintf(pause_msg, sizeof(pause_msg), "%s %lu\n", MSG_PAUSE_HB_TIMERS, current_term);

    TAKE_REMOVE_MUTEX(__FUNCTION__);
    current_removal.maintenance_ack_count = 0;
    GIVE_REMOVE_MUTEX(__FUNCTION__);

    ESP_LOGI(TAG, "Broadcasting PAUSE command to %d followers.", follower_count);
    for (int i = 0; i < follower_count; i++) {
        char follower_ip[INET_ADDRSTRLEN];
        if (db_get_follower_ip(i, follower_ip, sizeof(follower_ip))) {
            char nonce_hex[NONCE_HEX_SIZE];
            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

            char pause_msg[128];
            snprintf(pause_msg, sizeof(pause_msg), "%s:%lu:%s\n", MSG_PAUSE_HB_TIMERS, current_term, nonce_hex);
            
            connection_pool_send(follower_ip, pause_msg);
        }
    }

    int expected_acks = follower_count;
    if (expected_acks > 0) {
        ESP_LOGI(TAG, "Waiting for %d PAUSE_ACKs by polling shared state...", expected_acks);
        uint32_t start_wait_time = xTaskGetTickCount();
        bool timed_out = true;
        int received_acks = 0;

        while ((xTaskGetTickCount() - start_wait_time) * portTICK_PERIOD_MS < SINGLE_ACK_TIMEOUT_MS) {
            TAKE_REMOVE_MUTEX(__FUNCTION__);
            received_acks = current_removal.maintenance_ack_count;
            GIVE_REMOVE_MUTEX(__FUNCTION__);

           if (received_acks >= expected_acks) {
                timed_out = false;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        if (timed_out) {
            ESP_LOGE(TAG, "Timeout waiting for PAUSE_ACKs. Received %d/%d. Aborting removal.", received_acks, expected_acks);
            goto cleanup; 
        }
    }
    ESP_LOGI(TAG, "All followers confirmed PAUSE. Proceeding with removal.");

    ESP_LOGW(TAG, "Sending FIRE-AND-FORGET PREPARE_FOR_REMOVAL to %s...", ip_to_remove);
    char prepare_msg[128];
    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
    snprintf(prepare_msg, sizeof(prepare_msg), "%s:%lu:%s\n", MSG_PREPARE_FOR_REMOVAL, process_copy.transaction_id, nonce_hex);

    connection_pool_send(ip_to_remove, prepare_msg);

    vTaskDelay(pdMS_TO_TICKS(200)); 
    ESP_LOGI(TAG, "Assuming node %s is now passive. Proceeding with removal.", ip_to_remove);

    db_remove_node(ip_to_remove);
    raft_state_remove_peer(ip_to_remove);

    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
    int bcast_msg_size = snprintf(NULL, 0, "%s:%lu:%s:%s\n", MSG_NODE_REMOVED, current_removal.transaction_id, ip_to_remove, nonce_hex);
    if (bcast_msg_size > 0) {
        char* msg = malloc(bcast_msg_size + 1);
        if (msg) {
            snprintf(msg, bcast_msg_size + 1, "%s:%lu:%s:%s\n", MSG_NODE_REMOVED, current_removal.transaction_id, ip_to_remove, nonce_hex);
            connection_pool_send(ip_to_remove, msg);
            free(msg);
        }
    }

    follower_count = db_get_follower_count();
    all_followers_acked = true;
    if (follower_count > 0) {
        ESP_LOGI(TAG, "[RemoveID: %lu] Notifying %d followers and waiting for consensus.", process_copy.transaction_id, follower_count);

        for (int i = 0; i < follower_count; i++) {
            char follower_ip[INET_ADDRSTRLEN];
            if (db_get_follower_ip(i, follower_ip, sizeof(follower_ip))) {
                char nonce_hex[NONCE_HEX_SIZE];
                uint8_t nonce[NONCE_SIZE];
                generate_nonce(nonce, NONCE_SIZE);
                bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
                
                char bcast_msg[128];
                snprintf(bcast_msg, sizeof(bcast_msg), "%s:%lu:%s:%s\n", MSG_NODE_REMOVED, process_copy.transaction_id, ip_to_remove, nonce_hex);
                
                connection_pool_send(follower_ip, bcast_msg);
            }
        }

        uint32_t start_wait_time = xTaskGetTickCount();
        while ((xTaskGetTickCount() - start_wait_time) * portTICK_PERIOD_MS < SINGLE_ACK_TIMEOUT_MS) {
            TAKE_REMOVE_MUTEX(__FUNCTION__);
            int current_acks = current_removal.removal_ack_count;
            GIVE_REMOVE_MUTEX(__FUNCTION__);

            if (current_acks >= follower_count) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(200));
        }

        TAKE_REMOVE_MUTEX(__FUNCTION__);
        if (current_removal.removal_ack_count < follower_count) {
            ESP_LOGE(TAG, "Timed out waiting for REMOVED_ACKs. Got %d/%d.", current_removal.removal_ack_count, follower_count);
            all_followers_acked = false;
        }
        GIVE_REMOVE_MUTEX(__FUNCTION__);
    } else {
        ESP_LOGI(TAG, "[RemoveID: %lu] No other followers to notify.", current_removal.transaction_id);
    }

    if (all_followers_acked) {
        ESP_LOGI(TAG, "[RemoveID: %lu] Cleaning up CNode and CRP tables for removed node %s.", process_copy.transaction_id, ip_to_remove);
        db_remove_cnode_for_node(ip_to_remove);
        db_remove_crp_for_node(ip_to_remove);

        ESP_LOGI(TAG, "Broadcasting RESUME command to remaining followers BEFORE healing.");
        int follower_count_after_removal_resume = db_get_follower_count();
        for (int i = 0; i < follower_count_after_removal_resume; i++) {
            char follower_ip[INET_ADDRSTRLEN];
            if (db_get_follower_ip(i, follower_ip, sizeof(follower_ip))) {
                char nonce_hex_resume[NONCE_HEX_SIZE];
                uint8_t nonce_resume[NONCE_SIZE];
                generate_nonce(nonce_resume, NONCE_SIZE);
                bytes_to_hex(nonce_resume, nonce_hex_resume, NONCE_SIZE);
                
                char resume_msg[128];
                snprintf(resume_msg, sizeof(resume_msg), "%s:%lu:%s\n", MSG_RESUME_HB_TIMERS, raft_state_get_current_term(), nonce_hex_resume);
                
                connection_pool_send(follower_ip, resume_msg);
            }
        }

        ESP_LOGI(TAG, "[RemoveID: %lu] Node removal phase complete. Notifying monitor.", process_copy.transaction_id);
        char *event_msg_remove_complete = malloc(MAX_MESSAGE_SIZE);
        if (event_msg_remove_complete) {
            snprintf(event_msg_remove_complete, MAX_MESSAGE_SIZE, "REMOVE_COMPLETE:%s", ip_to_remove);
            send_monitoring_tcp_event(event_msg_remove_complete);
            free(event_msg_remove_complete);
        }

        ESP_LOGI(TAG, "[RemoveID: %lu] Starting network healing phase.", process_copy.transaction_id);
        char *event_msg_heal_start = malloc(MAX_MESSAGE_SIZE);
        if (event_msg_heal_start) {
            snprintf(event_msg_heal_start, MAX_MESSAGE_SIZE, "HEALING_PHASE_START:%s", process_copy.removed_node_ip);
            send_monitoring_tcp_event(event_msg_heal_start);
            free(event_msg_heal_start);
        }
        
        int follower_count_after_removal = db_get_follower_count();
        int current_network_size = follower_count_after_removal + 1;
        int heal_tasks_queued = 0;

        if (current_network_size > 1) {
            int n_target = (int)ceil(current_network_size * VERIFIER_TARGET_PERCENTAGE);
            if (n_target == 0) n_target = 1;

            char (*all_nodes_ips)[INET_ADDRSTRLEN] = malloc(current_network_size * sizeof(char[INET_ADDRSTRLEN]));
            if (all_nodes_ips) {
                int node_idx = 0;
                char my_ip[INET_ADDRSTRLEN];
                raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
                strncpy(all_nodes_ips[node_idx++], my_ip, INET_ADDRSTRLEN);

                char** follower_ips_array = NULL;
                int num_followers = db_get_all_follower_ips(&follower_ips_array, follower_count_after_removal);
                for (int i = 0; i < num_followers; i++) {
                    strncpy(all_nodes_ips[node_idx++], follower_ips_array[i], INET_ADDRSTRLEN);
                    free(follower_ips_array[i]);
                }
                if (follower_ips_array) free(follower_ips_array);

                ESP_LOGI(TAG, "[HEAL] Spawning heal tasks...");

                ESP_LOGI(TAG, "[HEAL] Clearing counting semaphore 'caller_sync_sem'...");
                portENTER_CRITICAL(&parallel_job_failure_mux);
                parallel_job_failure_count = 0;
                portEXIT_CRITICAL(&parallel_job_failure_mux);
                while (xSemaphoreTake(caller_sync_sem, (TickType_t)0) == pdTRUE) {
                    ESP_LOGW(TAG, "[HEAL] Cleared one stray signal from caller_sync_sem.");
                }
                ESP_LOGI(TAG, "[HEAL] Semaphore cleared. Spawning tasks.");

                for (int i = 0; i < current_network_size; i++) {
                    char* node_ip_to_check = all_nodes_ips[i];
                    int verifier_count = db_get_verifier_count_for_node(node_ip_to_check);

                    if (verifier_count < n_target) {
                        int needed = n_target - verifier_count;
                        ESP_LOGW(TAG, "[HEAL] Node %s needs %d new verifiers. Starting synchronous heal.", node_ip_to_check, needed);

                        join_request_t heal_req = {.type = JOIN_TYPE_HEAL_NODE, .num_verifiers_to_add = needed};
                        strncpy(heal_req.target_ip, node_ip_to_check, INET_ADDRSTRLEN);

                        char heal_event_msg[64];
                        snprintf(heal_event_msg, sizeof(heal_event_msg), "HEAL_START:%s", node_ip_to_check);
                        send_monitoring_tcp_event(heal_event_msg);

                        auth_join_run_heal_job_async(heal_req);
                        heal_tasks_queued++;
                    }
                }

                free(all_nodes_ips);

                ESP_LOGI(TAG, "[HEAL] Spawned %d heal tasks. Waiting for all to complete.", heal_tasks_queued);
                for (int i = 0; i < heal_tasks_queued; i++) {
                    if (xSemaphoreTake(caller_sync_sem, pdMS_TO_TICKS(JOIN_PROCESS_TIMEOUT_MS)) == pdTRUE) {
                        ESP_LOGI(TAG, "[HEAL] Heal task %d/%d completed.", i + 1, heal_tasks_queued);
                    } else {
                        ESP_LOGE(TAG, "[HEAL] Timed out waiting for completion of heal task %d/%d. Aborting.", i + 1, heal_tasks_queued);
                        all_followers_acked = false;
                        break;
                    }
                }

                if(all_followers_acked) {
                    ESP_LOGI(TAG, "[HEAL] All %d heal tasks completed.", heal_tasks_queued);
                    ESP_LOGI(TAG, "[HEAL] Committing all pending leader-side data to main DB...");
                    db_join_commit_all_pending_heal();
                }
            } else {
                 ESP_LOGE(TAG, "Failed to allocate memory for node IP array during heal phase.");
                 all_followers_acked = false;
            }
        }

        char *event_msg_heal_complete = malloc(MAX_MESSAGE_SIZE);
        if (event_msg_heal_complete) {
            if (all_followers_acked) {
                ESP_LOGI(TAG, "[RemoveID: %lu] Network heal phase finished successfully.", process_copy.transaction_id);
                remove_result_success = true;
                snprintf(event_msg_heal_complete, MAX_MESSAGE_SIZE, "HEALING_PHASE_COMPLETE:%s", process_copy.removed_node_ip);
            } else {
                ESP_LOGE(TAG, "[RemoveID: %lu] Network heal phase failed.", process_copy.transaction_id);
                snprintf(event_msg_heal_complete, MAX_MESSAGE_SIZE, "HEALING_PHASE_FAILED:%s", process_copy.removed_node_ip);
            }

            send_monitoring_tcp_event(event_msg_heal_complete);
            free(event_msg_heal_complete);
        }
        
        if (all_followers_acked) {
             ESP_LOGI(TAG, "[RemoveID: %lu] Network heal phase finished successfully.", process_copy.transaction_id);
             remove_result_success = true;
        } else {
            ESP_LOGE(TAG, "[RemoveID: %lu] Network heal phase failed.", process_copy.transaction_id);
        }
    } else {
        ESP_LOGE(TAG, "[RemoveID: %lu] Removal process failed, not all followers acknowledged.", process_copy.transaction_id);
    }

cleanup:
    if (!all_followers_acked) {
        ESP_LOGI(TAG, "Broadcasting RESUME command to remaining followers after ABORT.");

        int follower_count_after_removal_resume = db_get_follower_count();
        for (int i = 0; i < follower_count_after_removal_resume; i++) {
            char follower_ip[INET_ADDRSTRLEN];
            if (db_get_follower_ip(i, follower_ip, sizeof(follower_ip))) {
                char nonce_hex_resume[NONCE_HEX_SIZE];
                uint8_t nonce_resume[NONCE_SIZE];
                generate_nonce(nonce_resume, NONCE_SIZE);
                bytes_to_hex(nonce_resume, nonce_hex_resume, NONCE_SIZE);
                
                char resume_msg[128];
                snprintf(resume_msg, sizeof(resume_msg), "%s:%lu:%s\n", MSG_RESUME_HB_TIMERS, raft_state_get_current_term(), nonce_hex_resume);
                
                connection_pool_send(follower_ip, resume_msg);
            }
        }
    }

    if (remove_result_success) {
         ESP_LOGI(TAG, "[RemoveID: %lu] Network heal phase finished successfully.", process_copy.transaction_id);
    }
    xSemaphoreGive(remove_result_semaphore);
    TAKE_REMOVE_MUTEX(__FUNCTION__);
    memset(&current_removal, 0, sizeof(RemovalProcess));
    GIVE_REMOVE_MUTEX(__FUNCTION__);
}

/**
 * @brief (Leader-only) A dedicated task to process node removal requests sequentially.
 * @details This task waits for removal requests on a queue. It processes one
 * request at a time, calling the main trigger_node_removal logic and waiting for
 * it to complete before fetching the next request. This ensures removals are
 * handled sequentially.
 */
static void remove_manager_task(void *pvParameters) {
    char ip_to_remove[INET_ADDRSTRLEN];
    ESP_LOGI(TAG, "Remove Manager task started, waiting for requests.");

    while (1) {
        if (xQueueReceive(remove_request_queue, &ip_to_remove, portMAX_DELAY) == pdTRUE) {
            ESP_LOGI(TAG, "Remove Manager: Dequeued request to remove node %s. Starting process.", ip_to_remove);
            
            trigger_node_removal(ip_to_remove);
            
            ESP_LOGI(TAG, "Remove Manager: Process for node %s finished. Awaiting next request.", ip_to_remove);
        }
    }
}