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
#include "auth_puf.h"
#include "hatt_protocol.h"
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

// (Verifier) Last removal this node confirmed. A removal order is executed only if it matches.
static uint32_t confirmed_removal_tid = 0;
static char confirmed_removal_ip[INET_ADDRSTRLEN] = {0};
static TickType_t confirmed_removal_tick = 0;

// Independent evidence that the target's own Verifiers back a removal. These are written and read only
// from the message worker task (remove_handle_message), so they need no lock. The tally records the
// distinct Verifiers of the target that announced their confirmation; the pending order is a removal
// order received from the Coordinator that is held until that evidence arrives (messages may reorder).
static struct {
    uint32_t tid;
    char target[INET_ADDRSTRLEN];
    char confirmers[MAX_VERIFIERS][INET_ADDRSTRLEN];
    int count;
} confirm_tally;
static struct {
    bool present;
    uint32_t tid;
    char target[INET_ADDRSTRLEN];
    char nonce[NONCE_HEX_SIZE];
    char leader_ip[INET_ADDRSTRLEN];
    TickType_t tick;
} pending_order;
static SemaphoreHandle_t removal_mutex = NULL;
// One pass of heals at a time: the end of the bootstrap and a removal can both start one.
static SemaphoreHandle_t heal_network_mutex = NULL;

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
        if (heal_network_mutex == NULL) {
            heal_network_mutex = xSemaphoreCreateMutex();
        }

        if (remove_request_queue == NULL) {
            remove_request_queue = xQueueCreate(MAX_PENDING_REMOVALS, sizeof(char[INET_ADDRSTRLEN]));
        }
        
        if (remove_result_semaphore == NULL) {
           remove_result_semaphore = xSemaphoreCreateBinary();
        }
        taskEXIT_CRITICAL(&remove_init_spinlock);
  
        xTaskCreate(remove_manager_task, "remove_manager", 6144, NULL, 6, &remove_manager_task_handle);
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
/**
 * @brief (Internal) Records an acknowledgement, counting each member once.
 * @return true if the acknowledgement is new and comes from a member.
 */
static bool record_ack_once(char acked_ips[][INET_ADDRSTRLEN], int acked_count, const char *from_ip) {
    if (acked_count >= MAX_REMOVAL_CHECK_REPLIES || !db_node_exists(from_ip)) return false;
    for (int i = 0; i < acked_count; i++) {
        if (strcmp(acked_ips[i], from_ip) == 0) return false;
    }
    strncpy(acked_ips[acked_count], from_ip, INET_ADDRSTRLEN - 1);
    acked_ips[acked_count][INET_ADDRSTRLEN - 1] = '\0';
    return true;
}

/**
 * @brief (Internal) Waits for the acknowledgements of the other members.
 * @details The wait ends when all of them have answered. If some do not answer, e.g., because they
 * have crashed too, it ends shortly after the majority of the members, the Coordinator included,
 * has acknowledged, or at the timeout.
 * @param counter Counter of the acknowledgements, protected by the removal mutex.
 * @param expected Number of members asked.
 * @return true if at least the majority acknowledged.
 */
static bool wait_for_member_acks(const int *counter, int expected, uint32_t timeout_ms) {
    const int majority = (expected + 1) / 2;
    uint32_t start_tick = xTaskGetTickCount();
    uint32_t majority_tick = 0;
    bool majority_reached = false;
    int received = 0;

    while ((xTaskGetTickCount() - start_tick) * portTICK_PERIOD_MS < timeout_ms) {
        TAKE_REMOVE_MUTEX(__FUNCTION__);
        received = *counter;
        GIVE_REMOVE_MUTEX(__FUNCTION__);

        if (received >= expected) return true;
        if (received >= majority) {
            if (!majority_reached) {
                majority_reached = true;
                majority_tick = xTaskGetTickCount();
            } else if ((xTaskGetTickCount() - majority_tick) * portTICK_PERIOD_MS >= REMOVAL_ACK_GRACE_MS) {
                break;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (received < expected) {
        ESP_LOGW(TAG, "Received %d of %d acknowledgements (majority: %d).", received, expected, majority);
    }
    return received >= majority;
}

static void remove_handle_ack(const char* from_ip, const char* removed_node_ip, uint32_t transaction_id) {
    TAKE_REMOVE_MUTEX(__FUNCTION__);
    if (current_removal.is_active && 
        current_removal.transaction_id == transaction_id &&
        strcmp(current_removal.removed_node_ip, removed_node_ip) == 0 &&
        record_ack_once(current_removal.removal_acked_ips, current_removal.removal_ack_count, from_ip)) {
        
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
 * @brief (Internal) Tells whether a device is one of the Verifiers of another device.
 */
static bool is_verifier_of_device(const char *verifier_ip, const char *device_ip) {
    char (*verifiers)[INET_ADDRSTRLEN] = malloc(MAX_VERIFIERS * INET_ADDRSTRLEN);
    if (!verifiers) return false;

    bool found = false;
    int count = db_get_verifiers_for_node(device_ip, verifiers, MAX_VERIFIERS);
    for (int i = 0; i < count && !found; i++) {
        found = strcmp(verifiers[i], verifier_ip) == 0;
    }
    free(verifiers);
    return found;
}

bool remove_verifier_confirms(const char *ip_to_remove) {
    if (!auth_puf_is_verifier_of(ip_to_remove)) {
        return true;
    }

    int outcome = integrity_verification_check_prover(ip_to_remove, REMOVAL_CONFIRM_TIMEOUT_MS);
    if (outcome == HATT_NO_ANSWER) {
        ESP_LOGW(TAG, "Device %s did not pass the PUF challenge. Removal confirmed.", ip_to_remove);
        return true;
    }
    if (outcome != HATT_PASSED) {
        ESP_LOGW(TAG, "Device %s did not pass the attestation. Removal confirmed.", ip_to_remove);
        return true;
    }

    ESP_LOGE(TAG, "Device %s is alive and passed both checks. Removal REFUSED.", ip_to_remove);
    return false;
}

/**
 * @brief (Coordinator) Brings every device back to ceil(rho N) Verifiers, healing one Prover at a time.
 * @details Used after a removal and at the end of the bootstrap, when the devices that joined first
 * received fewer Verifiers because the network was still small.
 * @return true if every heal completed.
 */
static bool heal_network_unsafe(void) {
    bool heal_ok = true;
    int follower_count_after_removal = db_get_follower_count();
    int current_network_size = follower_count_after_removal + 1;
    int heal_tasks_queued = 0;

    if (current_network_size > 1) {
        int n_target = (int)ceil(current_network_size * VERIFIER_PERCENTAGE);
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

            ESP_LOGI(TAG, "[HEAL] Running heal jobs one at a time...");

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

                if (verifier_count < n_target && !auth_join_device_reachable(node_ip_to_check)) {
                    // A Prover that does not answer cannot take part in its own heal; its Verifiers report
                    // it as unreachable, and if it is still a member at the next pass it is healed then.
                    ESP_LOGW(TAG, "[HEAL] Node %s needs %d new verifiers but is not reachable. Skipping it.", node_ip_to_check, n_target - verifier_count);
                    continue;
                }
                if (verifier_count < n_target) {
                    int needed = n_target - verifier_count;
                    ESP_LOGW(TAG, "[HEAL] Node %s needs %d new verifiers. Starting synchronous heal.", node_ip_to_check, needed);

                    join_request_t heal_req = {.type = JOIN_TYPE_HEAL_NODE, .num_verifiers_to_add = needed};
                    strncpy(heal_req.target_ip, node_ip_to_check, INET_ADDRSTRLEN);

                    char heal_event_msg[64];
                    snprintf(heal_event_msg, sizeof(heal_event_msg), "HEAL_START:%s", node_ip_to_check);
                    send_monitoring_tcp_event(heal_event_msg);

                    // The Provers are healed one at a time: each heal attests and enrolls through several
                    // devices, and running them together would overload the network and the heap.
                    auth_join_run_heal_job_async(heal_req);
                    heal_tasks_queued++;
                    if (xSemaphoreTake(caller_sync_sem, pdMS_TO_TICKS(JOIN_PROCESS_TIMEOUT_MS)) == pdTRUE) {
                        ESP_LOGI(TAG, "[HEAL] Heal of %s completed (%d so far).", node_ip_to_check, heal_tasks_queued);
                    } else {
                        ESP_LOGE(TAG, "[HEAL] Timed out waiting for the heal of %s. Aborting.", node_ip_to_check);
                        heal_ok = false;
                        break;
                    }
                }
            }

            free(all_nodes_ips);
            ESP_LOGI(TAG, "[HEAL] %d heal jobs run.", heal_tasks_queued);

            if(heal_ok) {
                ESP_LOGI(TAG, "[HEAL] All %d heal tasks completed.", heal_tasks_queued);
                ESP_LOGI(TAG, "[HEAL] Committing all pending leader-side data to main DB...");
                db_join_commit_all_pending_heal();
            }
        } else {
             ESP_LOGE(TAG, "Failed to allocate memory for node IP array during heal phase.");
             heal_ok = false;
        }
    }
    return heal_ok;
}

bool auth_remove_heal_network(void) {
    // A pass started while another one runs waits for it and then heals only what is still missing,
    // since the Verifier counts are read again.
    if (heal_network_mutex) xSemaphoreTake(heal_network_mutex, portMAX_DELAY);
    bool heal_ok = heal_network_unsafe();
    if (heal_network_mutex) xSemaphoreGive(heal_network_mutex);
    return heal_ok;
}

bool auth_remove_in_progress(void) {
    bool active;
    TAKE_REMOVE_MUTEX(__FUNCTION__);
    active = current_removal.is_active;
    GIVE_REMOVE_MUTEX(__FUNCTION__);
    return active;
}

void auth_remove_leave_network(void) {
    ESP_LOGW(TAG, "Local request to leave the network. Spawning high-priority decommission task.");
    xTaskCreate(decommission_task, "decommission_task", 4096, NULL, configMAX_PRIORITIES - 1, NULL);
}

void remove_report_suspect(const char *suspect_ip) {
    char my_ip[INET_ADDRSTRLEN], leader_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    if (!raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0)) {
        ESP_LOGW(TAG, "No Coordinator known. Cannot report %s.", suspect_ip);
        return;
    }

    if (strcmp(my_ip, leader_ip) == 0) {
        char ip_copy[INET_ADDRSTRLEN] = {0};
        strncpy(ip_copy, suspect_ip, INET_ADDRSTRLEN - 1);
        if (xQueueSend(remove_request_queue, ip_copy, pdMS_TO_TICKS(100)) != pdPASS) {
            ESP_LOGE(TAG, "Could not queue removal request for %s. Queue may be full.", suspect_ip);
        }
        return;
    }

    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

    char report_msg[128];
    snprintf(report_msg, sizeof(report_msg), "%s:%s:%s\n", MSG_REMOVE_REPORT, suspect_ip, nonce_hex);
    connection_pool_send(leader_ip, report_msg);
}

/**
 * @brief Handles incoming node removal commands.
 * @details When a follower receives a removal command, it verifies the leader's integrity
 * before executing the command and sending an acknowledgement.
 * @param message The raw, null-terminated message string received from a peer.
 * @param from_ip The IP address of the node that sent the message.
 */
/**
 * @brief (Verifier) Announces to every member that this node confirms the removal of a target, so the
 * members can see the Verifiers' own backing of the order and not only the Coordinator's word.
 */
static void broadcast_removal_confirmation(uint32_t tid, const char *target) {
    int peer_count = 0;
    char **peers = raft_state_get_peers_copy(&peer_count);
    if (!peers) return;
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i], my_ip) != 0 && strcmp(peers[i], target) != 0) {
            uint8_t nonce[NONCE_SIZE];
            char nonce_hex[NONCE_HEX_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
            char msg[128];
            snprintf(msg, sizeof(msg), "%s:%lu:%s:%s\n", MSG_REMOVE_CONFIRMED, (unsigned long)tid, target, nonce_hex);
            connection_pool_send(peers[i], msg);
        }
        free(peers[i]);
    }
    free(peers);
}

/**
 * @brief Records a Verifier's confirmation of a removal and returns the number of distinct Verifiers
 * of the target heard so far. The tally is reset when a different (tid, target) is seen.
 */
static int note_verifier_confirmation(uint32_t tid, const char *target, const char *from_ip) {
    if (confirm_tally.tid != tid || strcmp(confirm_tally.target, target) != 0) {
        memset(&confirm_tally, 0, sizeof(confirm_tally));
        confirm_tally.tid = tid;
        strncpy(confirm_tally.target, target, INET_ADDRSTRLEN - 1);
    }
    for (int i = 0; i < confirm_tally.count; i++) {
        if (strcmp(confirm_tally.confirmers[i], from_ip) == 0) return confirm_tally.count;
    }
    if (confirm_tally.count < MAX_VERIFIERS) {
        strncpy(confirm_tally.confirmers[confirm_tally.count], from_ip, INET_ADDRSTRLEN - 1);
        confirm_tally.confirmers[confirm_tally.count][INET_ADDRSTRLEN - 1] = '\0';
        confirm_tally.count++;
    }
    return confirm_tally.count;
}

/** @brief Whether enough Verifiers of the target have independently confirmed the removal. */
static bool verifier_evidence_ok(uint32_t tid, const char *target) {
    return confirm_tally.tid == tid && strcmp(confirm_tally.target, target) == 0 &&
           confirm_tally.count >= REMOVAL_MIN_VERIFIER_CONFIRMATIONS;
}

/**
 * @brief Applies a removal locally and acknowledges it to the Coordinator. Called only once the order
 * is backed by this node's own confirmation or by the target's Verifiers' announcements.
 */
static void apply_removal_locally(uint32_t tid, const char *target, const char *nonce, const char *leader_ip) {
    confirmed_removal_tid = 0;
    confirmed_removal_ip[0] = '\0';
    ESP_LOGW(TAG, "Applying removal of peer %s (tid %lu). Updating local state.", target, (unsigned long)tid);
    db_remove_node(target);
    raft_state_remove_peer(target);
    db_remove_cnode_for_node(target);
    db_remove_crp_for_node(target);
    if (leader_ip && leader_ip[0]) {
        char ack_msg[128];
        snprintf(ack_msg, sizeof(ack_msg), "%s:%lu:%s:%s\n", MSG_NODE_REMOVED_ACK, (unsigned long)tid, target, nonce);
        connection_pool_send(leader_ip, ack_msg);
    }
}

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
        uint32_t tid = strtoul(transaction_id_str, NULL, 10);

        // This node applies the order only if it confirmed the removal itself, or if a Verifier of the
        // target announced its confirmation. A captured Coordinator acting alone, which skips the
        // confirmation phase, therefore cannot make any member remove a healthy device.
        bool self_confirmed = confirmed_removal_tid == tid && strcmp(confirmed_removal_ip, ip_to_remove) == 0 &&
                              (xTaskGetTickCount() - confirmed_removal_tick) * portTICK_PERIOD_MS <= REMOVAL_CONFIRMATION_VALIDITY_MS + hatt_measurement_timeout_ms();

        if (self_confirmed || verifier_evidence_ok(tid, ip_to_remove)) {
            apply_removal_locally(tid, ip_to_remove, nonce, leader_ip);
        } else {
            // The order may have arrived before the Verifiers' announcements: hold it until they do.
            pending_order.present = true;
            pending_order.tid = tid;
            strncpy(pending_order.target, ip_to_remove, INET_ADDRSTRLEN - 1);
            pending_order.target[INET_ADDRSTRLEN - 1] = '\0';
            strncpy(pending_order.nonce, nonce, sizeof(pending_order.nonce) - 1);
            pending_order.nonce[sizeof(pending_order.nonce) - 1] = '\0';
            strncpy(pending_order.leader_ip, leader_ip, INET_ADDRSTRLEN - 1);
            pending_order.leader_ip[INET_ADDRSTRLEN - 1] = '\0';
            pending_order.tick = xTaskGetTickCount();
            ESP_LOGW(TAG, "Removal order for %s from %s held: no Verifier of the target has confirmed it yet.", ip_to_remove, from_ip);
        }
    } else if (strcmp(command, MSG_REMOVE_CONFIRMED) == 0) {
        char* transaction_id_str = strtok_r(NULL, ":", &saveptr);
        char* target_ip = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!transaction_id_str || !target_ip || !nonce || !nonce_is_valid_and_store(nonce)) return;
        // Only a member that is actually a Verifier of the target can vouch for its removal.
        if (!db_node_exists(from_ip) || !is_verifier_of_device(from_ip, target_ip)) {
            ESP_LOGW(TAG, "%s for %s from %s ignored: not a Verifier of the target.", MSG_REMOVE_CONFIRMED, target_ip, from_ip);
            return;
        }
        uint32_t tid = strtoul(transaction_id_str, NULL, 10);
        note_verifier_confirmation(tid, target_ip, from_ip);
        // A held order for this target can now be applied, if the Coordinator's order has arrived.
        if (verifier_evidence_ok(tid, target_ip) && pending_order.present &&
            pending_order.tid == tid && strcmp(pending_order.target, target_ip) == 0 &&
            (xTaskGetTickCount() - pending_order.tick) * portTICK_PERIOD_MS <= REMOVAL_CONFIRMATION_VALIDITY_MS + hatt_measurement_timeout_ms()) {
            pending_order.present = false;
            apply_removal_locally(tid, target_ip, pending_order.nonce, pending_order.leader_ip);
        }
    } else if (strcmp(command, MSG_REMOVE_CHECK_REQ) == 0) {
        if (!has_leader || strcmp(from_ip, leader_ip) != 0) return;

        char* transaction_id_str = strtok_r(NULL, ":", &saveptr);
        char* ip_to_remove = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!transaction_id_str || !ip_to_remove || !nonce || !nonce_is_valid_and_store(nonce)) return;

        bool confirmed = remove_verifier_confirms(ip_to_remove);
        if (confirmed) {
            confirmed_removal_tid = strtoul(transaction_id_str, NULL, 10);
            strncpy(confirmed_removal_ip, ip_to_remove, INET_ADDRSTRLEN - 1);
            confirmed_removal_ip[INET_ADDRSTRLEN - 1] = '\0';
            confirmed_removal_tick = xTaskGetTickCount();
        }

        char reply_msg[128];
        snprintf(reply_msg, sizeof(reply_msg), "%s:%s:%s:%s\n", confirmed ? MSG_REMOVE_CHECK_OK : MSG_REMOVE_CHECK_REFUSED, transaction_id_str, ip_to_remove, nonce);
        connection_pool_send(leader_ip, reply_msg);
        // Announce the confirmation to every member, so each can apply the order on the Verifiers'
        // backing and not on the Coordinator's word alone.
        if (confirmed) broadcast_removal_confirmation(strtoul(transaction_id_str, NULL, 10), ip_to_remove);
    } else if (strcmp(command, MSG_REMOVE_CHECK_OK) == 0 || strcmp(command, MSG_REMOVE_CHECK_REFUSED) == 0) {
        char* transaction_id_str = strtok_r(NULL, ":", &saveptr);
        char* checked_node_ip = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!transaction_id_str || !checked_node_ip || !nonce) {
            ESP_LOGW(TAG, "Malformed %s from %s", command, from_ip);
            return;
        }

        TAKE_REMOVE_MUTEX(__FUNCTION__);
        if (current_removal.is_active &&
            current_removal.transaction_id == strtoul(transaction_id_str, NULL, 10) &&
            strcmp(current_removal.removed_node_ip, checked_node_ip) == 0) {
            // Each device is counted once, so that a single device cannot stand in for the others.
            bool already_replied = false;
            for (int i = 0; i < current_removal.check_replied_count; i++) {
                if (strcmp(current_removal.check_replied_ips[i], from_ip) == 0) {
                    already_replied = true;
                    break;
                }
            }

            // Only the Verifiers of the device can check it, so only their answers are counted.
            if (already_replied || !is_verifier_of_device(from_ip, checked_node_ip) ||
                current_removal.check_replied_count >= MAX_REMOVAL_CHECK_REPLIES) {
                ESP_LOGW(TAG, "[RemoveID: %s] Duplicate or unexpected %s from %s ignored.", transaction_id_str, command, from_ip);
            } else {
                strncpy(current_removal.check_replied_ips[current_removal.check_replied_count], from_ip, INET_ADDRSTRLEN - 1);
                current_removal.check_replied_count++;
                if (strcmp(command, MSG_REMOVE_CHECK_OK) == 0) {
                    current_removal.check_ok_count++;
                } else {
                    ESP_LOGW(TAG, "[RemoveID: %s] Verifier %s refused the removal of %s.", transaction_id_str, from_ip, checked_node_ip);
                    current_removal.check_refused_count++;
                }
            }
        }
        GIVE_REMOVE_MUTEX(__FUNCTION__);
    } else if (strcmp(command, MSG_REMOVE_REPORT) == 0) {
        char* suspect_ip = strtok_r(NULL, ":", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!suspect_ip || !nonce || !nonce_is_valid_and_store(nonce)) return;

        char my_ip[INET_ADDRSTRLEN];
        raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
        if (!has_leader || strcmp(my_ip, leader_ip) != 0 || !db_node_exists(suspect_ip) || strcmp(suspect_ip, my_ip) == 0) return;

        ESP_LOGW(TAG, "Verifier %s reported device %s. Queueing its removal; the other verifiers will confirm it.", from_ip, suspect_ip);
        char ip_copy[INET_ADDRSTRLEN] = {0};
        strncpy(ip_copy, suspect_ip, INET_ADDRSTRLEN - 1);
        if (xQueueSend(remove_request_queue, ip_copy, pdMS_TO_TICKS(100)) != pdPASS) {
            ESP_LOGE(TAG, "Could not queue removal request for %s. Queue may be full.", suspect_ip);
        }
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

        // A device never decommissions itself on a network command: it leaves only on a local
        // request (auth_remove_leave_network), so that the Coordinator cannot evict a healthy device.
        ESP_LOGW(TAG, "Received PREPARE_FOR_REMOVAL from %s. Ignored.", from_ip);
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
            if (record_ack_once(current_removal.pause_acked_ips, current_removal.maintenance_ack_count, from_ip)) {
                current_removal.maintenance_ack_count++;
            }
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

    // The device under removal may be unreachable: it is not asked to pause and its ACK is not awaited.
    int paused_followers = 0;
    ESP_LOGI(TAG, "Broadcasting PAUSE command to the followers.");
    for (int i = 0; i < follower_count; i++) {
        char follower_ip[INET_ADDRSTRLEN];
        if (db_get_follower_ip(i, follower_ip, sizeof(follower_ip)) && strcmp(follower_ip, ip_to_remove) != 0) {
            paused_followers++;
            char nonce_hex[NONCE_HEX_SIZE];
            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

            char pause_msg[128];
            snprintf(pause_msg, sizeof(pause_msg), "%s:%lu:%s\n", MSG_PAUSE_HB_TIMERS, current_term, nonce_hex);
            
            connection_pool_send(follower_ip, pause_msg);
        }
    }

    // Other members may have crashed as well: the removal goes on with the majority of the members.
    int expected_acks = paused_followers;
    if (expected_acks > 0) {
        ESP_LOGI(TAG, "Waiting for %d PAUSE_ACKs by polling shared state...", expected_acks);
        if (!wait_for_member_acks(&current_removal.maintenance_ack_count, expected_acks, SINGLE_ACK_TIMEOUT_MS)) {
            ESP_LOGE(TAG, "Timeout waiting for PAUSE_ACKs. Aborting removal.");
            goto cleanup; 
        }
    }
    ESP_LOGI(TAG, "PAUSE confirmed. Proceeding with removal.");

    // Confirmation phase: the majority of the Verifiers of the device must agree before anything is deleted.
    // A Verifier confirms if the device does not answer or fails its checks, and refuses if the device passes them.
    // All the Verifiers are consulted; each checks the device on its own, and the device serves them one at a time.
    char my_ip_check[INET_ADDRSTRLEN];
    get_my_ip(my_ip_check, sizeof(my_ip_check));
    int verifier_total = 0;
    int remote_count = 0;
    bool self_is_verifier = false;
    char (*verifiers)[INET_ADDRSTRLEN] = malloc(MAX_VERIFIERS * INET_ADDRSTRLEN);
    if (verifiers) {
        int listed = db_get_verifiers_for_node(ip_to_remove, verifiers, MAX_VERIFIERS);
        for (int i = 0; i < listed; i++) {
            if (strcmp(verifiers[i], ip_to_remove) == 0) continue;
            verifier_total++;
            if (strcmp(verifiers[i], my_ip_check) == 0) {
                self_is_verifier = true;
                continue;
            }
            if (remote_count != i) memcpy(verifiers[remote_count], verifiers[i], INET_ADDRSTRLEN);
            remote_count++;
        }
    }

    // Every Verifier is consulted, so that each of them can confirm and later execute the order. The
    // checks run on the Verifiers themselves, and the device under removal serves them one at a time.
    for (int i = 0; verifiers && i < remote_count; i++) {
        char nonce_hex[NONCE_HEX_SIZE];
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
        char check_msg[128];
        snprintf(check_msg, sizeof(check_msg), "%s:%lu:%s:%s\n", MSG_REMOVE_CHECK_REQ, process_copy.transaction_id, ip_to_remove, nonce_hex);
        connection_pool_send(verifiers[i], check_msg);
    }
    if (verifiers) free(verifiers);

    // The removal is decided by the majority of the Verifiers that answer, i.e., it needs more confirmations
    // than refusals. A Verifier that does not answer within the timeout, e.g., because it failed as well, is
    // not counted, so the failure of some Verifiers does not block the removal of a failed device.
    // The Coordinator votes only if it is one of the Verifiers of the device.
    int own_ok = 0, own_refused = 0;
    if (self_is_verifier) {
        if (remove_verifier_confirms(ip_to_remove)) {
            own_ok = 1;
            broadcast_removal_confirmation(process_copy.transaction_id, ip_to_remove);
        } else {
            own_refused = 1;
        }
    }
    int ok_count = own_ok, refused_count = own_refused;

    // The order is sent only after all the answers, so that a Verifier that confirms late is not left out.
    const uint32_t check_timeout_ms = REMOVAL_CHECK_PHASE_TIMEOUT_MS + (uint32_t)remote_count * hatt_measurement_timeout_ms();
    uint32_t start_tick = xTaskGetTickCount();
    while ((xTaskGetTickCount() - start_tick) * portTICK_PERIOD_MS < check_timeout_ms) {
        TAKE_REMOVE_MUTEX(__FUNCTION__);
        int answered = current_removal.check_replied_count;
        ok_count = current_removal.check_ok_count + own_ok;
        refused_count = current_removal.check_refused_count + own_refused;
        GIVE_REMOVE_MUTEX(__FUNCTION__);
        if (answered >= remote_count) break;
        // The refusals already outnumber the confirmations that can still arrive.
        if (2 * refused_count >= verifier_total) break;
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    bool removal_confirmed = (verifier_total == 0) || (ok_count > refused_count);
    ESP_LOGI(TAG, "[RemoveID: %lu] Verifiers of %s: %d confirmed, %d refused, %d did not answer, %d in total.",
             process_copy.transaction_id, ip_to_remove, ok_count, refused_count, verifier_total - ok_count - refused_count, verifier_total);

    if (!removal_confirmed) {
        ESP_LOGE(TAG, "[RemoveID: %lu] Removal of %s was not confirmed by its verifiers. Aborting.", process_copy.transaction_id, ip_to_remove);
        char *event_msg_refused = malloc(MAX_MESSAGE_SIZE);
        if (event_msg_refused) {
            snprintf(event_msg_refused, MAX_MESSAGE_SIZE, "REMOVE_REFUSED:%s", ip_to_remove);
            send_monitoring_tcp_event(event_msg_refused);
            free(event_msg_refused);
        }
        goto cleanup;
    }
    ESP_LOGI(TAG, "[RemoveID: %lu] Removal of %s confirmed. Proceeding.", process_copy.transaction_id, ip_to_remove);

    db_remove_node(ip_to_remove);
    raft_state_remove_peer(ip_to_remove);

    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
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

        // The removal was decided by the Verifiers; the order is effective once the majority of the members has applied it.
        // A member that does not acknowledge has crashed, and is removed in turn, or is a Verifier that did not confirm.
        if (!wait_for_member_acks(&current_removal.removal_ack_count, follower_count, SINGLE_ACK_TIMEOUT_MS)) {
            ESP_LOGE(TAG, "Timed out waiting for REMOVED_ACKs.");
            all_followers_acked = false;
        }
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
        
        if (!auth_remove_heal_network()) {
            all_followers_acked = false;
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