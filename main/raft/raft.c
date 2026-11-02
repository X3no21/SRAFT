/* =============================
 * File: raft.c
 * Description: An implementation of a simplified RAFT consensus algorithm for leader election.
 * ============================= */

#include "raft.h"
#include "esp_heap_caps.h"
#include "raft_state.h"
#include "connection_pool.h"
#include "utility.h"
#include "auth_join.h"
#include "auth_remove.h"
#include "auth_puf.h"
#include "auth_db.h"
#include "integrity_verification.h"
#include "nonce_manager.h"

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>

static const char *TAG = "RAFT";

static TaskHandle_t raft_orchestrator_task_handle = NULL;
static TimerHandle_t heartbeat_sender_timer = NULL;

static bool is_raft_initialized = false;

/**
 * @brief Retrieves the handle of the heartbeat sender timer.
 * @return The FreeRTOS TimerHandle_t for the heartbeat sender.
 */
TimerHandle_t raft_get_heartbeat_sender_timer(void) {
    return heartbeat_sender_timer;
}

/**
 * @brief Notifies the central orchestrator task to wake up and evaluate the node's state.
 * @details This is a lightweight signaling mechanism used by timer callbacks to offload heavy processing
 * from the FreeRTOS Timer Service task context, preventing stack overflows.
 * @return void
 */
static void notify_orchestrator() {
    if (raft_orchestrator_task_handle != NULL) {
        xTaskNotifyGive(raft_orchestrator_task_handle);
    }
}

/**
 * @brief Callback function executed when the heartbeat timer expires.
 * @details This indicates a potential leader failure for a FOLLOWER node. It notifies the
 * orchestrator task to take action.
 * @param xTimer The handle of the timer that expired.
 */
static void heartbeat_timeout_callback(TimerHandle_t xTimer) {
    notify_orchestrator();
}

/**
 * @brief Callback function executed when the election timer expires.
 * @details This indicates that a CANDIDATE has failed to win the election in the allotted time.
 * It notifies the orchestrator task to start a new election.
 * @param xTimer The handle of the timer that expired.
 */
static void election_timeout_callback(TimerHandle_t xTimer) {
    notify_orchestrator();
}

/**
 * @brief Sends heartbeat messages to all peers.
 * @details This function is called periodically. It retrieves the current cluster state
 * and sends a HEARTBEAT RPC to all known peers to assert authority and prevent new elections.
 */
static void send_heartbeats_to_peers() {
    int peer_count = 0;
    char **peers = raft_state_get_peers_copy(&peer_count);
    if (!peers) return;

    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), my_mac, sizeof(my_mac));
    uint32_t current_term = raft_state_get_current_term();

    char *msg = malloc(MAX_MESSAGE_SIZE);
    if (!msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
        return;
    }
    snprintf(msg, MAX_MESSAGE_SIZE, "%s %lu %s %s\n", MSG_HEARTBEAT, current_term, my_ip, my_mac);
    ESP_LOGI(TAG, "%s", msg);

    ESP_LOGD(TAG, "Leader sending heartbeats for term %lu", current_term);

    for (int i = 0; i < peer_count; i++) {
        if (strcmp(my_ip, peers[i]) != 0) {
            connection_pool_send(peers[i], msg);
        }
    }

    free(msg);
    for (int i = 0; i < peer_count; i++) free(peers[i]);
    free(peers);
}

/**
 * @brief Callback function executed by the leader's periodic heartbeat timer.
 * @details Checks if the node is still the leader and, if so, triggers the sending
 * of heartbeat messages to all peers.
 * @param xTimer The handle of the timer that triggered the callback.
 */
static void heartbeat_sender_callback(TimerHandle_t xTimer) {
    if (raft_state_get_state() == LEADER) {
        send_heartbeats_to_peers();

        leader_heal_if_needed();
    }
}

/**
 * @brief As a new leader, broadcasts a "Leader Is" (LI) message to all peers.
 * @details This is an optimization for faster cluster convergence after an election. The message
 * includes the leader's term, IP, and MAC address.
 * @return void
 */
static void announce_leadership() {
    int peer_count = 0;
    char **peers = raft_state_get_peers_copy(&peer_count);
    if (!peers) return;

    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), my_mac, sizeof(my_mac));
    uint32_t term = raft_state_get_current_term();

    char *msg = malloc(MAX_MESSAGE_SIZE);
    if (!msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
        return;
    }
    snprintf(msg, MAX_MESSAGE_SIZE, "%s %lu %s %s\n", MSG_LEADER_ANNOUNCE, term, my_ip, my_mac);
    ESP_LOGI(TAG, "%s", msg);

    for (int i = 0; i < peer_count; i++) {
        if (strcmp(my_ip, peers[i]) != 0) {
            connection_pool_send(peers[i], msg);
        }
    }

    free(msg);
    for (int i = 0; i < peer_count; i++) free(peers[i]);
    free(peers);
}

/**
 * @brief Finalizes the process of a node becoming the leader.
 * @details It updates the node's state, notifies the monitoring server, and announces
 * its new leadership role to all peers in the cluster.
 * @return void
 */
static void become_leader() {
    uint32_t term = raft_state_get_current_term();
    int vote_count = raft_state_get_vote_count();
    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), my_mac, sizeof(my_mac));

    ESP_LOGI(TAG, "Transitioning to LEADER for term %lu! Total Votes: %d", term, vote_count);
    
    raft_state_become_leader();

    char *event_msg = malloc(MAX_MESSAGE_SIZE);
    if (!event_msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
        return;
    }
    snprintf(event_msg, MAX_MESSAGE_SIZE, "LEADER_ELECTED:%lu:%s", term, my_mac);
    ESP_LOGI(TAG, "%s", event_msg);
    send_monitoring_tcp_event(event_msg);
    free(event_msg);

    announce_leadership();

    if (heartbeat_sender_timer) {
        xTimerStart(heartbeat_sender_timer, 0);
    }
}

/**
 * @brief Initiates a leader election.
 * @details This function transitions the node to a CANDIDATE, notifies the monitoring server,
 * and sends RequestVote RPCs to all peers via the connection pool. The RPC includes
 * the candidate's MAC address for blacklist verification.
 * @return void
 */
static void start_election() {
    uint32_t new_term = raft_state_become_candidate();
    ESP_LOGI(TAG, "Starting election: now CANDIDATE for new term %lu.", new_term);

    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), my_mac, sizeof(my_mac));
    char *event_msg = malloc(MAX_MESSAGE_SIZE);
    if (!event_msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
        return;
    }
    snprintf(event_msg, MAX_MESSAGE_SIZE, "ELECTION_START:%lu:%s", new_term, my_mac);
    ESP_LOGI(TAG, "%s", event_msg);
    send_monitoring_tcp_event(event_msg);
    free(event_msg);

    int peer_count = 0;
    char **peers = raft_state_get_peers_copy(&peer_count);
    if (!peers) return;
    
    int majority = (peer_count / 2) + 1;
    if (raft_state_get_vote_count() >= majority) {
        become_leader();
        for (int i = 0; i < peer_count; i++) free(peers[i]);
        free(peers);
        return;
    }

    char *rpc_msg = malloc(MAX_MESSAGE_SIZE);
    if (!rpc_msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
        return;
    }
    snprintf(rpc_msg, MAX_MESSAGE_SIZE, "%s %lu %s %s 0 0\n", MSG_REQUEST_VOTE, new_term, my_ip, my_mac);
    ESP_LOGI(TAG, "%s", rpc_msg);

    for (int i = 0; i < peer_count; i++) {
        if (strcmp(my_ip, peers[i]) != 0) {
            connection_pool_send(peers[i], rpc_msg);
        }
    }

    free(rpc_msg);
    for (int i = 0; i < peer_count; i++) free(peers[i]);
    free(peers);
}

/**
 * @brief A central task that manages RAFT's time-based events and logic.
 * @details This task is purely event-driven, woken up by timer callbacks. If a follower's
 * heartbeat timer expires or a candidate's election timer expires, it triggers a new election.
 * @param pvParameters Unused task parameters.
 */
static void raft_orchestrator_task(void *pvParameters) {
    ESP_LOGI(TAG, "Orchestrator task started.");
    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        ESP_LOGD(TAG, "Orchestrator woken up by timer.");

        raft_state_e current_state = raft_state_get_state();

        if (current_state == FOLLOWER) {
            uint32_t age = raft_state_get_last_heartbeat_age();
            if (age < HEARTBEAT_TIMEOUT_MS) {
                ESP_LOGW(TAG, "Ignoring stale heartbeat timeout. Last heartbeat was %lu ms ago.", age);
            } else {
                ESP_LOGW(TAG, "Heartbeat timeout! (Term: %lu, Age: %lu ms)", raft_state_get_current_term(), age);
                start_election();
            }
        } else if (current_state == CANDIDATE) {
            uint32_t failed_term = raft_state_get_current_term();
            int current_votes = raft_state_get_vote_count();
            char my_ip[INET_ADDRSTRLEN];
            char my_mac[MAC_ADDR_STR_LEN];
            raft_state_get_self_info(my_ip, sizeof(my_ip), my_mac, sizeof(my_mac));

            ESP_LOGW(TAG, "Election timeout! (Term: %lu, Votes: %d)", failed_term, current_votes);
            char *event_msg = malloc(MAX_MESSAGE_SIZE);
            if (event_msg) {
                snprintf(event_msg, MAX_MESSAGE_SIZE, "CANDIDATE_STEPDOWN:%lu:%s", failed_term, my_mac);
                send_monitoring_tcp_event(event_msg);
                free(event_msg);
            }
            raft_state_increase_election_timeout();
            start_election();
        }
    }
}

/**
 * @brief Forcefully stops all active Raft timers and the orchestrator task.
 * @details This function acts as a hard stop for the Raft protocol logic on a node. 
 * It is called when a node is being decommissioned (e.g., removed from the cluster) 
 * to ensure it becomes inert. It deletes the main orchestrator task to prevent new 
 * elections and explicitly stops the leader's heartbeat sender, the follower's 
 * heartbeat timeout, and the candidate's election timers.
 * @return void
 */
void raft_shutdown_timers_and_tasks(void) {
    ESP_LOGW(TAG, "Shutting down all Raft timers and tasks...");

    if (heartbeat_sender_timer && xTimerIsTimerActive(heartbeat_sender_timer)) {
        xTimerStop(heartbeat_sender_timer, pdMS_TO_TICKS(100));
        ESP_LOGI(TAG, "Heartbeat sender timer stopped.");
    }

    TimerHandle_t election_timer = NULL, heartbeat_timer = NULL;
    raft_state_get_timers(&election_timer, &heartbeat_timer);
    if (election_timer && xTimerIsTimerActive(election_timer)) {
        xTimerStop(election_timer, pdMS_TO_TICKS(100));
        ESP_LOGI(TAG, "Election timer stopped.");
    }
    if (heartbeat_timer && xTimerIsTimerActive(heartbeat_timer)) {
        xTimerStop(heartbeat_timer, pdMS_TO_TICKS(100));
        ESP_LOGI(TAG, "Heartbeat timeout timer stopped.");
    }
    is_raft_initialized = false;
}

/**
 * @brief Queue for offloading heavy RAFT messages (Join, Remove, Integrity) to a background task.
 */
static QueueHandle_t raft_worker_queue = NULL;

typedef struct {
    char *message;
    char from_ip[INET_ADDRSTRLEN];
} raft_worker_msg_t;

/**
 * @brief Worker task that processes heavy RAFT messages sequentially.
 * @details This task handles Join, Remove, and Integrity Check messages which may involve
 * database lookups, crypto operations, or other blocking calls. By offloading these
 * from the main message handler, we ensure that Heartbeats and RequestVotes are
 * processed immediately in the I/O task context.
 */
static void raft_worker_task(void *pvParameters) {
    raft_worker_msg_t *msg;
    ESP_LOGI(TAG, "RAFT Worker Task started.");
    while (1) {
        if (xQueueReceive(raft_worker_queue, &msg, portMAX_DELAY) == pdTRUE) {
            
            if (strncmp(msg->message, MSG_REQUEST_INTEGRITY_CHECK, strlen(MSG_REQUEST_INTEGRITY_CHECK)) == 0 || 
                strncmp(msg->message, MSG_PROCEED_WITH_INTEGRITY_CHECK, strlen(MSG_PROCEED_WITH_INTEGRITY_CHECK)) == 0) {
                integrity_verification_handle_message(msg->message, msg->from_ip);
            } else if (strncmp(msg->message, MSG_REMOVE_PREFIX, strlen(MSG_REMOVE_PREFIX)) == 0) {
                remove_handle_message(msg->message, msg->from_ip);
            } else if (strncmp(msg->message, MSG_NODE_REMOVED_ACK, strlen(MSG_NODE_REMOVED_ACK)) == 0) {
                 char *removed_node_ip = strchr(msg->message, ':');
                if (removed_node_ip != NULL && strlen(removed_node_ip) > 1) {
                    remove_handle_message(msg->message, msg->from_ip);
                }
            } else if (strncmp(msg->message, MSG_NODE_REMOVED, strlen(MSG_NODE_REMOVED)) == 0 || 
                       strncmp(msg->message, MSG_NODE_REMOVE_ABORT, strlen(MSG_NODE_REMOVE_ABORT)) == 0 ||
                       strncmp(msg->message, MSG_PREPARE_FOR_REMOVAL, strlen(MSG_PREPARE_FOR_REMOVAL)) == 0 ||
                       strncmp(msg->message, MSG_PAUSE_HB_ACK, strlen(MSG_PAUSE_HB_ACK)) == 0) {
                remove_handle_message(msg->message, msg->from_ip);
            } else {
                join_handle_message(msg->message, msg->from_ip);
            }

            free(msg->message);
            free(msg);
        }
    }
}

/**
 * @brief Queues a message for the background worker task.
 */
static void queue_for_worker(char *message, const char *from_ip) {
    if (!raft_worker_queue) {
        ESP_LOGE(TAG, "RAFT worker queue not initialized! Dropping message.");
        free(message);
        return;
    }

    raft_worker_msg_t *msg = malloc(sizeof(raft_worker_msg_t));
    if (!msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for RAFT worker message.");
        free(message);
        return;
    }

    msg->message = message;
    strncpy(msg->from_ip, from_ip, INET_ADDRSTRLEN - 1);
    msg->from_ip[INET_ADDRSTRLEN - 1] = '\0';

    if (xQueueSend(raft_worker_queue, &msg, pdMS_TO_TICKS(100)) != pdPASS) {
        ESP_LOGE(TAG, "RAFT worker queue full! Dropping message.");
        free(msg->message);
        free(msg);
    }
}

/**
 * @brief Callback passed to the connection pool to handle all incoming RPC messages.
 * @details This function is the single entry point for all data received from the network.
 * It parses the message and dispatches it to the appropriate handler in the RAFT state machine.
 * @param from_ip The IP address of the node that sent the message.
 * @param message The null-terminated message string.
 */
static bool is_from_leader(const char *from_ip) {
    char leader_ip[INET_ADDRSTRLEN];
    return raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0) && strcmp(from_ip, leader_ip) == 0;
}

void raft_message_handler(const char* from_ip, const char* message) {
    bool is_join_protocol_message = 
        strncmp(message, MSG_JOIN_FAIL_MASTER_CORRUPT, strlen(MSG_JOIN_FAIL_MASTER_CORRUPT)) == 0 ||
        strncmp(message, MSG_JOIN_REQ, strlen(MSG_JOIN_REQ)) == 0 ||
        strncmp(message, MSG_JOIN_CHL, strlen(MSG_JOIN_CHL)) == 0 ||
        strncmp(message, MSG_JOIN_FINALIZE, strlen(MSG_JOIN_FINALIZE)) == 0 ||
        strncmp(message, MSG_NET_STATE, strlen(MSG_NET_STATE)) == 0 ||
        strncmp(message, MSG_JOIN_RESPONSE, strlen(MSG_JOIN_RESPONSE)) == 0 ||
        strncmp(message, MSG_JOIN_FAIL_NO_VERIFIERS, strlen(MSG_JOIN_FAIL_NO_VERIFIERS)) == 0 ||
        strncmp(message, MSG_JOIN_ABORT, strlen(MSG_JOIN_ABORT)) == 0 ||
        strncmp(message, MSG_CHALLENGE_GENERATED, strlen(MSG_CHALLENGE_GENERATED)) == 0 ||
        strncmp(message, MSG_NODE_ADDED_COMMIT, strlen(MSG_NODE_ADDED_COMMIT)) == 0 ||
        strncmp(message, MSG_NODE_HEALED_COMMIT, strlen(MSG_NODE_HEALED_COMMIT)) == 0 ||
        strncmp(message, MSG_COMMIT_ACK, strlen(MSG_COMMIT_ACK)) == 0 ||
        strncmp(message, MSG_CLEANUP_COMMIT, strlen(MSG_CLEANUP_COMMIT)) == 0 ||
        strncmp(message, MSG_VERIFIER_UPDATE, strlen(MSG_VERIFIER_UPDATE)) == 0 ||
        strncmp(message, MSG_VERIFIER_UPDATE_ACK, strlen(MSG_VERIFIER_UPDATE_ACK)) == 0 ||
        strncmp(message, MSG_CHL_RESULT, strlen(MSG_CHL_RESULT)) == 0 ||
        strncmp(message, MSG_REQ_CHL_GEN, strlen(MSG_REQ_CHL_GEN)) == 0 ||
        strncmp(message, MSG_DELEGATE_CRPS, strlen(MSG_DELEGATE_CRPS)) == 0;

    if (!is_join_protocol_message) {
        if (!raft_state_is_peer(from_ip) && !db_node_exists(from_ip)) {
            ESP_LOGW(TAG, "Message from unknown peer %s discarded (not in Raft peers or DB): '%s'", from_ip, message);
            return;
        }
    }

    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);

    ESP_LOGI(TAG, "<- RPC RECV from %s to %s: %s", from_ip, my_ip, message);

    uint32_t rpc_term, rpc_lli, rpc_llt;
    char ip_str[INET_ADDRSTRLEN];
    char mac_str[MAC_ADDR_STR_LEN];
    char nonce[NONCE_HEX_SIZE];

    char *buffer_copy = malloc(MAX_MESSAGE_SIZE);
    if (!buffer_copy) {
        ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
        return;
    }
    strncpy(buffer_copy, message, MAX_MESSAGE_SIZE - 1);
    buffer_copy[MAX_MESSAGE_SIZE - 1] = '\0';

    if (sscanf(message, "RV %lu %15s %17s %lu %lu", &rpc_term, ip_str, mac_str, &rpc_lli, &rpc_llt) == 5) {
        // The election messages are accepted only from the device they name.
        if (strcmp(from_ip, ip_str) != 0) {
            ESP_LOGW(TAG, "%s from %s names another device (%s). Ignored.", MSG_REQUEST_VOTE, from_ip, ip_str);
            free(buffer_copy);
            return;
        }
        bool vote_was_granted = raft_state_handle_request_vote(rpc_term, ip_str, mac_str, rpc_lli, rpc_llt);
        if (vote_was_granted) {
            char *reply_msg = malloc(MAX_MESSAGE_SIZE);
            if (!reply_msg) {
                ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
                free(buffer_copy);
                return;
            }
            snprintf(reply_msg, MAX_MESSAGE_SIZE, "%s %lu %s\n", MSG_VOTE_GRANTED, raft_state_get_current_term(), my_ip);
            connection_pool_send(ip_str, reply_msg);
            free(reply_msg);
        }
        free(buffer_copy);
    } else if (strncmp(message, MSG_BLACKLIST_ADD "|", strlen(MSG_BLACKLIST_ADD) + 1) == 0) {
        // Only the Coordinator excludes devices for the whole network. A device that does not know
        // the Coordinator yet accepts the list from one of its peers.
        char leader_ip[INET_ADDRSTRLEN];
        bool has_leader = raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0);
        bool sender_allowed = has_leader ? (strcmp(from_ip, leader_ip) == 0) : raft_state_is_peer(from_ip);

        char *saveptr;
        strtok_r(buffer_copy, "|", &saveptr);
        char *mac = strtok_r(NULL, "|", &saveptr);
        char *bl_nonce = strtok_r(NULL, "|\r\n", &saveptr);
        if (sender_allowed && mac && bl_nonce && strlen(mac) < MAC_ADDR_STR_LEN && nonce_is_valid_and_store(bl_nonce)) {
            raft_state_blacklist_mac(mac);
        } else {
            ESP_LOGW(TAG, "%s from %s ignored.", MSG_BLACKLIST_ADD, from_ip);
        }
        free(buffer_copy);
    } else if (sscanf(message, "HB %lu %15s %17s", &rpc_term, ip_str, mac_str) == 3 || sscanf(message, "LI %lu %15s %17s", &rpc_term, ip_str, mac_str) == 3) {
        if (strcmp(from_ip, ip_str) == 0) {
            raft_state_handle_heartbeat(rpc_term, ip_str, mac_str);
        } else {
            ESP_LOGW(TAG, "Heartbeat from %s names another Coordinator (%s). Ignored.", from_ip, ip_str);
        }
        free(buffer_copy);
    } else if (sscanf(message, "VG %lu %15s", &rpc_term, ip_str) == 2) {
        if (raft_state_get_state() == CANDIDATE && rpc_term == raft_state_get_current_term() && strcmp(from_ip, ip_str) == 0) {
            int new_vote_count = raft_state_record_vote(from_ip);
            if (new_vote_count < 0) {
                ESP_LOGW(TAG, "Vote of %s for term %lu already counted. Ignored.", from_ip, rpc_term);
                free(buffer_copy);
                return;
            }
            int peer_count = 0;
            char **peers = raft_state_get_peers_copy(&peer_count);
            int majority = 0;
            if (peers) {
                majority = (peer_count / 2) + 1;
                ESP_LOGI(TAG, "Vote received! Total votes: %d | Peers in quorum: %d | Majority needed: %d", new_vote_count, peer_count, majority);
                for (int i = 0; i < peer_count; i++) free(peers[i]);
                free(peers);
            }
            if (majority > 0 && new_vote_count >= majority) {
                become_leader();
            }
        }
        free(buffer_copy);
    } else if (sscanf(message, "VD %lu %15s", &rpc_term, ip_str) == 2) {
        if (rpc_term > raft_state_get_current_term()) {
            ESP_LOGI(TAG, "Received vote denied from a higher term (%lu). Becoming follower.", rpc_term);
            raft_state_become_follower(rpc_term);
        }
        free(buffer_copy);
    } else {
        if (strncmp(message, MSG_REQUEST_INTEGRITY_CHECK, strlen(MSG_REQUEST_INTEGRITY_CHECK)) == 0 || 
            strncmp(message, MSG_PROCEED_WITH_INTEGRITY_CHECK, strlen(MSG_PROCEED_WITH_INTEGRITY_CHECK)) == 0) {

            queue_for_worker(buffer_copy, from_ip);
        } else if (strncmp(message, MSG_JOIN_REQ, strlen(MSG_JOIN_REQ)) == 0 ||
                   strncmp(message, MSG_JOIN_CHL, strlen(MSG_JOIN_CHL)) == 0 ||
                   strncmp(message, MSG_JOIN_FINALIZE, strlen(MSG_JOIN_FINALIZE)) == 0 ||
                   strncmp(message, MSG_NET_STATE, strlen(MSG_NET_STATE)) == 0 ||
                   strncmp(message, MSG_JOIN_RESPONSE, strlen(MSG_JOIN_RESPONSE)) == 0 ||
                   strncmp(message, MSG_JOIN_ABORT, strlen(MSG_JOIN_ABORT)) == 0 ||
                   strncmp(message, MSG_JOIN_FAIL_MASTER_CORRUPT, strlen(MSG_JOIN_FAIL_MASTER_CORRUPT)) == 0 ||
                   strncmp(message, MSG_DELEGATE_CRPS, strlen(MSG_DELEGATE_CRPS)) == 0 ||
                   strncmp(message, MSG_VERIFIER_UPDATE, strlen(MSG_VERIFIER_UPDATE)) == 0 ||
                   strncmp(message, MSG_VERIFIER_UPDATE_ACK, strlen(MSG_VERIFIER_UPDATE_ACK)) == 0 ||
                   strncmp(message, MSG_REQ_CHL_GEN, strlen(MSG_REQ_CHL_GEN)) == 0 ||
                   strncmp(message, MSG_CHALLENGE_GENERATED, strlen(MSG_CHALLENGE_GENERATED)) == 0 ||
                   strncmp(message, MSG_CHL_RESULT, strlen(MSG_CHL_RESULT)) == 0 ||
                   strncmp(message, MSG_NODE_ADDED_COMMIT, strlen(MSG_NODE_ADDED_COMMIT)) == 0 ||
                   strncmp(message, MSG_NODE_HEALED_COMMIT, strlen(MSG_NODE_HEALED_COMMIT)) == 0 ||
                   strncmp(message, MSG_COMMIT_ACK, strlen(MSG_COMMIT_ACK)) == 0 ||
                   strncmp(message, MSG_CLEANUP_COMMIT, strlen(MSG_CLEANUP_COMMIT)) == 0 ||
                   strncmp(message, MSG_BROKER_REQ, strlen(MSG_BROKER_REQ)) == 0) {

            queue_for_worker(buffer_copy, from_ip);
        } else if (strncmp(message, MSG_NODE_REMOVED_ACK, strlen(MSG_NODE_REMOVED_ACK)) == 0 ||
                   strncmp(message, MSG_REMOVE_PREFIX, strlen(MSG_REMOVE_PREFIX)) == 0) {
            queue_for_worker(buffer_copy, from_ip);
        } else if (strncmp(message, MSG_NODE_REMOVED, strlen(MSG_NODE_REMOVED)) == 0 || 
                   strncmp(message, MSG_NODE_REMOVE_ABORT, strlen(MSG_NODE_REMOVE_ABORT)) == 0 ||
                   strncmp(message, MSG_PREPARE_FOR_REMOVAL, strlen(MSG_PREPARE_FOR_REMOVAL)) == 0 ||
                   strncmp(message, MSG_PAUSE_HB_ACK, strlen(MSG_PAUSE_HB_ACK)) == 0) {

            queue_for_worker(buffer_copy, from_ip);
        } else if (strncmp(message, MSG_AUTH_REQ, strlen(MSG_AUTH_REQ)) == 0 || 
                   strncmp(message, MSG_AUTH_RESPONSE, strlen(MSG_AUTH_RESPONSE)) == 0 || 
                   strncmp(message, MSG_INITIATE_AUTH_REQ, strlen(MSG_INITIATE_AUTH_REQ)) == 0 || 
                   strncmp(message, MSG_AUTH_FINAL_RESULT, strlen(MSG_AUTH_FINAL_RESULT)) == 0 ||
                   strncmp(message, MSG_ENROLL_KEY, strlen(MSG_ENROLL_KEY)) == 0) {

            auth_puf_queue_message(buffer_copy, from_ip);
        } else if (sscanf(message, MSG_PAUSE_HB_TIMERS ":%lu:%s", &rpc_term, nonce) == 2) {
            if (!is_from_leader(from_ip)) {
                ESP_LOGW(TAG, "%s from non-Coordinator %s ignored.", MSG_PAUSE_HB_TIMERS, from_ip);
                free(buffer_copy);
                return;
            }
            if (!nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "%s command from %s ignored due to invalid or replayed nonce.", MSG_PAUSE_HB_TIMERS, from_ip);
                free(buffer_copy);
                return;
            }

            if (rpc_term == raft_state_get_current_term()) {
                raft_stop_heartbeat_timeout_timer();
                char ack_msg[128];
                snprintf(ack_msg, sizeof(ack_msg), "%s:%lu:%s\n", MSG_PAUSE_HB_ACK, rpc_term, nonce);
                connection_pool_send(from_ip, ack_msg);
            } else {
                ESP_LOGW(TAG, "%s command from leader %s ignored due to term mismatch. MyTerm: %lu, RpcTerm: %lu",
                        MSG_PAUSE_HB_TIMERS, from_ip, raft_state_get_current_term(), rpc_term);
            }
            free(buffer_copy);
        } else if (sscanf(message, MSG_RESUME_HB_TIMERS ":%lu:%s", &rpc_term, nonce) == 2) {
            if (!is_from_leader(from_ip)) {
                ESP_LOGW(TAG, "%s from non-Coordinator %s ignored.", MSG_RESUME_HB_TIMERS, from_ip);
                free(buffer_copy);
                return;
            }
            if (!nonce_is_valid_and_store(nonce)) {
                ESP_LOGW(TAG, "%s command from %s ignored due to invalid or replayed nonce.", MSG_RESUME_HB_TIMERS, from_ip);
                free(buffer_copy);
                return;
            }

            if (rpc_term >= raft_state_get_current_term()) {
                raft_start_heartbeat_timeout_timer();
            } else {
                ESP_LOGW(TAG, "%s command from leader %s ignored due to term mismatch. MyTerm: %lu, RpcTerm: %lu",
                        MSG_RESUME_HB_TIMERS, from_ip, raft_state_get_current_term(), rpc_term);
            }
            free(buffer_copy);
        } else {
            ESP_LOGW(TAG, "Unknown or unparseable message from %s: '%s'", from_ip, message);
            free(buffer_copy);
        }
    }
}

/**
 * @brief Checks if the Raft protocol task and timers have been initialized.
 * @return true if Raft is already running, false otherwise.
 */
bool is_raft_running(void) {
    return is_raft_initialized;
}

/**
 * @brief Initializes the RAFT logic controller and its background tasks.
 * @details This function sets up the server to listen for incoming messages and the orchestrator
 * task to manage time-based events like elections and heartbeats. It should be
 * called after the connection pool has been started.
 * @param peers An array of C-strings containing the IP addresses of all nodes in the cluster.
 * @param num_peers The total number of peers in the array.
 * @return void
 */
void raft_init_with_peers(char **peers, int num_peers) {
    if (is_raft_initialized) {
        ESP_LOGW(TAG, "raft_init_with_peers called but Raft is already running. Ignoring.");
        return;
    }

    raft_state_set_initial_peers(peers, num_peers);

    uint32_t random_initial_timeout = HEARTBEAT_TIMEOUT_MS + (esp_random() % ELECTION_TIMEOUT_RANDOM_WINDOW_MS);
    TimerHandle_t local_heartbeat_timer = xTimerCreate("HeartbeatTimeout", pdMS_TO_TICKS(random_initial_timeout), pdFALSE, (void *)0, heartbeat_timeout_callback);
    TimerHandle_t local_election_timer = xTimerCreate("ElectionTimeout", pdMS_TO_TICKS(ELECTION_TIMEOUT_BASE_MS), pdFALSE, (void *)1, election_timeout_callback);
    heartbeat_sender_timer = xTimerCreate("HeartbeatSender", pdMS_TO_TICKS(HEARTBEAT_INTERVAL_MS), pdTRUE, (void *)2, heartbeat_sender_callback);
    
    raft_state_set_timers(local_election_timer, local_heartbeat_timer);

    if (!local_heartbeat_timer || !local_election_timer || !heartbeat_sender_timer) {
        ESP_LOGE(TAG, "RAFT init failed: Failed to create RAFT timers.");
        return;
    }
    
    
    if (!raft_worker_queue) {
        raft_worker_queue = xQueueCreate(10, sizeof(raft_worker_msg_t));
        xTaskCreate(raft_worker_task, "raft_worker", 5120, NULL, 6, NULL);
    }

    xTimerStart(local_heartbeat_timer, 0);
    if (xTaskCreate(&raft_orchestrator_task, "raft_orchestrator", 4096, NULL, 7, &raft_orchestrator_task_handle) != pdPASS) {
        ESP_LOGE(TAG, "RAFT init failed: could not create the orchestrator task (free heap %u, largest block %u).",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
        return;
    }

    is_raft_initialized = true;
    ESP_LOGI(TAG, "RAFT logic initialized successfully. Free heap %u, largest block %u.",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

/**
 * @brief Public function to externally trigger a new election.
 * @details This function safely notifies the internal RAFT orchestrator task to
 * abandon its current state and start a new election process. It is intended
 * for use by other modules that detect a critical failure, such as a compromised leader.
 * @return void
 */
void raft_force_new_election(void) {
    ESP_LOGW(TAG, "An external module is forcing a new election.");
    notify_orchestrator();
}

/**
 * @brief (Internal) Builds the message that excludes a device.
 */
static void format_blacklist_msg(const char *mac, char *msg, size_t msg_size) {
    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
    snprintf(msg, msg_size, "%s|%s|%s\n", MSG_BLACKLIST_ADD, mac, nonce_hex);
}

void raft_broadcast_blacklist_entry(const char *mac) {
    int peer_count = 0;
    char **peers = raft_state_get_peers_copy(&peer_count);
    if (!peers) return;

    char my_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i], my_ip) != 0) {
            char msg[96];
            format_blacklist_msg(mac, msg, sizeof(msg));
            connection_pool_send(peers[i], msg);
        }
        free(peers[i]);
    }
    free(peers);
}

void raft_send_blacklist_to(const char *target_ip) {
    char (*macs)[MAC_ADDR_STR_LEN] = malloc(MAX_BLACKLIST * MAC_ADDR_STR_LEN);
    if (!macs) return;

    int count = raft_state_get_blacklist(macs, MAX_BLACKLIST);
    for (int i = 0; i < count; i++) {
        char msg[96];
        format_blacklist_msg(macs[i], msg, sizeof(msg));
        connection_pool_send(target_ip, msg);
    }
    free(macs);
}
