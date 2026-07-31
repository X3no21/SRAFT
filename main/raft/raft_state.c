/* =============================
 * File: raft_state.c
 * Description: Manages the RAFT node's state with thread-safe functions.
 * ============================= */

#include "raft_state.h"
#include "rest_api.h"
#include "utility.h"
#include "integrity_verification.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include "freertos/timers.h"

static const char *TAG = "RAFT_STATE";

static raft_node_t node;
static SemaphoreHandle_t raft_state_mutex = NULL;

#define TAKE_RAFT_STATE_MUTEX(func_name) do { \
    ESP_LOGD("RAFT_MUTEX", "Attempting to take lock in %s", func_name); \
    xSemaphoreTake(raft_state_mutex, portMAX_DELAY); \
    ESP_LOGD("RAFT_MUTEX", ">> Lock TAKEN in %s", func_name); \
} while(0)

#define GIVE_RAFT_STATE_MUTEX(func_name) do { \
    ESP_LOGD("RAFT_MUTEX", "<< Lock GIVEN in %s", func_name); \
    xSemaphoreGive(raft_state_mutex); \
} while(0)

void __raft_state_reset_election_timeout_unsafe(void);

/**
 * @brief Atomically retrieves the handles for the core Raft state timers.
 * @details This thread-safe accessor function allows external modules to get the handles 
 * for the follower's heartbeat timeout timer and the candidate's election timer. It is 
 * primarily used during a controlled shutdown sequence to stop the timers cleanly.
 * @param election_timer A pointer to a TimerHandle_t variable where the election 
 * timer handle will be stored.
 * @param heartbeat_timer A pointer to a TimerHandle_t variable where the heartbeat 
 * timeout timer handle will be stored.
 * @return void
 */
void raft_state_get_timers(TimerHandle_t *election_timer, TimerHandle_t *heartbeat_timer) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    *election_timer = node.election_timer;
    *heartbeat_timer = node.heartbeat_timer;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Atomically stops the follower's heartbeat timeout timer.
 * @details This function is called on a follower node when it receives a command 
 * from the leader to enter a 'maintenance mode'. Stopping this timer prevents the 
 * follower from timing out and attempting to start a new election while the leader 
 * is performing a long-running, critical operation (e.g., cluster healing after a 
 * node removal). The operation is thread-safe.
 * @return void
 */
void raft_stop_heartbeat_timeout_timer(void) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    if (node.heartbeat_timer && xTimerIsTimerActive(node.heartbeat_timer)) {
        xTimerStop(node.heartbeat_timer, 0);
        ESP_LOGW(TAG, "Heartbeat timeout timer PAUSED by leader's command.");
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Atomically resets and restarts the follower's heartbeat timeout timer.
 * @details This function is called on a follower node when it receives a command 
 * from the leader to exit 'maintenance mode'. It resets the timer, effectively 
 * restarting the follower's election clock. This ensures the node returns to its 
 * normal state of expecting heartbeats from the leader to maintain cluster 
 * stability. The operation is thread-safe.
 * @return void
 */
void raft_start_heartbeat_timeout_timer(void) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    if (node.heartbeat_timer) {
        xTimerReset(node.heartbeat_timer, 0);
        ESP_LOGI(TAG, "Heartbeat timeout timer RESUMED by leader's command.");
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Fetches the node's own IP and MAC address and stores them in the state.
 * @return void
 */
static void fetch_own_info() {
    esp_netif_ip_info_t ip_info;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif != NULL && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        inet_ntop(AF_INET, &ip_info.ip, node.my_ip, sizeof(node.my_ip));
    } else {
        strcpy(node.my_ip, "0.0.0.0");
    }

    uint8_t mac_addr[6];
    esp_read_mac(mac_addr, ESP_MAC_WIFI_STA);
    snprintf(node.my_mac, sizeof(node.my_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

/**
 * @brief Initializes the RAFT state module, including the mutex.
 * @details Must be called once before any other function in this module. It allocates
 * resources and fetches the node's network identifiers.
 * @return void
 */
void raft_state_init(void) {
    ESP_LOGI(TAG, "Initializing Node RAST_STATE Module...");
    if (raft_state_mutex == NULL) {
        raft_state_mutex = xSemaphoreCreateMutex();
    }
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    memset(&node, 0, sizeof(raft_node_t));
    if (node.state != FOLLOWER) {
        ESP_LOGI(TAG, "State change: -> FOLLOWER (Term: %lu)", node.current_term);
    }
    node.state = FOLLOWER;
    node.current_election_timeout_ms = ELECTION_TIMEOUT_BASE_MS;
    fetch_own_info();
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Deinitializes the RAFT state module, freeing all resources.
 * @details This function deletes timers, frees allocated memory for the peer list, and
 * deletes the mutex to ensure a clean shutdown.
 * @return void
 */
void raft_state_deinit(void) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    if (node.election_timer) {
        xTimerDelete(node.election_timer, pdMS_TO_TICKS(100));
        node.election_timer = NULL;
    }
    if (node.heartbeat_timer) {
        xTimerDelete(node.heartbeat_timer, pdMS_TO_TICKS(100));
        node.heartbeat_timer = NULL;
    }

    if (node.peer_ips != NULL) {
        for (int i = 0; i < node.peer_count; i++) {
            if (node.peer_ips[i] != NULL)
                free(node.peer_ips[i]);
        }
        free(node.peer_ips);
        node.peer_ips = NULL;
    }
    memset(&node, 0, sizeof(raft_node_t));
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Sets the initial state of the node after discovery.
 * @details This function populates the internal state with the list of discovered peers.
 * It will clear any pre-existing peer list before adding the new one.
 * @param peers An array of C-strings containing the IP addresses of all nodes in the cluster.
 * The function will make its own deep copy of this data.
 * @param num_peers The total number of peers in the array.
 * @return void
 */
void raft_state_set_initial_peers(char **peers, int num_peers) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    if (node.peer_ips) {
        for (int i = 0; i < node.peer_count; i++)
            free(node.peer_ips[i]);
        free(node.peer_ips);
    }

    node.peer_ips = malloc(sizeof(char *) * num_peers);
    if (!node.peer_ips) {
        node.peer_count = 0;
    } else {
        node.peer_count = 0;
        for (int i = 0; i < num_peers; i++) {
            if (peers[i] && strlen(peers[i]) > 0) {
                node.peer_ips[node.peer_count] = strdup(peers[i]);
                if (node.peer_ips[node.peer_count]) {
                    node.peer_count++;
                }
            }
        }
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Associates the created FreeRTOS timer handles with the RAFT state.
 * @details This allows the state module to manage the timers (start, stop, change period)
 * as part of its atomic state transition functions.
 * @param election_timer_handle Handle to the election timer.
 * @param heartbeat_timer_handle Handle to the heartbeat timer.
 * @return void
 */
void raft_state_set_timers(TimerHandle_t election_timer_handle, TimerHandle_t heartbeat_timer_handle) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    node.election_timer = election_timer_handle;
    node.heartbeat_timer = heartbeat_timer_handle;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief NOT atomically transitions the node to the CANDIDATE state.
 * @details This function increments the term, sets the node to vote for itself, resets the vote
 * count to 1, and starts the election timer with a new randomized timeout.
 * @return The new term number after the transition.
 */
uint32_t __raft_state_become_candidate_unsafe(void) {
    uint32_t new_term = 0;
    if (node.heartbeat_timer && xTimerIsTimerActive(node.heartbeat_timer)) {
        xTimerStop(node.heartbeat_timer, 0);
    }

    node.state = CANDIDATE;
    node.current_term++;
    ESP_LOGI(TAG, "State change: -> CANDIDATE (Term: %lu)", node.current_term); 

    strncpy(node.voted_for, node.my_ip, sizeof(node.voted_for) - 1);
    node.voted_for[sizeof(node.voted_for) - 1] = '\0';
    node.vote_count = 1;
    strcpy(node.leader_ip, "");
    strcpy(node.leader_mac, "");
    new_term = node.current_term;

    if (node.election_timer) {
        uint32_t random_election_timeout_ms = node.current_election_timeout_ms + (esp_random() % ELECTION_TIMEOUT_RANDOM_WINDOW_MS);
        xTimerChangePeriod(node.election_timer, pdMS_TO_TICKS(random_election_timeout_ms), 0);
        xTimerStart(node.election_timer, 0);
    }
    return new_term;
}

/**
 * @brief Atomically transitions the node to the CANDIDATE state.
 * @details This function increments the term, sets the node to vote for itself, resets the vote
 * count to 1, and starts the election timer with a new randomized timeout.
 * @return The new term number after the transition.
 */
uint32_t raft_state_become_candidate(void) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    uint32_t new_term = __raft_state_become_candidate_unsafe();
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return new_term;
}

/**
 * @brief NOT atomically transitions the node to the FOLLOWER state.
 * @details If the new term is greater than the current term, the node's term is updated and its
 * `voted_for` field is cleared. It always stops the election timer (if active) and
 * starts the heartbeat timer.
 * @param new_term The term to adopt.
 * @return void
 */
void __raft_state_become_follower_unsafe(uint32_t new_term) {
    if (node.state == CANDIDATE) {
        char *event_msg = malloc(MAX_MESSAGE_SIZE);
        if (!event_msg) {
            ESP_LOGE(TAG, "Failed to allocate memory for message copy in raft handler.");
            return;
        }
        snprintf(event_msg, MAX_MESSAGE_SIZE, "CANDIDATE_STEPDOWN:%lu:%s", node.current_term, node.my_ip);
        send_monitoring_tcp_event(event_msg);
        free(event_msg);
    }

    if (node.state != FOLLOWER) {
        ESP_LOGI(TAG, "State change: -> FOLLOWER (Term: %lu)", new_term);
    }

    node.state = FOLLOWER;
    if (new_term > node.current_term) {
        node.current_term = new_term;
        strcpy(node.voted_for, "");
    }

    if (node.election_timer && xTimerIsTimerActive(node.election_timer)) {
        xTimerStop(node.election_timer, 0);
    }

    if (node.heartbeat_timer) {
        xTimerChangePeriod(node.heartbeat_timer, pdMS_TO_TICKS(HEARTBEAT_TIMEOUT_MS), 0);
        xTimerStart(node.heartbeat_timer, 0);
    }
    node.last_heartbeat_received_at = xTaskGetTickCount();
}

/**
 * @brief Atomically transitions the node to the FOLLOWER state.
 * @details If the new term is greater than the current term, the node's term is updated and its
 * `voted_for` field is cleared. It always stops the election timer (if active) and
 * starts the heartbeat timer.
 * @param new_term The term to adopt.
 * @return void
 */
void raft_state_become_follower(uint32_t new_term) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    __raft_state_become_follower_unsafe(new_term);
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief NOT atomically transitions the node to the LEADER state.
 * @details This function sets the node's state to LEADER, records its own IP and MAC as the
 * leader's, and stops both the election and heartbeat timers.
 * @return void
 */
void __raft_state_become_leader_unsafe(void) {
    node.state = LEADER;
    ESP_LOGI(TAG, "State change: -> LEADER (Term: %lu)", node.current_term);
    strncpy(node.leader_ip, node.my_ip, sizeof(node.leader_ip) - 1);
    node.leader_ip[sizeof(node.leader_ip) - 1] = '\0';
    strncpy(node.leader_mac, node.my_mac, sizeof(node.leader_mac) - 1);
    node.leader_mac[sizeof(node.leader_mac) - 1] = '\0';
    
    node.current_election_timeout_ms = ELECTION_TIMEOUT_BASE_MS;

    if (node.election_timer && xTimerIsTimerActive(node.election_timer)) {
        xTimerStop(node.election_timer, 0);
    }
    if (node.heartbeat_timer && xTimerIsTimerActive(node.heartbeat_timer)) {
        xTimerStop(node.heartbeat_timer, 0);
    }
}

/**
 * @brief Atomically transitions the node to the LEADER state.
 * @details This function sets the node's state to LEADER, records its own IP and MAC as the
 * leader's, and stops both the election and heartbeat timers.
 * @return void
 */
void raft_state_become_leader(void) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    __raft_state_become_leader_unsafe();
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Gets the current state of the RAFT node.
 * @return The current state as a raft_state_e enum value (FOLLOWER, CANDIDATE, or LEADER).
 */
raft_state_e raft_state_get_state(void) {
    raft_state_e current_state = FOLLOWER;
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    current_state = node.state;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return current_state;
}

/**
 * @brief Gets the current term of the RAFT node.
 * @return The current term number as a uint32_t.
 */
uint32_t raft_state_get_current_term(void) {
    uint32_t term = 0;
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
        term = node.current_term;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return term;
}

/**
 * @brief Gets a copy of the current leader's information (IP and MAC address).
 * @param leader_ip_buf A character buffer to store the leader's IP address.
 * @param ip_buf_size The size of the leader_ip_buf.
 * @param leader_mac_buf A character buffer to store the leader's MAC address.
 * @param mac_buf_size The size of the leader_mac_buf.
 * @return true if a leader exists and its information was successfully copied, false otherwise.
 */
bool raft_state_get_leader_info(char *leader_ip_buf, size_t ip_buf_size, char *leader_mac_buf, size_t mac_buf_size) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    bool has_leader = false;
    if (strlen(node.leader_ip) > 0) {
        strncpy(leader_ip_buf, node.leader_ip, ip_buf_size - 1);
        leader_ip_buf[ip_buf_size - 1] = '\0';

        if (leader_mac_buf != NULL && mac_buf_size > 0) {
            strncpy(leader_mac_buf, node.leader_mac, mac_buf_size - 1);
            leader_mac_buf[mac_buf_size - 1] = '\0';
        }
        
        has_leader = true;
    } else {
        leader_ip_buf[0] = '\0';
        if (leader_mac_buf != NULL && mac_buf_size > 0) {
            leader_mac_buf[0] = '\0';
        }
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return has_leader;
}

/**
 * @brief Gets a copy of this node's own IP and MAC address.
 * @param my_ip_buf A character buffer to store the node's IP address.
 * @param ip_buf_size The size of the my_ip_buf.
 * @param my_mac_buf A character buffer to store the node's MAC address. Can be NULL if not needed.
 * @param mac_buf_size The size of the my_mac_buf.
 * @return void
 */
void raft_state_get_self_info(char *my_ip_buf, size_t ip_buf_size, char *my_mac_buf, size_t mac_buf_size) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    strncpy(my_ip_buf, node.my_ip, ip_buf_size - 1);
    my_ip_buf[ip_buf_size - 1] = '\0';
    if (my_mac_buf && mac_buf_size > 0) {
        strncpy(my_mac_buf, node.my_mac, mac_buf_size - 1);
        my_mac_buf[mac_buf_size - 1] = '\0';
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Gets a thread-safe deep copy of the peer list and its count.
 * @param peer_count A pointer to an integer where the number of discovered peers will be stored.
 * @return A dynamically allocated array of C-strings. The caller is responsible for
 * freeing the outer array and each individual string within it. Returns NULL on failure.
 */
char **raft_state_get_peers_copy(int *peer_count) {
    char **peer_list_copy = NULL;
    *peer_count = 0;
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    if (node.peer_count > 0 && node.peer_ips) {
        peer_list_copy = malloc(sizeof(char *) * node.peer_count);
        if (peer_list_copy) {
            int valid_peers = 0;
            for (int i = 0; i < node.peer_count; i++) {
                peer_list_copy[i] = strdup(node.peer_ips[i]);
                if (peer_list_copy[i] == NULL) {
                    for (int j = 0; j < i; j++) {
                        free(peer_list_copy[j]);
                    }
                    free(peer_list_copy);
                    peer_list_copy = NULL;
                    valid_peers = 0;
                    break;
                }
                valid_peers++;
            }
            *peer_count = valid_peers;
        }
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return peer_list_copy;
}

/**
 * @brief Atomically handles a RequestVote RPC.
 * @details This function contains the core logic for deciding whether to grant a vote,
 * including a check against the MAC address blacklist. It strictly follows RAFT rules.
 * @param rpc_term The term from the incoming RPC.
 * @param rpc_candidate_ip The IP of the candidate requesting the vote.
 * @param rpc_candidate_mac The MAC address of the candidate.
 * @param rpc_last_log_index The last log index from the candidate's log.
 * @param rpc_last_log_term The last log term from the candidate's log.
 * @param[out] vote_granted A pointer to a bool which is set to true if the vote is granted, false otherwise.
 * @return The node's current term after processing the request.
 */
bool raft_state_handle_request_vote(uint32_t rpc_term, const char* rpc_candidate_ip, const char* rpc_candidate_mac, uint32_t rpc_last_log_index, uint32_t rpc_last_log_term) {
    bool vote_granted = false;
    bool term_updated = false;

    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    if (rpc_term < node.current_term) {
        ESP_LOGW(TAG, "Vote DENIED to %s: their term %lu is older than current term %lu.", rpc_candidate_ip, rpc_term, node.current_term);
        GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
        return false;
    } else if (rpc_term > node.current_term) {
        ESP_LOGI(TAG, "Received RV from %s with higher term %lu (current: %lu). Becoming follower.", rpc_candidate_ip, rpc_term, node.current_term);
        __raft_state_become_follower_unsafe(rpc_term);
        term_updated = true;
    }

    bool is_blacklisted = false;
    for (int i = 0; i < node.blacklist_count; i++) {
        if (strcmp(node.blacklisted_macs[i], rpc_candidate_mac) == 0) {
            is_blacklisted = true;
            break;
        }
    }

    if (is_blacklisted) {
        ESP_LOGE(TAG, "Vote DENIED to %s (MAC: %s): Candidate MAC is blacklisted.", rpc_candidate_ip, rpc_candidate_mac);
        GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
        return false;
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);

    ESP_LOGI(TAG, "Received vote request from %s. Performing integrity check before voting...", rpc_candidate_ip);
    bool is_honest = integrity_verification_run_single(rpc_candidate_ip, rpc_candidate_mac);

    if (!is_honest) {
        ESP_LOGE(TAG, "Vote DENIED to %s for term %lu: FAILED integrity check.", rpc_candidate_ip, rpc_term);
        char my_mac[MAC_ADDR_STR_LEN];
        get_my_mac(my_mac, sizeof(my_mac));
        char event_msg[128];
        snprintf(event_msg, sizeof(event_msg), "INTEGRITY_CHECK_FAILED:%s:%s", rpc_candidate_mac, my_mac);
        send_monitoring_tcp_event(event_msg);
        return false;
    }
    ESP_LOGI(TAG, "Integrity check PASSED for candidate %s.", rpc_candidate_ip);
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);

    if (rpc_term < node.current_term) {
         ESP_LOGW(TAG, "Vote DENIED to %s: term %lu became stale during checks (current: %lu).", rpc_candidate_ip, rpc_term, node.current_term);
         GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
         return false;
    }
    
    if (rpc_term > node.current_term && !term_updated) {
         ESP_LOGI(TAG, "Term %lu became current during integrity check. Becoming follower before voting check.", rpc_term);
        __raft_state_become_follower_unsafe(rpc_term);
        term_updated = true;
    }
    
    bool log_is_ok = (rpc_last_log_term > node.last_log_term) || 
                     (rpc_last_log_term == node.last_log_term && rpc_last_log_index >= node.last_log_index);
    
    bool can_vote = (strlen(node.voted_for) == 0) || (strcmp(node.voted_for, rpc_candidate_ip) == 0);

    if (rpc_term == node.current_term && log_is_ok && can_vote) {
        if (node.state == FOLLOWER || node.state == CANDIDATE) {
            strncpy(node.voted_for, rpc_candidate_ip, sizeof(node.voted_for) - 1);
            node.voted_for[sizeof(node.voted_for) - 1] = '\0';
            
            ESP_LOGI(TAG, "Vote GRANTED to %s for term %lu", rpc_candidate_ip, node.current_term);
            vote_granted = true;

            if (node.state == FOLLOWER && node.heartbeat_timer) {
                xTimerReset(node.heartbeat_timer, 0);
            }
        } else {
            ESP_LOGW(TAG, "Vote DENIED to %s for term %lu: Currently LEADER.", rpc_candidate_ip, rpc_term);
        }
    } else {
        if (rpc_term != node.current_term) {
             ESP_LOGW(TAG, "Vote DENIED to %s: Term mismatch (%lu vs current %lu) after integrity check.", rpc_candidate_ip, rpc_term, node.current_term);
        } else if (!log_is_ok) {
            ESP_LOGW(TAG, "Vote DENIED to %s for term %lu: Candidate's log is not up-to-date.", rpc_candidate_ip, rpc_term);
        } else if (!can_vote) {
             ESP_LOGW(TAG, "Vote DENIED to %s for term %lu: Already voted for %s in this term.", rpc_candidate_ip, rpc_term, node.voted_for);
        }
    }
    
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return vote_granted;
}

/**
 * @brief Atomically handles a Heartbeat or LeaderAnnounce RPC.
 * @details If the message's term is valid, it updates the node's state to FOLLOWER,
 * records the leader's identity, and resets the heartbeat timer. It also cancels
 * any ongoing voting grace period.
 * @param rpc_term The term from the incoming RPC.
 * @param rpc_leader_ip The IP of the leader sending the message.
 * @param rpc_leader_mac The MAC address of the leader sending the message.
 * @return void
 */
void raft_state_handle_heartbeat(uint32_t rpc_term, const char *rpc_leader_ip, const char *rpc_leader_mac) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    
    if (rpc_term >= node.current_term) {
        if (rpc_term > node.current_term || node.state != FOLLOWER) {
            __raft_state_become_follower_unsafe(rpc_term);
        }

        strncpy(node.leader_ip, rpc_leader_ip, sizeof(node.leader_ip) - 1);
        node.leader_ip[sizeof(node.leader_ip) - 1] = '\0';
        strncpy(node.leader_mac, rpc_leader_mac, sizeof(node.leader_mac) - 1);
        node.leader_mac[sizeof(node.leader_mac) - 1] = '\0';

        if (node.heartbeat_timer) {
            xTimerReset(node.heartbeat_timer, 0);
        }
        node.last_heartbeat_received_at = xTaskGetTickCount();
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Atomically increments the vote count for the current node.
 * @return The new vote count after incrementing.
 */
int raft_state_increment_vote_count(void) {
    int new_count = 0;
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    node.vote_count++;
    new_count = node.vote_count;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return new_count;
}

/**
 * @brief Gets the current vote count for a candidate node.
 * @return The number of votes received in the current term.
 */
int raft_state_get_vote_count(void) {
    int count = 0;
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    count = node.vote_count;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return count;
}

/**
 * @brief Gets a copy of the IP address the node voted for in the current term.
 * @param voted_for_buf A character buffer to store the IP address.
 * @param buf_size The size of the buffer.
 * @return void
 */
void raft_state_get_voted_for(char *voted_for_buf, size_t buf_size) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    strncpy(voted_for_buf, node.voted_for, buf_size - 1);
    voted_for_buf[buf_size - 1] = '\0';
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Gets the node's latest log metadata (simulated).
 * @param last_log_index A pointer to a uint32_t to store the last log index.
 * @param last_log_term A pointer to a uint32_t to store the last log term.
 * @return void
 */
void raft_state_get_log_info(uint32_t *last_log_index, uint32_t *last_log_term) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    *last_log_index = node.last_log_index;
    *last_log_term = node.last_log_term;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Adds a MAC address to the blacklist to prevent it from being voted for.
 * @param mac_to_blacklist The null-terminated MAC address string to add.
 * @return void
 */
void raft_state_blacklist_mac(const char *mac_to_blacklist) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    if (node.blacklist_count < 10) {
        bool already_exists = false;
        for (int i = 0; i < node.blacklist_count; i++) {
            if (strcmp(node.blacklisted_macs[i], mac_to_blacklist) == 0) {
                already_exists = true;
                break;
            }
        }
        if (!already_exists) {
            strncpy(node.blacklisted_macs[node.blacklist_count], mac_to_blacklist, MAC_ADDR_STR_LEN - 1);
            node.blacklisted_macs[node.blacklist_count][MAC_ADDR_STR_LEN - 1] = '\0';
            node.blacklist_count++;
            ESP_LOGW(TAG, "MAC address %s has been added to the blacklist.", mac_to_blacklist);
        }
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Aumenta atomicamente il timeout di elezione per il backoff esponenziale.
 * @details Questa funzione viene chiamata quando il timer di elezione di un candidato scade.
 * Raddoppia il periodo di timeout base per l'elezione, fino a un massimo predefinito
 * (ELECTION_TIMEOUT_BACKOFF_CAP_MS), per ridurre la contesa sulla rete e la probabilità
 * di voti divisi nei round di elezione successivi. L'operazione è thread-safe.
 * @return void
 */
void raft_state_increase_election_timeout(void) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    node.current_election_timeout_ms *= 2;
    if (node.current_election_timeout_ms > ELECTION_TIMEOUT_BACKOFF_CAP_MS) {
        node.current_election_timeout_ms = ELECTION_TIMEOUT_BACKOFF_CAP_MS;
    }
    ESP_LOGW(TAG, "Election backoff: new base timeout is %lu ms", node.current_election_timeout_ms);
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief NOT atomically resets the election timeout to its default base value.
 * @details This function is called when an election cycle concludes successfully
 * (e.g., a leader is elected or discovered via heartbeat). It restores the
 * current_election_timeout_ms to ELECTION_TIMEOUT_BASE_MS to ensure that future
 * elections start with a normal, shorter timeout. The operation is thread-safe.
 * @return void
 */
void __raft_state_reset_election_timeout_unsafe(void) {
    node.current_election_timeout_ms = ELECTION_TIMEOUT_BASE_MS;
}

/**
 * @brief Atomically resets the election timeout to its default base value.
 * @details This function is called when an election cycle concludes successfully
 * (e.g., a leader is elected or discovered via heartbeat). It restores the
 * current_election_timeout_ms to ELECTION_TIMEOUT_BASE_MS to ensure that future
 * elections start with a normal, shorter timeout. The operation is thread-safe.
 * @return void
 */
void raft_state_reset_election_timeout(void) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    __raft_state_reset_election_timeout_unsafe();
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Atomically adds a new peer to the RAFT state's peer list.
 * @details This function is designed to be called when a new peer is discovered
 * on the network. It safely adds the peer's IP address to the internal list
 * used for calculating the election quorum. The operation is thread-safe and
 * handles dynamic memory reallocation of the peer list. It ensures a peer is
 * not added more than once.
 * @param peer_ip The null-terminated IP address string of the new peer to add.
 * @return void
 */
void raft_state_add_peer(const char* peer_ip) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    for (int i = 0; i < node.peer_count; i++) {
        if (strcmp(node.peer_ips[i], peer_ip) == 0) {
            GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
            return;
        }
    }

    char** new_list = realloc(node.peer_ips, sizeof(char*) * (node.peer_count + 1));
    if (new_list) {
        node.peer_ips = new_list;
        node.peer_ips[node.peer_count] = strdup(peer_ip);
        node.peer_count++;
        ESP_LOGI(TAG, "Peer %s added to RAFT state. Total peers for quorum: %d", peer_ip, node.peer_count);
    } else {
        ESP_LOGE(TAG, "Failed to reallocate memory for new RAFT peer!");
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Atomically removes a peer from the RAFT state's peer list.
 * @details This function is designed to be called when a node is confirmed to have been 
 * removed from the cluster. It safely finds and removes the peer's IP address from the 
 * internal list used for calculating the election quorum, ensuring future elections 
 * are based on the correct cluster size. The operation is thread-safe.
 * @param peer_ip The null-terminated IP address string of the peer to remove.
 * @return void
 */
void raft_state_remove_peer(const char* peer_ip) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    int found_index = -1;
    for (int i = 0; i < node.peer_count; i++) {
        if (strcmp(node.peer_ips[i], peer_ip) == 0) {
            found_index = i;
            break;
        }
    }

    if (found_index != -1) {
        free(node.peer_ips[found_index]);
        for (int i = found_index; i < node.peer_count - 1; i++) {
            node.peer_ips[i] = node.peer_ips[i + 1];
        }
        node.peer_count--;
        if (node.peer_count > 0) {
            char** new_list = realloc(node.peer_ips, sizeof(char*) * node.peer_count);
            if (new_list) {
                node.peer_ips = new_list;
            }
        } else {
            free(node.peer_ips);
            node.peer_ips = NULL;
        }
        ESP_LOGI(TAG, "Peer %s removed from RAFT state. New quorum size: %d", peer_ip, node.peer_count);
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
}

/**
 * @brief Safely updates the peer list of an already running Raft instance.
 * @param new_peers An array of C-strings containing the new list of peer IPs.
 * @param num_peers The number of peers in the new list.
 */
void raft_state_update_peers(char **peers, int num_peers) {
    ESP_LOGI(TAG, "Updating Raft peer list with %d peers.", num_peers);
    raft_state_set_initial_peers(peers, num_peers);
}

/**
 * @brief Atomically checks if a given IP address is in the current Raft peer list.
 * @details This thread-safe function is used to validate if an incoming message is from a
 * recognized member of the Raft cluster, which is crucial during the bootstrap phase
 * before the authentication database is fully populated.
 * @param ip The null-terminated IP address string to check.
 * @return true if the IP is found in the peer list, false otherwise.
 */
bool raft_state_is_peer(const char* ip) {
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    bool found = false;
    if (ip) {
        for (int i = 0; i < node.peer_count; i++) {
            if (strcmp(node.peer_ips[i], ip) == 0) {
                found = true;
                break;
            }
        }
    }
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    return found;
}

/**
 * @brief Returns the time in milliseconds since the last valid heartbeat was received.
 */
uint32_t raft_state_get_last_heartbeat_age(void) {
    TickType_t last_tick;
    TAKE_RAFT_STATE_MUTEX(__FUNCTION__);
    last_tick = node.last_heartbeat_received_at;
    GIVE_RAFT_STATE_MUTEX(__FUNCTION__);
    
    return pdTICKS_TO_MS(xTaskGetTickCount() - last_tick);
}