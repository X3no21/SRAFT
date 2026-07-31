/* =============================
 * File: raft_state.h
 * Description: Public interface for thread-safe access to the RAFT node state.
 * ============================= */

#ifndef RAFT_STATE_H
#define RAFT_STATE_H

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"
#include "connection_pool.h"
#include <stdint.h>
#include <stdbool.h>
#include <lwip/inet.h>

// ========== RAFT Protocol and Network Configuration ==========
#define HEARTBEAT_INTERVAL_MS 3000
#define HEARTBEAT_TIMEOUT_MS 20000
#define ELECTION_TIMEOUT_RANDOM_WINDOW_MS 4500
#define ELECTION_TIMEOUT_BASE_MS 20000
#define ELECTION_TIMEOUT_BACKOFF_CAP_MS 60000

#define PORT 9000                                   // The default TCP port for RAFT communication.
#define RAFT_LISTEN_BACKLOG 256                     // TCP listen backlog size.

// ========== RAFT RPC Message Prefixes ==========
#define MSG_REQUEST_VOTE "RV"       // RequestVote: RV <term> <candidate_ip> <candidate_mac> <last_log_idx> <last_log_term>
#define MSG_VOTE_GRANTED "VG"       // VoteGranted: VG <term> <voter_ip>
#define MSG_VOTE_DENIED "VD"        // VoteDenied:  VD <term> <voter_ip>
#define MSG_HEARTBEAT "HB"          // Heartbeat:   HB <term> <leader_ip> <leader_mac>
#define MSG_LEADER_ANNOUNCE "LI"    // LeaderIs:    LI <term> <leader_ip> <leader_mac>

#define MAC_ADDR_STR_LEN 18 // "XX:XX:XX:XX:XX:XX\0"

typedef enum {
    FOLLOWER,
    CANDIDATE,
    LEADER
} raft_state_e;

typedef struct {
    raft_state_e state;
    uint32_t current_term;
    char voted_for[INET_ADDRSTRLEN];
    int vote_count;
    uint32_t last_log_index;
    uint32_t last_log_term;
    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    char leader_ip[INET_ADDRSTRLEN];
    char leader_mac[MAC_ADDR_STR_LEN];
    char **peer_ips;
    int peer_count;
    TimerHandle_t heartbeat_timer;
    TimerHandle_t election_timer;
    uint32_t current_election_timeout_ms;
    char blacklisted_macs[10][MAC_ADDR_STR_LEN];
    int blacklist_count;
    TickType_t last_heartbeat_received_at;
} raft_node_t;

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
void raft_state_get_timers(TimerHandle_t *election_timer, TimerHandle_t *heartbeat_timer);

/**
 * @brief Initializes the RAFT state module, including the mutex.
 * @details Must be called once before any other function in this module. It allocates
 * resources and fetches the node's network identifiers.
 * @return void
 */
void raft_state_init(void);

/**
 * @brief Deinitializes the RAFT state module, freeing all resources.
 * @details This function deletes timers, frees allocated memory for the peer list, and
 * deletes the mutex to ensure a clean shutdown.
 * @return void
 */
void raft_state_deinit(void);

/**
 * @brief Atomically checks if a given IP address is in the current Raft peer list.
 * @details This thread-safe function is used to validate if an incoming message is from a
 * recognized member of the Raft cluster, which is crucial during the bootstrap phase
 * before the authentication database is fully populated.
 * @param ip The null-terminated IP address string to check.
 * @return true if the IP is found in the peer list, false otherwise.
 */
bool raft_state_is_peer(const char* ip);

/**
 * @brief Returns the time in milliseconds since the last valid heartbeat was received.
 */
uint32_t raft_state_get_last_heartbeat_age(void);

/**
 * @brief Sets the initial state of the node after discovery.
 * @details This function populates the internal state with the list of discovered peers.
 * It will clear any pre-existing peer list before adding the new one.
 * @param peers An array of C-strings containing the IP addresses of all nodes in the cluster.
 * The function will make its own deep copy of this data.
 * @param num_peers The total number of peers in the array.
 * @return void
 */
void raft_state_set_initial_peers(char **peers, int num_peers);

/**
 * @brief Associates the created FreeRTOS timer handles with the RAFT state.
 * @details This allows the state module to manage the timers (start, stop, change period)
 * as part of its atomic state transition functions.
 * @param election_timer_handle Handle to the election timer.
 * @param heartbeat_timer_handle Handle to the heartbeat timer.
 * @return void
 */
void raft_state_set_timers(TimerHandle_t election_timer_handle, TimerHandle_t heartbeat_timer_handle);

/**
 * @brief Atomically transitions the node to the CANDIDATE state.
 * @details This function increments the term, sets the node to vote for itself, resets the vote
 * count to 1, and starts the election timer with a new randomized timeout.
 * @return The new term number after the transition.
 */
uint32_t raft_state_become_candidate(void);

/**
 * @brief Atomically transitions the node to the FOLLOWER state.
 * @details If the new term is greater than the current term, the node's term is updated and its
 * `voted_for` field is cleared. It always stops the election timer (if active) and
 * starts the heartbeat timer.
 * @param new_term The term to adopt.
 * @return void
 */
void raft_state_become_follower(uint32_t new_term);

/**
 * @brief Atomically transitions the node to the LEADER state.
 * @details This function sets the node's state to LEADER, records its own IP and MAC as the
 * leader's, and stops both the election and heartbeat timers.
 * @return void
 */
void raft_state_become_leader(void);

/**
 * @brief Gets the current state of the RAFT node.
 * @return The current state as a raft_state_e enum value (FOLLOWER, CANDIDATE, or LEADER).
 */
raft_state_e raft_state_get_state(void);

/**
 * @brief Gets the current term of the RAFT node.
 * @return The current term number as a uint32_t.
 */
uint32_t raft_state_get_current_term(void);

/**
 * @brief Gets a copy of the current leader's information (IP and MAC address).
 * @param leader_ip_buf A character buffer to store the leader's IP address.
 * @param ip_buf_size The size of the leader_ip_buf.
 * @param leader_mac_buf A character buffer to store the leader's MAC address.
 * @param mac_buf_size The size of the leader_mac_buf.
 * @return true if a leader exists and its information was successfully copied, false otherwise.
 */
bool raft_state_get_leader_info(char* leader_ip_buf, size_t ip_buf_size, char* leader_mac_buf, size_t mac_buf_size);

/**
 * @brief Gets a copy of this node's own IP and MAC address.
 * @param my_ip_buf A character buffer to store the node's IP address.
 * @param ip_buf_size The size of the my_ip_buf.
 * @param my_mac_buf A character buffer to store the node's MAC address. Can be NULL if not needed.
 * @param mac_buf_size The size of the my_mac_buf.
 * @return void
 */
void raft_state_get_self_info(char* my_ip_buf, size_t ip_buf_size, char* my_mac_buf, size_t mac_buf_size);

/**
 * @brief Gets a thread-safe deep copy of the peer list and its count.
 * @param peer_count A pointer to an integer where the number of discovered peers will be stored.
 * @return A dynamically allocated array of C-strings. The caller is responsible for
 * freeing the outer array and each individual string within it. Returns NULL on failure.
 */
char** raft_state_get_peers_copy(int* peer_count);

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
bool raft_state_handle_request_vote(uint32_t rpc_term, const char* rpc_candidate_ip, const char* rpc_candidate_mac, uint32_t rpc_last_log_index, uint32_t rpc_last_log_term);

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
void raft_state_handle_heartbeat(uint32_t rpc_term, const char* rpc_leader_ip, const char* rpc_leader_mac);

/**
 * @brief Atomically increments the vote count for the current node.
 * @return The new vote count after incrementing.
 */
int raft_state_increment_vote_count(void);

/**
 * @brief Gets the current vote count for a candidate node.
 * @return The number of votes received in the current term.
 */
int raft_state_get_vote_count(void);

/**
 * @brief Gets a copy of the IP address the node voted for in the current term.
 * @param voted_for_buf A character buffer to store the IP address.
 * @param buf_size The size of the buffer.
 * @return void
 */
void raft_state_get_voted_for(char* voted_for_buf, size_t buf_size);

/**
 * @brief Gets the node's latest log metadata (simulated).
 * @param last_log_index A pointer to a uint32_t to store the last log index.
 * @param last_log_term A pointer to a uint32_t to store the last log term.
 * @return void
 */
void raft_state_get_log_info(uint32_t* last_log_index, uint32_t* last_log_term);

/**
 * @brief Adds a MAC address to the blacklist to prevent it from being voted for.
 * @param mac_to_blacklist The null-terminated MAC address string to add.
 * @return void
 */
void raft_state_blacklist_mac(const char* mac_to_blacklist);

/**
 * @brief Atomically increases the election timeout for exponential backoff.
 * @details This function is called when a candidate's election timer expires.
 * It doubles the base election timeout period, up to a predefined maximum
 * (ELECTION_TIMEOUT_BACKOFF_CAP_MS), to reduce network contention and the probability
 * of split votes in subsequent election rounds. The operation is thread-safe.
 * @return void
 */
void raft_state_increase_election_timeout(void);

/**
 * @brief Atomically resets the election timeout to its default base value.
 * @details This function is called when an election cycle concludes successfully
 * (e.g., a leader is elected or discovered via heartbeat). It restores the
 * current_election_timeout_ms to ELECTION_TIMEOUT_BASE_MS to ensure that future
 * elections start with a normal, shorter timeout. The operation is thread-safe.
 * @return void
 */
void raft_state_reset_election_timeout(void);

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
void raft_state_add_peer(const char* peer_ip);

/**
 * @brief Atomically removes a peer from the RAFT state's peer list.
 * @details This function is designed to be called when a node is confirmed to have been 
 * removed from the cluster. It safely finds and removes the peer's IP address from the 
 * internal list used for calculating the election quorum, ensuring future elections 
 * are based on the correct cluster size. The operation is thread-safe.
 * @param peer_ip The null-terminated IP address string of the peer to remove.
 * @return void
 */
void raft_state_remove_peer(const char* peer_ip);

/**
 * @brief Safely updates the peer list of an already running Raft instance.
 * @param new_peers An array of C-strings containing the new list of peer IPs.
 * @param num_peers The number of peers in the new list.
 */
void raft_state_update_peers(char **new_peers, int num_peers);

/**
 * @brief Atomically stops the follower's heartbeat timeout timer.
 * @details This function is called on a follower node when it receives a command 
 * from the leader to enter a 'maintenance mode'. Stopping this timer prevents the 
 * follower from timing out and attempting to start a new election while the leader 
 * is performing a long-running, critical operation (e.g., cluster healing after a 
 * node removal). The operation is thread-safe.
 * @return void
 */
void raft_stop_heartbeat_timeout_timer(void);

/**
 * @brief Atomically resets and restarts the follower's heartbeat timeout timer.
 * @details This function is called on a follower node when it receives a command 
 * from the leader to exit 'maintenance mode'. It resets the timer, effectively 
 * restarting the follower's election clock. This ensures the node returns to its 
 * normal state of expecting heartbeats from the leader to maintain cluster 
 * stability. The operation is thread-safe.
 * @return void
 */
void raft_start_heartbeat_timeout_timer(void);

#endif // RAFT_STATE_H