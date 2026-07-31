/* =============================
 * File: auth_remove.h
 * Description: Public interface for the self-healing node removal logic.
 * ============================= */

#ifndef AUTH_REMOVE_H
#define AUTH_REMOVE_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <stdint.h>

#define VERIFIER_TARGET_PERCENTAGE 0.3f
#define HEAL_THRESHOLD_PERCENTAGE 0.2f
#define SINGLE_ACK_TIMEOUT_MS 20000 
#define REMOVAL_ACK_TIMEOUT_MS 60000

#define MSG_NODE_REMOVED "NODE_REMOVED"
#define MSG_NODE_REMOVED_ACK "NODE_REMOVED_ACK"
#define MSG_NODE_REMOVE_ABORT "NODE_REMOVE_ABORT"
#define MSG_PREPARE_FOR_REMOVAL "PREPARE_REMOVE"

#define MSG_PAUSE_HB_TIMERS "PAUSE_TIMERS"
#define MSG_PAUSE_HB_ACK "PAUSE_ACK"
#define MSG_RESUME_HB_TIMERS "RESUME_TIMERS"

#define MAX_PENDING_REMOVALS 32

/**
 * @brief Holds the state for a single, ongoing node removal process on the leader.
 */
typedef struct {
    bool is_active;
    uint32_t transaction_id;
    char removed_node_ip[INET_ADDRSTRLEN];
    int maintenance_ack_count;
    int removal_ack_count;
} RemovalProcess;

extern QueueHandle_t remove_request_queue;
extern SemaphoreHandle_t remove_result_semaphore;
extern bool remove_result_success;

/**
 * @brief Initializes the synchronization primitives for the removal module.
 * @details This function is called lazily and must be called from within a
 * mutex-protected block to prevent race conditions during initialization.
 */
void auth_remove_init(void);

/**
 * @brief Handles incoming node removal commands.
 * @details When a follower receives a removal command, it verifies the leader's integrity
 * before executing the command and sending an acknowledgement.
 * @param message The raw, null-terminated message string received from a peer.
 * @param from_ip The IP address of the node that sent the message.
 */
void remove_handle_message(char *message, const char *from_ip);

/**
 * @brief (Leader-only) Triggers the removal of a node from the cluster.
 * @details This function, callable only on the leader, initiates the two-phase removal process.
 * It first broadcasts the removal command and waits for a quorum of acknowledgements.
 * If successful, it proceeds to the self-healing phase. On failure, it times out.
 * @param ip_to_remove The IP address of the node to be removed from the cluster.
 */
void trigger_node_removal(const char* ip_to_remove);

#endif // AUTH_REMOVE_H