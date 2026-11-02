/* =============================
 * File: auth_remove.h
 * Description: Public interface for the self-healing node removal logic.
 * ============================= */

#ifndef AUTH_REMOVE_H
#define AUTH_REMOVE_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <stdint.h>

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

// Verifier-side confirmation of a removal. All the commands of this group share the "RM_" prefix.
#define MSG_REMOVE_PREFIX "RM_"
#define MSG_REMOVE_CHECK_REQ "RM_CHK_REQ"
#define MSG_REMOVE_CHECK_OK "RM_CHK_OK"
#define MSG_REMOVE_CHECK_REFUSED "RM_CHK_NO"
#define MSG_REMOVE_REPORT "RM_REPORT"
// A Verifier of the target broadcasts this when it confirms a removal, so every member can check that
// the Coordinator's order is backed by the target's own Verifiers, not by the Coordinator alone.
#define MSG_REMOVE_CONFIRMED "RM_CONFIRMED"
// Independent Verifier confirmations a member requires before it applies a removal order. One already
// defeats a captured Coordinator acting alone on a healthy device (whose honest Verifiers never
// confirm); forcing a removal then also requires compromising a Verifier of that specific target.
#define REMOVAL_MIN_VERIFIER_CONFIRMATIONS 1

// How long a Verifier waits for the device under removal to answer its challenge.
#define REMOVAL_CONFIRM_TIMEOUT_MS 5000
// How long the Coordinator waits for the Verifiers to confirm a removal.
#define REMOVAL_CHECK_PHASE_TIMEOUT_MS 10000
// Once the majority of the members has acknowledged, the others are awaited for this time only.
#define REMOVAL_ACK_GRACE_MS 3000
// How long a confirmation given by a Verifier stays valid for the removal order that follows it.
// The Verifiers are consulted one at a time, so the order may come well after the first confirmation.
#define REMOVAL_CONFIRMATION_VALIDITY_MS 120000
#define MAX_REMOVAL_CHECK_REPLIES 32

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
    int check_ok_count;
    int check_refused_count;
    char check_replied_ips[MAX_REMOVAL_CHECK_REPLIES][INET_ADDRSTRLEN];
    int check_replied_count;
    // Devices whose acknowledgement was already counted, for the pause and for the removal order.
    char pause_acked_ips[MAX_REMOVAL_CHECK_REPLIES][INET_ADDRSTRLEN];
    char removal_acked_ips[MAX_REMOVAL_CHECK_REPLIES][INET_ADDRSTRLEN];
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

/**
 * @brief (Verifier) Decides whether this node agrees with the removal of a device.
 * @details A node that holds no CRP for the device has nothing to protect and agrees. A Verifier
 * of the device challenges it with one of its CRPs and, if the response is correct, attests it:
 * it agrees only if the device does not answer, answers wrongly, or fails the attestation.
 * @param ip_to_remove The IP address of the device under removal.
 * @return true if the removal is confirmed, false if the device is alive and healthy.
 */
bool remove_verifier_confirms(const char *ip_to_remove);

/**
 * @brief Makes this device leave the network on a local request (planned decommissioning).
 * @details The device stops its protocol tasks and wipes its authentication data. It is the only
 * way a device decommissions itself: no network message can trigger it.
 */
void auth_remove_leave_network(void);

/**
 * @brief Tells whether a removal is being coordinated by this device.
 */
bool auth_remove_in_progress(void);

/**
 * @brief (Coordinator) Brings every device back to ceil(rho N) Verifiers, healing one Prover at a time.
 * @return true if every heal completed.
 */
bool auth_remove_heal_network(void);

/**
 * @brief Reports to the Coordinator a device that failed a check, so that its removal is started.
 * @details If this node is the Coordinator, the removal is queued directly.
 * @param suspect_ip The IP address of the device that failed the check.
 */
void remove_report_suspect(const char *suspect_ip);

#endif // AUTH_REMOVE_H