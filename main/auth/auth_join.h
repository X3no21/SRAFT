/* =============================
 * File: auth_join.h
 * Description: Public interface for the synchronized node join protocol.
 * ============================= */

#ifndef AUTH_JOIN_H
#define AUTH_JOIN_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <stdint.h>

#define MSG_JOIN_FAIL_MASTER_CORRUPT "JOIN_FAIL_MC"
#define MSG_JOIN_REQ "JOIN_REQ"
#define MSG_JOIN_CHL "JOIN_CHL"
#define MSG_JOIN_FINALIZE "JOIN_FINALIZE"
// Part of the network state sent to a joining device before JOIN_FINALIZE (the state does not fit in one message).
#define MSG_NET_STATE "NET_STATE"
// Payload of a NET_STATE message, in characters.
#define NET_STATE_CHUNK_SIZE 1400
#define MSG_JOIN_RESPONSE "JOIN_RESPONSE"
#define MSG_JOIN_FAIL_NO_VERIFIERS "JOIN_FAIL_NV"
#define MSG_JOIN_ABORT "JOIN_ABORT"
#define MSG_CHALLENGE_GENERATED "CHL_GEN"
#define MSG_NODE_ADDED_COMMIT "NODE_ADDED_COMMIT"
#define MSG_NODE_HEALED_COMMIT "NODE_HEALED_COMMIT"
#define MSG_COMMIT_ACK "COMMIT_ACK"
#define MSG_CLEANUP_COMMIT "CLEANUP_COMMIT"
#define MSG_VERIFIER_UPDATE "VERIFIER_UPDATE"
#define MSG_VERIFIER_UPDATE_ACK "VUA"
#define MSG_CHL_RESULT "CHL_RESULT"
#define MSG_REQ_CHL_GEN "REQ_CHL_GEN"
#define MSG_DELEGATE_CRPS "DELEGATE_CRPS"
// (Leader -> intermediary) Asks a device that holds CRPs of both parties to give them the key of an enrollment.
#define MSG_BROKER_REQ "BRK_REQ"
// Marker of an enrollment whose responses travel encrypted.
#define ENROLL_SECURE_MARKER '!'
#define ENROLL_SEALED_PREFIX "ENC."
#define ENROLL_NO_BROKER "-"

#define MAX_JOIN_MSG 4096
#define NONCE_SIZE 16
#define NONCE_HEX_SIZE (NONCE_SIZE * 2 + 1)
// Redundancy parameter rho: fraction of the devices assigned as Verifiers to each Prover, at join and at healing.
#define VERIFIER_PERCENTAGE 0.3f
#define MAX_VERIFIERS 32
// A decision taken by the Verifiers of a device needs the majority of them.
#define VERIFIER_QUORUM(n) ((n) / 2 + 1)
// A device is excluded for good only if at least this many Verifiers agree.
#define MIN_VERIFIERS_TO_EXCLUDE 2
#define MAX_PARALLEL_HEALS 32
// CRPs that a Verifier holds for each of its Provers. A CRP is not consumed by its use, so one would be
// enough; the second lets a Verifier repeat a failed check with another response before it reports the
// Prover, so that a single response that is not reproduced does not cause a removal. More CRPs would only
// use up the challenges of the PUF of the Prover (PUF_RESPONSE_CAPACITY), which bound how many times its
// Verifiers can be replaced.
#define CRPS_PER_VERIFIER 2
// Time allowed to a device to accept a connection before it is given a role in a heal.
#define DEVICE_PROBE_TIMEOUT_MS 1500
// A commit acknowledged by the majority of the members is completed after this grace period even if some
// members do not answer, e.g., because they failed and have not been removed yet.
#define COMMIT_ACK_GRACE_MS 3000
#define JOIN_PROCESS_TIMEOUT_MS 160000
#define MAX_PENDING_JOINS 32
#define SINGLE_VERIFIER_TIMEOUT_MS 30000

extern QueueHandle_t join_request_queue;

extern SemaphoreHandle_t join_result_semaphore;
extern SemaphoreHandle_t caller_sync_sem;
extern volatile uint32_t parallel_job_failure_count;
extern portMUX_TYPE parallel_job_failure_mux;
extern bool join_result_success;


typedef enum {
    JOIN_TYPE_NEW_NODE = 0,
    JOIN_TYPE_GENESIS = 1,
    JOIN_TYPE_HEAL_NODE = 2,
    JOIN_TYPE_BOOTSTRAP_SYNC = 3
} join_request_type_t;

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    join_request_type_t type;
    int num_verifiers_to_add;
} join_request_t;

/**
 * @brief Holds the state for a single, ongoing node join process on the leader.
 */
typedef struct {
    bool in_use;
    uint32_t transaction_id;
    char new_node_ip[INET_ADDRSTRLEN];
    uint32_t start_time_ms;
    join_request_type_t type;

    int expected_verifier_results;
    int received_verifier_results;
    int failed_verifier_results;
    // Verifiers that reported a proof different from the reference, and Verifiers already counted.
    int wrong_proof_results;
    uint32_t reported_verifiers_mask;

    SemaphoreHandle_t ack_semaphore;
    SemaphoreHandle_t completion_semaphore;

    char verifier_ips[MAX_VERIFIERS][INET_ADDRSTRLEN]; 
    int verifier_count;
    // For each verifier, the intermediary that gives it and the Prover the key of the enrollment
    // (empty when the responses are enrolled as in the first enrollment of a device).
    // Stored as IPv4 addresses (0 = none) to keep the table of parallel heals small.
    uint32_t broker_addrs[MAX_VERIFIERS];

    int commit_ack_count;
    int expected_commit_acks;
    // Time at which the majority of the members acknowledged the commit (0 until then).
    uint32_t commit_majority_ms;
} JoinProcess;

/**
 * @brief Initializes the join module's mutex.
 * @details This function ensures the primary mutex for protecting the join state machine is created.
 * It uses a lazy initialization pattern, creating the mutex only on its first required use.
 */
void auth_join_init(void);

/**
 * @brief (Prover) Tells whether a challenge was just answered for a Verifier in an enrollment
 * that is not committed yet, so that the Verifier can attest this device with it.
 */
bool join_is_pending_challenge(const char *verifier_ip, const char *challenge);

/**
 * @brief Tells whether this device is taking part in a join or a heal: as Coordinator of an
 * operation that is not finished, or as Verifier of an enrollment that is not committed yet.
 */
bool auth_join_operation_in_progress(void);

/**
 * @brief (Leader-only) Starts the network self-healing process.
 * @details The leader iterates through all followers, checks if they have a sufficient
 * number of verifiers, and assigns new ones if a node is below the required threshold.
 */
void leader_start_network_heal(void);

/**
 * @brief Sets a flag indicating that the node was started in a mode that requires an automatic network heal.
 * @param enabled True to enable the one-time healing check after an election, false otherwise.
 * @param cluster_size The total number of nodes expected in the cluster during bootstrap.
 */
void auth_join_set_healing_mode(bool enabled, int cluster_size);

/**
 * @brief (Leader-only) Stages genesis credentials for the first leader.
 * @details This function is called only once when a node becomes the first leader
 * of a bootstrap cluster. It generates its own security credentials (CRPs and CNodes)
 * and places them into the temporary (staging) database, pending delegation to the
 * first follower that joins.
 * @return void
 */
void leader_bootstrap_self_join(void);

/**
 * @brief (Leader-only) Triggers the network healing process if the healing mode flag is set.
 * @details This function is designed to be called by the Raft module immediately after a node becomes leader.
 * It checks the flag, runs the heal process if needed, and then resets the flag to prevent re-execution.
 */
void leader_heal_if_needed(void);

/**
 * @brief (Leader-only) Selects followers to act as verifiers and notifies all parties.
 * @param target_ip The IP of the node to be verified.
 * @param num_to_add The number of verifiers to assign.
 * @param transaction_id The unique ID for the current join process.
 */
void master_assign_new_verifiers(JoinProcess* job, const char *target_ip, int num_to_add, uint32_t transaction_id);

/**
 * @brief Sends a join request from a new node to the cluster's leader.
 * @details This function is called by a node that wishes to join the cluster. It formats
 * a JOIN_REQ message and queues it for transmission to the current leader.
 * @param my_node_id The ID (typically IP address) of the node sending the request.
 * @param master_ip The IP address of the current cluster leader.
 * @return void
 */
void node_to_add_send_join_request(const char* my_node_id, const char *master_ip);

/**
 * @brief (Leader-only) Handles an initial join request from a new node.
 * @details This function is the entry point for the leader when it receives a JOIN_REQ.
 * It initializes the JoinProcess state, calculates the required number of verifiers,
 * and kicks off the verification process by assigning verifiers.
 * @param new_node_ip The IP address of the node requesting to join.
 * @return void
 */
void node_master_handle_join_request(const char *target_ip, join_request_type_t type, join_request_t request);

/**
 * @brief (Leader-only) Finalizes the join process after verification is complete.
 * @details Based on the success or failure of the verification phase, this function
 * either triggers a commit (notifying all nodes of the new member) or a
 * rollback (notifying all participants to discard the transaction).
 * @param is_success True if the join was successful, false otherwise.
 * @return void
 */
void finalize_join_process(JoinProcess* job, bool is_success);

/**
 * @brief Central message handler for the synchronized join protocol.
 * @details This function is the main router for all incoming messages related to the join protocol.
 * It parses the command and, based on the node's role (Leader, Follower, New Node),
 * dispatches the message to the appropriate handling logic. It is designed to be
 * called from the main server task that receives network messages.
 * @param message The raw, null-terminated message string received from a peer.
 * @param from_ip The IP address of the node that sent the message.
 * @return void
 */
void join_handle_message(char *message, const char *from_ip);

/**
 * @brief (Leader-only) Asynchronously runs a network heal job.
 * @details This function queues a heal request to be processed by the join worker task.
 * It is used to add missing verifiers to a node without blocking the main Raft loop.
 * @param request The join request structure containing details about the heal operation.
 * @return void
 */
void auth_join_run_heal_job_async(join_request_t request);

/**
 * @brief Tells within a short time whether a device accepts connections on its attestation port.
 */
bool auth_join_device_reachable(const char *ip);

#endif // AUTH_JOIN_H