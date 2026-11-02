/* =============================
 * File: integrity_verification.h
 * Description: Public interface for orchestrating integrity verification protocols.
 * ============================= */

#ifndef INTEGRITY_VERIFICATION_H
#define INTEGRITY_VERIFICATION_H

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "raft_state.h"

#define MAX_VOTERS 32

#define MSG_REQUEST_INTEGRITY_CHECK "V_REQ"
#define MSG_PROCEED_WITH_INTEGRITY_CHECK "V_PROCEED"
#define MAX_PENDING_INTEGRITY_CHECKS 32

#define HATT_PROTOCOL_TIMEOUT_MS 60000

// Period of the re-attestation that each Verifier runs on the devices it holds CRPs for. 0 disables it.
#define PERIODIC_REATTEST_INTERVAL_MS 60000
// How long a Verifier waits for the device to answer the PUF challenge that precedes the attestation.
#define PERIODIC_REATTEST_AUTH_TIMEOUT_MS 5000
// Consecutive failed checks of the same device before it is reported.
#define PERIODIC_REATTEST_FAILURES_TO_REPORT 2

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    char target_mac[MAC_ADDR_STR_LEN];
} single_check_request_t;

typedef struct {
    single_check_request_t request;
    SemaphoreHandle_t result_semaphore;
    bool is_honest;
} single_check_job_t;

/**
 * @brief Runs a single, blocking point-to-point integrity check.
 * @details This function performs a direct HAtt attestation on the target and waits for
 * the result. If the attestation fails, it will automatically blacklist the target's
 * MAC address and trigger a new RAFT election.
 * @param target_ip The IP address of the node to be verified.
 * @param target_mac The MAC address of the node to be verified.
 * @return true if the attestation is successful, false otherwise.
 */
bool integrity_verification_run_single(const char* target_ip, const char* target_mac);


/**
 * @brief Unified message handler for the centralized integrity verification protocol.
 * @details This function acts as the main router for the leader-coordinated integrity check.
 * It handles two primary messages: `MSG_REQUEST_INTEGRITY_CHECK` from a follower, which
 * it queues for the leader's manager task; and `MSG_PROCEED_WITH_INTEGRITY_CHECK`
 * from the leader, which triggers the follower to begin the attestation process.
 * This orchestrates a sequential, leader-managed verification of the cluster.
 * @param message The raw, null-terminated message string. This buffer will be
 * modified by `strtok_r`.
 * @param from_ip The IP address of the node that sent the message. Used to identify
 * the requester.
 */
void integrity_verification_handle_message(char* message, const char* from_ip);

/**
 * @brief Starts the periodic re-attestation task. Safe to call more than once.
 * @details Every PERIODIC_REATTEST_INTERVAL_MS the task picks one of the devices this node is a
 * Verifier of, challenges it with a stored CRP, and attests it. A device that fails
 * PERIODIC_REATTEST_FAILURES_TO_REPORT consecutive checks is reported: the Coordinator is
 * blacklisted and a new election is forced, any other device is reported to the Coordinator,
 * which starts its removal.
 */
void integrity_verification_start_periodic(void);

/**
 * @brief (Verifier) Authenticates a Prover with one of the CRPs held for it and attests it with the same CRP.
 * @details If the authentication fails, it is repeated with the other CRPs held for the Prover, so that a
 * single response that the Prover does not reproduce is not taken for a failure of the device.
 * @param target_ip The Prover.
 * @param auth_timeout_ms Time allowed to each authentication.
 * @return HATT_PASSED or HATT_FAILED from the attestation, HATT_NO_ANSWER if no CRP authenticated it.
 */
int integrity_verification_check_prover(const char *target_ip, uint32_t auth_timeout_ms);

#endif // INTEGRITY_VERIFICATION_H