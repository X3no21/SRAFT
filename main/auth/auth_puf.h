/* =============================
 * File: auth_puf.h
 * Description: Public interface for the PUF-based authentication protocol.
 * ============================= */

#ifndef AUTH_PUF_H
#define AUTH_PUF_H

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "auth_db.h"

#define PUF_MAX_MSG_SIZE 512

#define MSG_AUTH_REQ "AUTH_REQ"
#define MSG_AUTH_RESPONSE "AUTH_RES"
#define MSG_INITIATE_AUTH_REQ "INITIATE_AUTH_REQ"
#define MSG_AUTH_FINAL_RESULT "AFR"

#define AUTH_CHECK_OP_PREFIX "chk_"
#define AUTH_CHANNEL_OP_PREFIX "ch_"
#define MSG_ENROLL_KEY "EKEY"
#define AUTH_KEY_SIZE 32
// How long a device waits for the key that protects an enrollment before giving up.
#define ENROLL_KEY_WAIT_MS 20000

extern SemaphoreHandle_t auth_result_sem;
extern bool auth_result_success;

/**
 * @brief (Verifier) Challenges a Prover with one of the locally stored CRPs and waits for the outcome.
 * @details Unlike the monitored authentication flow, this check is local to the Verifier: no result
 * is sent back to the Prover and no monitoring event is emitted. Checks are serialized.
 * @param target_ip The IP address of the Prover to challenge.
 * @param timeout_ms How long to wait for the response.
 * @return true only if the Prover answered in time with the expected response. false if this node
 * holds no CRP for the Prover, the Prover did not answer, or the response was wrong.
 */
bool auth_puf_challenge_prover(const char *target_ip, uint32_t timeout_ms);

/**
 * @brief (Verifier) Same as auth_puf_challenge_prover, with a given CRP of the Prover.
 */
bool auth_puf_challenge_prover_with_crp(const char *target_ip, const CRPNode *crp, uint32_t timeout_ms);

/**
 * @brief Tells whether this node holds at least one CRP for the given Prover, i.e., is one of its Verifiers.
 */
bool auth_puf_is_verifier_of(const char *target_ip);

/**
 * @brief Encrypts a buffer with AES-256-GCM under a fresh nonce.
 * @param key The AUTH_KEY_SIZE-byte key.
 * @param aad Associated data, bound to the ciphertext.
 * @param out_hex Output buffer for the hexadecimal encoding of nonce, ciphertext, and tag.
 * @param out_hex_size Size of the output buffer: at least (12 + len + 16) * 2 + 1 bytes.
 * @return true on success.
 */
bool auth_puf_seal(const uint8_t *key, const char *aad, const uint8_t *plaintext, size_t len, char *out_hex, size_t out_hex_size);

/**
 * @brief Decrypts and verifies a buffer produced by auth_puf_seal.
 * @return The length of the plaintext, or -1 if the input is malformed or does not verify.
 */
int auth_puf_open(const uint8_t *key, const char *aad, const char *in_hex, uint8_t *out, size_t out_size);

/**
 * @brief (Intermediary) Gives a Prover and its new Verifier the key that protects an enrollment.
 * @details The caller must hold CRPs of the new Verifier and, unless it is the Prover itself, of
 * the Prover. It runs the authentication exchange with each of them and sends the same fresh key
 * inside the two session keys. The key is not kept by the intermediary.
 * @param transaction_id The identifier of the enrollment.
 * @param prover_ip The device whose CRPs are going to be enrolled.
 * @param verifier_ip The device that is going to hold them.
 * @return true if the key was delivered to both.
 */
bool auth_puf_broker_enrollment(uint32_t transaction_id, const char *prover_ip, const char *verifier_ip);

/**
 * @brief Waits for the key that protects an enrollment with a given peer.
 * @return true if the key arrived within the timeout.
 */
bool auth_puf_enroll_key_wait(uint32_t transaction_id, const char *peer_ip, uint8_t *key, uint32_t timeout_ms);

/**
 * @brief Forgets the key that protected an enrollment.
 */
void auth_puf_enroll_key_drop(uint32_t transaction_id, const char *peer_ip);

typedef struct {
    char *message;
    char from_ip[INET_ADDRSTRLEN];
} auth_message_t;

/**
 * @brief Initializes the PUF authentication module.
 * @details This function performs lazy, thread-safe initialization of the synchronization
 * primitives required for the PUF authentication process. Specifically, it creates the
 * `auth_result_sem` binary semaphore. This semaphore is essential for making the
 * `/request_authentication` API endpoint synchronous, allowing the HTTP handler to block
 * until the P2P authentication process completes and a definitive result is available.
 * @param None.
 * @return void
 */
void auth_puf_init(void);

/**
 * @brief Queues an incoming authentication message for processing by the worker task.
 * @details This function is thread-safe and non-blocking. It copies the message pointer
 * and sender IP into the queue. The worker task is responsible for freeing the message memory.
 * @param message The dynamically allocated message string. Ownership is transferred to the queue.
 * @param from_ip The IP address of the sender.
 * @return void
 */
void auth_puf_queue_message(char *message, const char *from_ip);

/**
 * @brief A node (Prover) initiates its own authentication process against a random verifier.
 * @details This function looks up a random verifier from the database and queues an
 * authentication request to it via the connection pool.
 * @return void
 */
void initiate_authentication_as_prover(void);

/**
 * @brief A node (Prover) initiates its own authentication process against a *specific* verifier.
 * @details This function is called by an API handler when commanded by the monitoring server.
 * It sends an authentication request to the specified verifier.
 * @param verifier_ip The IP address of the verifier to use.
 * @return void
 */
void initiate_authentication_as_prover_specific(const char* verifier_ip);

#endif // AUTH_PUF_H