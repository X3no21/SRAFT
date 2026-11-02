/* =============================
 * File: hatt_protocol.h
 * Description: Public interface for the HAtt remote attestation protocol.
 * ============================= */

#ifndef HATT_PROTOCOL_H
#define HATT_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include "auth_db.h"

#define HATT_PORT 3333
#define HATT_SOCKET_TIMEOUT_S 10
// Verifiers waiting to be served by the Prover, which handles one session at a time.
#define HATT_LISTEN_BACKLOG 32
// Time allowed to a Prover for one measurement of its memory. A Prover serves several Verifiers at
// the same time, e.g., during an election, so the time a Verifier waits for the proof grows with
// the size of the network.
// Measured on the ESP32 for the firmware image (about 1.9 s with the parameters below), plus a margin.
#define HATT_MEASUREMENT_BUDGET_MS 2500
// Attestation parameters, as in the evaluation of HAtt: the attested memory is the firmware image of
// the running application, divided in blocks of m words, with beta bits read from every word.
#define HATT_WORD_SIZE_BYTES 4
#define HATT_WORDS_PER_BLOCK 16
#define HATT_BITS_PER_WORD 1
#define HATT_ITERATIONS 4
#define HATT_MEMORY_BLOCK_SIZE_BYTES (HATT_WORDS_PER_BLOCK * HATT_WORD_SIZE_BYTES)
#define HATT_CHALLENGE_SIZE_BYTES 16
#define HATT_SEED_SIZE_BYTES 16
#define HATT_PUF_RESPONSE_SIZE_BYTES 16
#define HATT_NONCE_SIZE_BYTES 16
#define HATT_HASH_SIZE_BYTES 32
#define HATT_PID_SIZE_BYTES HATT_HASH_SIZE_BYTES
#define HATT_MAC_ADDR_LEN 6
#define HATT_MAX_ID_LEN 32
#define HATT_MAX_CHALLENGE_LEN 64
// The verification bits sigma are sent as their SHA-256 digest.
#define HATT_SIGMA_SIZE_BYTES HATT_HASH_SIZE_BYTES



typedef struct {
    char verifier_id[HATT_MAX_ID_LEN];
    char challenge[HATT_MAX_CHALLENGE_LEN];
    uint8_t nonce_n_id[HATT_NONCE_SIZE_BYTES];
    uint8_t pid[HATT_PID_SIZE_BYTES];
    uint8_t encrypted_payload[HATT_SEED_SIZE_BYTES * 2 + HATT_NONCE_SIZE_BYTES];
    uint8_t auth_tag_i1[HATT_HASH_SIZE_BYTES];
} Message1_t;

typedef struct {
    uint8_t encrypted_payload[HATT_MAX_ID_LEN + HATT_NONCE_SIZE_BYTES * 2];
    uint8_t auth_tag_i2[HATT_HASH_SIZE_BYTES];
} Message2_t;

typedef struct {
    uint8_t auth_tag_i3[HATT_HASH_SIZE_BYTES];
} Message3_t;

typedef struct {
    uint8_t encrypted_payload[HATT_SIGMA_SIZE_BYTES + HATT_NONCE_SIZE_BYTES * 2];
    uint8_t auth_tag_i4[HATT_HASH_SIZE_BYTES];
} Message4_t;

typedef struct {
    char device_id[HATT_MAX_ID_LEN];
    uint8_t puf_secret[HATT_MAC_ADDR_LEN];
    uint8_t puf_response_r[HATT_PUF_RESPONSE_SIZE_BYTES];
    uint8_t n1[HATT_NONCE_SIZE_BYTES];
    uint8_t n2[HATT_NONCE_SIZE_BYTES];
    uint8_t s_beta[HATT_SEED_SIZE_BYTES];
    uint8_t s_omega[HATT_SEED_SIZE_BYTES];
    uint32_t prng_state;
} ProverState_t;

typedef struct {
    char verifier_id[HATT_MAX_ID_LEN];
    char prover_id_on_record[HATT_MAX_ID_LEN];
    char challenge[HATT_MAX_CHALLENGE_LEN];
    uint8_t puf_response_r[HATT_PUF_RESPONSE_SIZE_BYTES];
    uint8_t n1[HATT_NONCE_SIZE_BYTES];
    uint8_t n2[HATT_NONCE_SIZE_BYTES];
    uint8_t s_beta[HATT_SEED_SIZE_BYTES];
    uint8_t s_omega[HATT_SEED_SIZE_BYTES];
    uint8_t expected_sigma[HATT_SIGMA_SIZE_BYTES];
    bool expected_sigma_ready;
    uint32_t prng_state;
} VerifierState_t;

/**
 * @brief Outcome of an attestation, as seen by the Verifier.
 * @details Only HATT_FAILED is evidence against the Prover: the Prover returned, under a valid
 * authentication tag, a proof that differs from the expected one. HATT_NO_ANSWER covers every
 * run that did not reach a verdict (unreachable Prover, timeout, invalid message): the check is
 * not passed, but nothing is proved about the software of the Prover.
 */
typedef enum {
    HATT_PASSED = 0,
    HATT_FAILED,
    HATT_NO_ANSWER
} hatt_result_t;

/**
 * @brief Runs an attestation and returns its outcome.
 * @param prover_ip The IP address of the Prover.
 * @param enrolled_crp CRP to bind the attestation to, or NULL to use a stored one.
 */
hatt_result_t hatt_verifier_attest(const char *prover_ip, const CRPNode *enrolled_crp);

/**
 * @brief Upper bound, in milliseconds, of the time a Prover may take to return its proof.
 */
uint32_t hatt_measurement_timeout_ms(void);

/**
 * @brief Creates the locks of the attested memory (idempotent).
 */
void hatt_init(void);

/**
 * @brief Starts the background task for the HAtt Prover (idempotent).
 * @details This task listens for incoming attestation requests on the dedicated HAtt port
 * and handles the full 4-message protocol exchange for any connecting Verifier.
 * @return void
 */
void hatt_prover_start_task(void);

/**
 * @brief SHA-256 digest of the attested memory, i.e., of the firmware image without its appended digest.
 * @param digest Output buffer of HATT_HASH_SIZE_BYTES bytes.
 * @return true on success.
 */
bool hatt_attested_image_digest(uint8_t digest[HATT_HASH_SIZE_BYTES]);

/**
 * @brief Runs a full attestation protocol from the Verifier's perspective.
 * @details This function connects to a Prover, executes the 4-message exchange,
 * and verifies the integrity of the Prover's memory based on its golden image.
 * This is a blocking function that returns only after the protocol completes or fails.
 * @param prover_ip The IP address of the Prover node to attest.
 * @return true if the attestation is successful and the Prover is deemed honest, false otherwise.
 */
bool hatt_verifier_run_attestation(const char *prover_ip);

/**
 * @brief Runs the attestation of a Prover with a given CRP as key material.
 * @details Used during an enrollment, when the CRPs of the Prover are not committed yet: the
 * attestation is bound to the PUF of the device that has just answered the challenge.
 * @param prover_ip The IP address of the Prover.
 * @param enrolled_crp The CRP to use, or NULL to pick one of the stored CRPs of the Prover.
 * @return true if the attestation is successful, false otherwise.
 */
bool hatt_verifier_run_attestation_with_crp(const char *prover_ip, const CRPNode *enrolled_crp);

#endif // HATT_PROTOCOL_H