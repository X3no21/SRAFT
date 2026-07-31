/* =============================
 * File: hatt_protocol.h
 * Description: Public interface for the HAtt remote attestation protocol.
 * ============================= */

#ifndef HATT_PROTOCOL_H
#define HATT_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

#define HATT_PORT 3333
#define HATT_MEMORY_SIZE_BYTES 1024
#define HATT_MEMORY_BLOCK_SIZE_BYTES 64
#define HATT_BITS_PER_BLOCK_TO_SAMPLE 8
#define HATT_CHALLENGE_SIZE_BYTES 16
#define HATT_SEED_SIZE_BYTES 16
#define HATT_PUF_RESPONSE_SIZE_BYTES 16
#define HATT_NONCE_SIZE_BYTES 16
#define HATT_HASH_SIZE_BYTES 32
#define HATT_PID_SIZE_BYTES HATT_HASH_SIZE_BYTES
#define HATT_MAC_ADDR_LEN 6
#define HATT_MAX_ID_LEN 32
#define HATT_SIGMA_SIZE_BYTES ((HATT_MEMORY_SIZE_BYTES / HATT_MEMORY_BLOCK_SIZE_BYTES * HATT_BITS_PER_BLOCK_TO_SAMPLE) / 8)



typedef struct {
    char verifier_id[HATT_MAX_ID_LEN];
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
    uint8_t memory[HATT_MEMORY_SIZE_BYTES];
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
    uint8_t prover_golden_image[HATT_MEMORY_SIZE_BYTES];
    uint8_t puf_response_r[HATT_PUF_RESPONSE_SIZE_BYTES];
    uint8_t n1[HATT_NONCE_SIZE_BYTES];
    uint8_t n2[HATT_NONCE_SIZE_BYTES];
    uint8_t s_beta[HATT_SEED_SIZE_BYTES];
    uint8_t s_omega[HATT_SEED_SIZE_BYTES];
    uint32_t prng_state;
} VerifierState_t;

/**
 * @brief Starts the background task for the HAtt Prover.
 * @details This task listens for incoming attestation requests on the dedicated HAtt port
 * and handles the full 4-message protocol exchange for any connecting Verifier.
 * @return void
 */
void hatt_prover_start_task(void);

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
 * @brief [TEST ONLY] Tamper with the node's HAtt secret.
 * @details This function is for testing only. It overwrites the
 * shared challenge with random data, ensuring that any subsequent
 * integrity check will fail.
 * @return void
 */
void hatt_test_tamper_secret(void);

#endif // HATT_PROTOCOL_H