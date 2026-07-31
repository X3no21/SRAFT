/* =============================
 * File: hatt_protocol.c
 * Description: Implements the HAtt hybrid remote attestation protocol.
 * ============================= */

#include "hatt_protocol.h"
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "psa/crypto.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "utility.h"
#include "auth_db.h"

static const char *TAG = "HATT_PROTOCOL";

static uint8_t SHARED_HATT_CHALLENGE[HATT_CHALLENGE_SIZE_BYTES] = {
    0x1A, 0x9F, 0x3E, 0x8B, 0xC7, 0x2D, 0x6F, 0x5A,
    0x4D, 0x8A, 0x9B, 0x0C, 0x1D, 0xEF, 0x4A, 0x7B
};

static bool force_tamper_memory = false;

/**
 * @brief Simulates a tampered memory state for testing purposes.
 * @details This function is used to force the Prover to simulate a tampered memory state,
 * which is useful for testing the integrity verification process.
 * @return void
 */
void hatt_test_tamper_secret(void) {
    ESP_LOGW(TAG, "!!! TAMPERING HATT MEMORY SIMULATION FOR TEST !!!");
    force_tamper_memory = true;
}

/**
 * @brief Computes SHA256 hash over multiple data chunks.
 * @param data_chunks An array of pointers to the data chunks.
 * @param chunk_sizes An array of sizes for each corresponding data chunk.
 * @param num_chunks The number of chunks to hash.
 * @param output_hash A buffer of HATT_HASH_SIZE_BYTES to store the resulting hash.
 * @return void
 */
static void hatt_sha256(const uint8_t **data_chunks, const size_t *chunk_sizes, int num_chunks, uint8_t *output_hash) {
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_hash_setup(&op, PSA_ALG_SHA_256);
    for (int i = 0; i < num_chunks; ++i) {
        if (data_chunks[i] != NULL && chunk_sizes[i] > 0) {
            psa_hash_update(&op, data_chunks[i], chunk_sizes[i]);
        }
    }
    size_t hash_len = 0;
    psa_hash_finish(&op, output_hash, HATT_HASH_SIZE_BYTES, &hash_len);
}

/**
 * @brief Computes an HMAC-SHA256 MAC over multiple data chunks.
 * @param key The secret key for the HMAC operation.
 * @param data_chunks An array of pointers to the data chunks.
 * @param chunk_sizes An array of sizes for each corresponding data chunk.
 * @param num_chunks The number of chunks to authenticate.
 * @param output_mac A buffer of HATT_HASH_SIZE_BYTES to store the resulting MAC.
 * @return void
 */
static void hatt_hmac_sha256(const uint8_t *key, const uint8_t **data_chunks, const size_t *chunk_sizes, int num_chunks, uint8_t *output_mac) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t key_id;
    psa_import_key(&attr, key, HATT_HASH_SIZE_BYTES, &key_id);

    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    for (int i = 0; i < num_chunks; i++) {
        if (data_chunks[i] != NULL && chunk_sizes[i] > 0) {
            psa_mac_update(&op, data_chunks[i], chunk_sizes[i]);
        }
    }
    size_t mac_len = 0;
    psa_mac_sign_finish(&op, output_mac, HATT_HASH_SIZE_BYTES, &mac_len);
    psa_destroy_key(key_id);
}

/**
 * @brief Derives separate encryption and authentication keys from a master key using HMAC-based KDF.
 * @param master_key The secret key to derive from (e.g., PUF response).
 * @param k_enc Output buffer of HATT_HASH_SIZE_BYTES for the encryption key.
 * @param k_mac Output buffer of HATT_HASH_SIZE_BYTES for the authentication key.
 * @return void
 */
static void hatt_kdf(const uint8_t *master_key, uint8_t *k_enc, uint8_t *k_mac) {
    const char *enc_label = "enc_key";
    const char *mac_label = "mac_key";

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t key_id;
    psa_import_key(&attr, master_key, HATT_PUF_RESPONSE_SIZE_BYTES, &key_id);

    size_t out_len = 0;
    psa_mac_operation_t enc_op = PSA_MAC_OPERATION_INIT;
    psa_mac_sign_setup(&enc_op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_mac_update(&enc_op, (const unsigned char*)enc_label, strlen(enc_label));
    psa_mac_sign_finish(&enc_op, k_enc, HATT_HASH_SIZE_BYTES, &out_len);

    psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;
    psa_mac_sign_setup(&mac_op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_mac_update(&mac_op, (const unsigned char*)mac_label, strlen(mac_label));
    psa_mac_sign_finish(&mac_op, k_mac, HATT_HASH_SIZE_BYTES, &out_len);

    psa_destroy_key(key_id);
}

/**
 * @brief Performs AES-128-CBC encryption or decryption.
 * @param encrypt true for encryption, false for decryption.
 * @param key The 128-bit (16-byte) AES key. Note: HMAC-SHA256 KDF produces a 256-bit key, only the first 128 bits are used.
 * @param iv The 128-bit (16-byte) Initialization Vector.
 * @param input The input data buffer.
 * @param input_len The length of the input data.
 * @param output The output buffer for the result.
 * @return 0 on success, a negative error code on failure.
 */
static int hatt_aes_crypt(bool encrypt, const uint8_t *key, const uint8_t *iv, const uint8_t *input, size_t input_len, uint8_t *output) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_key_id_t key_id;
    if (psa_import_key(&attr, key, 16, &key_id) != PSA_SUCCESS) {
        return -1;
    }

    uint8_t temp_iv[16];
    memcpy(temp_iv, iv, 16);

    uint8_t scratch[128];
    size_t update_len = 0, finish_len = 0;
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_status_t status = encrypt ? psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING)
                                  : psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (status == PSA_SUCCESS) status = psa_cipher_set_iv(&op, temp_iv, sizeof(temp_iv));
    if (status == PSA_SUCCESS) status = psa_cipher_update(&op, input, input_len, scratch, sizeof(scratch), &update_len);
    if (status == PSA_SUCCESS) status = psa_cipher_finish(&op, scratch + update_len, sizeof(scratch) - update_len, &finish_len);

    int ret;
    if (status == PSA_SUCCESS) {
        memcpy(output, scratch, update_len + finish_len);
        ret = 0;
    } else {
        psa_cipher_abort(&op);
        ret = -1;
    }

    psa_destroy_key(key_id);
    return ret;
}

/**
 * @brief Initializes the PRNG state using a combined seed.
 * @param state Pointer to the PRNG state to be initialized.
 * @param seed_data_1 First seed data.
 * @param size1 Size of the first seed data.
 * @param seed_data_2 Second seed data (optional).
 * @param size2 Size of the second seed data (optional).
 * @return void
 */
static void prng_seed(uint32_t* state, const uint8_t* seed_data_1, size_t size1, const uint8_t* seed_data_2, size_t size2) {
    uint8_t combined_seed[size1 + size2];
    memcpy(combined_seed, seed_data_1, size1);
    if (seed_data_2 && size2 > 0) {
        memcpy(combined_seed + size1, seed_data_2, size2);
    }
    uint8_t hash[HATT_HASH_SIZE_BYTES];
    const uint8_t* chunks[] = {combined_seed};
    const size_t sizes[] = {sizeof(combined_seed)};
    hatt_sha256(chunks, sizes, 1, hash);
    memcpy(state, hash, sizeof(uint32_t));
}

static uint32_t prng_get_random(uint32_t* state) {
    *state = (1103515245 * (*state) + 12345) & 0x7FFFFFFF;
    return *state;
}

static void hatt_compute_sigma(uint8_t *sigma_output, const uint8_t *memory, const uint8_t *puf_response_r, const uint8_t *s_beta, const uint8_t *s_omega, uint32_t* prng_state_ptr) {
    uint8_t xor_seed[HATT_SEED_SIZE_BYTES];
    for(int i=0; i < HATT_SEED_SIZE_BYTES; i++) {
        xor_seed[i] = s_beta[i] ^ puf_response_r[i];
    }
    prng_seed(prng_state_ptr, xor_seed, sizeof(xor_seed), NULL, 0);

    const int num_blocks = HATT_MEMORY_SIZE_BYTES / HATT_MEMORY_BLOCK_SIZE_BYTES;
    int *rho = malloc(num_blocks * sizeof(int));
    if (!rho) return;
    
    for (int i = 0; i < num_blocks; ++i) rho[i] = i;
    for (int i = num_blocks - 1; i > 0; i--) {
        int j = prng_get_random(prng_state_ptr) % (i + 1);
        int temp = rho[i]; rho[i] = rho[j]; rho[j] = temp;
    }

    int sigma_bit_idx = 0;
    memset(sigma_output, 0, HATT_SIGMA_SIZE_BYTES);

    for (int i = 0; i < num_blocks; ++i) {
        int block_idx = rho[i];
        
        uint8_t rho_i_bytes[sizeof(int)];
        memcpy(rho_i_bytes, &rho[i], sizeof(int));
        for(int k=0; k < HATT_SEED_SIZE_BYTES; k++) {
            xor_seed[k] = s_omega[k] ^ rho_i_bytes[k % sizeof(int)];
        }
        prng_seed(prng_state_ptr, xor_seed, sizeof(xor_seed), NULL, 0);

        const int total_bits_in_block = HATT_MEMORY_BLOCK_SIZE_BYTES * 8;
        int *omega = malloc(total_bits_in_block * sizeof(int));
        if (!omega) continue;
        
        for (int j = 0; j < total_bits_in_block; ++j) omega[j] = j;
        for (int j = total_bits_in_block - 1; j > 0; j--) {
            int k = prng_get_random(prng_state_ptr) % (j + 1);
            int temp = omega[j]; omega[j] = omega[k]; omega[k] = temp;
        }

        const uint8_t *block_ptr = memory + (block_idx * HATT_MEMORY_BLOCK_SIZE_BYTES);
        for (int j = 0; j < HATT_BITS_PER_BLOCK_TO_SAMPLE; ++j) {
            int bit_idx = omega[j];
            bool val = (block_ptr[bit_idx / 8] >> (bit_idx % 8)) & 1;
            if (val) {
                sigma_output[sigma_bit_idx / 8] |= (1 << (sigma_bit_idx % 8));
            }
            sigma_bit_idx++;
        }
        free(omega);
    }
    free(rho);
}

/**
 * @brief Initializes a Prover's state for an attestation session.
 * @param s Pointer to the Prover's state structure.
 * @param my_ip The IP address of this node, used as its device ID.
 * @return void
 */
static void prover_init(ProverState_t *s, const char* my_ip) {
    strncpy(s->device_id, my_ip, HATT_MAX_ID_LEN -1);
    s->device_id[HATT_MAX_ID_LEN - 1] = '\0';
    for (int i = 0; i < HATT_MEMORY_SIZE_BYTES; ++i) s->memory[i] = (uint8_t)i;
    
    if (force_tamper_memory) {
        s->memory[0] ^= 0xFF;
    }
    esp_read_mac(s->puf_secret, ESP_MAC_WIFI_STA);
}

/**
 * @brief Initializes a Verifier's state for an attestation session.
 * @param s Pointer to the Verifier's state structure.
 * @param my_ip The IP address of this node, used as the Verifier's ID.
 * @param prover_ip The IP address of the Prover, used as its ID on record.
 * @return void
 */
static void verifier_init(VerifierState_t *s, const char* my_ip, const char* prover_ip) {
    strncpy(s->verifier_id, my_ip, HATT_MAX_ID_LEN - 1);
    s->verifier_id[HATT_MAX_ID_LEN - 1] = '\0';
    strncpy(s->prover_id_on_record, prover_ip, HATT_MAX_ID_LEN - 1);
    s->prover_id_on_record[HATT_MAX_ID_LEN - 1] = '\0';
    for (int i = 0; i < HATT_MEMORY_SIZE_BYTES; ++i) s->prover_golden_image[i] = (uint8_t)i;
}

/**
 * @brief Verifier creates Message 1 to initiate the protocol.
 * @param s Pointer to the Verifier's state.
 * @param m1 Pointer to the Message1_t structure to be populated.
 * @return void
 */
static void verifier_create_message1(VerifierState_t *s, Message1_t *m1) {
    uint8_t nid[HATT_NONCE_SIZE_BYTES];
    uint8_t k_enc[HATT_HASH_SIZE_BYTES], k_mac[HATT_HASH_SIZE_BYTES];
    uint8_t iv[16] = {0};

    esp_fill_random(s->s_beta, sizeof(s->s_beta));
    esp_fill_random(s->s_omega, sizeof(s->s_omega));
    esp_fill_random(s->n1, sizeof(s->n1));
    esp_fill_random(nid, sizeof(nid));
    
    hatt_kdf(s->puf_response_r, k_enc, k_mac); 

    strncpy(m1->verifier_id, s->verifier_id, HATT_MAX_ID_LEN -1);
    m1->verifier_id[HATT_MAX_ID_LEN-1] = '\0';
    memcpy(m1->nonce_n_id, nid, sizeof(nid));
    
    const uint8_t *pc[] = {(uint8_t *)s->prover_id_on_record, s->puf_response_r, nid};
    const size_t pcs[] = {strlen(s->prover_id_on_record), HATT_PUF_RESPONSE_SIZE_BYTES, HATT_NONCE_SIZE_BYTES};
    hatt_sha256(pc, pcs, 3, m1->pid);

    uint8_t m1_plaintext[sizeof(m1->encrypted_payload)];
    memcpy(m1_plaintext, s->s_beta, HATT_SEED_SIZE_BYTES);
    memcpy(m1_plaintext + HATT_SEED_SIZE_BYTES, s->s_omega, HATT_SEED_SIZE_BYTES);
    memcpy(m1_plaintext + HATT_SEED_SIZE_BYTES * 2, s->n1, HATT_NONCE_SIZE_BYTES);
    hatt_aes_crypt(true, k_enc, iv, m1_plaintext, sizeof(m1_plaintext), m1->encrypted_payload);

    const uint8_t *i1c[] = {(uint8_t*)s->verifier_id, (uint8_t*)s->prover_id_on_record, (uint8_t*)m1, s->n1, s->puf_response_r};
    const size_t i1cs[] = {strlen(s->verifier_id), strlen(s->prover_id_on_record), sizeof(Message1_t) - HATT_HASH_SIZE_BYTES, HATT_NONCE_SIZE_BYTES, HATT_PUF_RESPONSE_SIZE_BYTES};
    hatt_hmac_sha256(k_mac, i1c, i1cs, 5, m1->auth_tag_i1);
}

/**
 * @brief Verifier handles Message 2 from the Prover and creates Message 3.
 * @param s Pointer to the Verifier's state.
 * @param m2 Pointer to the received Message2_t.
 * @param m3 Pointer to the Message3_t structure to be populated.
 * @return true if Message 2 is valid, false otherwise.
 */
static bool verifier_handle_message2(VerifierState_t *s, const Message2_t *m2, Message3_t *m3) {
    uint8_t k_enc[HATT_HASH_SIZE_BYTES], k_mac[HATT_HASH_SIZE_BYTES];
    hatt_kdf(s->puf_response_r, k_enc, k_mac);
    
    uint8_t iv[16] = {0};
    uint8_t m2_decrypted[sizeof(m2->encrypted_payload)];
    if (hatt_aes_crypt(false, k_enc, iv, m2->encrypted_payload, sizeof(m2->encrypted_payload), m2_decrypted) != 0) return false;
    
    if (memcmp(m2_decrypted + HATT_MAX_ID_LEN, s->n1, HATT_NONCE_SIZE_BYTES) != 0) return false;
    memcpy(s->n2, m2_decrypted + HATT_MAX_ID_LEN + HATT_NONCE_SIZE_BYTES, HATT_NONCE_SIZE_BYTES);
    
    const uint8_t *i2c[] = {(uint8_t*)s->prover_id_on_record, (uint8_t*)s->verifier_id, m2->encrypted_payload, s->n1, s->n2, s->puf_response_r};
    const size_t i2cs[] = {strlen(s->prover_id_on_record), strlen(s->verifier_id), sizeof(m2->encrypted_payload), HATT_NONCE_SIZE_BYTES, HATT_NONCE_SIZE_BYTES, HATT_PUF_RESPONSE_SIZE_BYTES};
    uint8_t i2_recalculated[HATT_HASH_SIZE_BYTES];
    hatt_hmac_sha256(k_mac, i2c, i2cs, 6, i2_recalculated);

    if (memcmp(i2_recalculated, m2->auth_tag_i2, HATT_HASH_SIZE_BYTES) != 0) return false;

    const uint8_t *i3c[] = {s->n1, s->n2, s->puf_response_r};
    const size_t i3cs[] = {HATT_NONCE_SIZE_BYTES, HATT_NONCE_SIZE_BYTES, HATT_PUF_RESPONSE_SIZE_BYTES};
    hatt_hmac_sha256(k_mac, i3c, i3cs, 3, m3->auth_tag_i3);
    return true;
}

/**
 * @brief Verifier handles Message 4 and performs the final attestation check.
 * @param s Pointer to the Verifier's state.
 * @param m4 Pointer to the received Message4_t.
 * @return true if Message 4 is valid and the attestation succeeds, false otherwise.
 */
static bool verifier_handle_message4(VerifierState_t *s, const Message4_t *m4) {
    uint8_t k_enc[HATT_HASH_SIZE_BYTES], k_mac[HATT_HASH_SIZE_BYTES];
    hatt_kdf(s->puf_response_r, k_enc, k_mac);

    const uint8_t *i4c[] = {(uint8_t*)s->prover_id_on_record, (uint8_t*)s->verifier_id, m4->encrypted_payload, s->puf_response_r};
    const size_t i4cs[] = {strlen(s->prover_id_on_record), strlen(s->verifier_id), sizeof(m4->encrypted_payload), HATT_PUF_RESPONSE_SIZE_BYTES};
    uint8_t i4_recalculated[HATT_HASH_SIZE_BYTES];
    hatt_hmac_sha256(k_mac, i4c, i4cs, 4, i4_recalculated);

    if (memcmp(i4_recalculated, m4->auth_tag_i4, HATT_HASH_SIZE_BYTES) != 0) return false;

    uint8_t iv[16] = {0};
    uint8_t m4_decrypted[sizeof(m4->encrypted_payload)];
    if (hatt_aes_crypt(false, k_enc, iv, m4->encrypted_payload, sizeof(m4->encrypted_payload), m4_decrypted) != 0) return false;

    uint8_t prover_sigma[HATT_SIGMA_SIZE_BYTES];
    memcpy(prover_sigma, m4_decrypted, HATT_SIGMA_SIZE_BYTES);
    
    uint8_t verifier_sigma[HATT_SIGMA_SIZE_BYTES];
    hatt_compute_sigma(verifier_sigma, s->prover_golden_image, s->puf_response_r, s->s_beta, s->s_omega, &s->prng_state);

    return (memcmp(prover_sigma, verifier_sigma, HATT_SIGMA_SIZE_BYTES) == 0);
}

/**
 * @brief Prover handles Message 1 and creates Message 2.
 * @param s Pointer to the Prover's state.
 * @param m1 Pointer to the received Message1_t.
 * @param ch The secret challenge used for this session.
 * @param m2 Pointer to the Message2_t structure to be populated.
 * @return true if Message 1 is valid, false otherwise.
 */
static bool prover_handle_message1(ProverState_t *s, const Message1_t *m1, Message2_t *m2) {
    uint8_t k_enc[HATT_HASH_SIZE_BYTES], k_mac[HATT_HASH_SIZE_BYTES];
    uint8_t iv[16] = {0};
    
    uint8_t challenge_to_use[HATT_CHALLENGE_SIZE_BYTES];
    memcpy(challenge_to_use, SHARED_HATT_CHALLENGE, HATT_CHALLENGE_SIZE_BYTES);

    bool specific_challenge_found = db_get_challenge_for_verifier(m1->verifier_id, (char*)challenge_to_use, HATT_CHALLENGE_SIZE_BYTES);

    if (specific_challenge_found) {
        ESP_LOGI(TAG, "Using specific challenge from DB for verifier %s", m1->verifier_id);
        memset(s->puf_response_r, 0, sizeof(s->puf_response_r));
        simulate_puf_response(challenge_to_use, HATT_CHALLENGE_SIZE_BYTES, (char *)s->puf_response_r);
    } else {
        ESP_LOGW(TAG, "No specific challenge found for verifier %s, using default shared challenge (BOOTSTRAP MODE).", m1->verifier_id);
        memcpy(s->puf_response_r, SHARED_HATT_CHALLENGE, HATT_PUF_RESPONSE_SIZE_BYTES);
    }
    
    hatt_kdf(s->puf_response_r, k_enc, k_mac);

    uint8_t m1_decrypted[sizeof(m1->encrypted_payload)];
    if (hatt_aes_crypt(false, k_enc, iv, m1->encrypted_payload, sizeof(m1->encrypted_payload), m1_decrypted) != 0) {
        return false;
    }
    
    memcpy(s->s_beta, m1_decrypted, HATT_SEED_SIZE_BYTES);
    memcpy(s->s_omega, m1_decrypted + HATT_SEED_SIZE_BYTES, HATT_SEED_SIZE_BYTES);
    memcpy(s->n1, m1_decrypted + HATT_SEED_SIZE_BYTES * 2, HATT_NONCE_SIZE_BYTES);
    
    const uint8_t *i1c[] = {(uint8_t*)m1->verifier_id, (uint8_t*)s->device_id, (uint8_t*)m1, s->n1, s->puf_response_r};
    const size_t i1cs[] = {strlen(m1->verifier_id), strlen(s->device_id), sizeof(Message1_t) - HATT_HASH_SIZE_BYTES, HATT_NONCE_SIZE_BYTES, HATT_PUF_RESPONSE_SIZE_BYTES};
    uint8_t i1_recalculated[HATT_HASH_SIZE_BYTES];

    hatt_hmac_sha256(k_mac, i1c, i1cs, 5, i1_recalculated);
    if (memcmp(i1_recalculated, m1->auth_tag_i1, HATT_HASH_SIZE_BYTES) != 0) {
        return false;
    }
    
    esp_fill_random(s->n2, sizeof(s->n2));

    uint8_t m2_plaintext[sizeof(m2->encrypted_payload)] = {0};
    memcpy(m2_plaintext, s->device_id, strlen(s->device_id));
    memcpy(m2_plaintext + HATT_MAX_ID_LEN, s->n1, HATT_NONCE_SIZE_BYTES);
    memcpy(m2_plaintext + HATT_MAX_ID_LEN + HATT_NONCE_SIZE_BYTES, s->n2, HATT_NONCE_SIZE_BYTES);
    hatt_aes_crypt(true, k_enc, iv, m2_plaintext, sizeof(m2_plaintext), m2->encrypted_payload);

    const uint8_t *i2c[] = {(uint8_t*)s->device_id, (uint8_t*)m1->verifier_id, m2->encrypted_payload, s->n1, s->n2, s->puf_response_r};
    const size_t i2cs[] = {strlen(s->device_id), strlen(m1->verifier_id), sizeof(m2->encrypted_payload), HATT_NONCE_SIZE_BYTES, HATT_NONCE_SIZE_BYTES, HATT_PUF_RESPONSE_SIZE_BYTES};
    hatt_hmac_sha256(k_mac, i2c, i2cs, 6, m2->auth_tag_i2);

    return true;
}

/**
 * @brief Prover handles Message 3 and creates Message 4.
 * @param s Pointer to the Prover's state.
 * @param m3 Pointer to the received Message3_t.
 * @param verifier_id The ID of the Verifier, used for authenticating messages.
 * @param m4 Pointer to the Message4_t structure to be populated.
 * @return true if Message 3 is valid, false otherwise.
 */
static bool prover_handle_message3(ProverState_t *s, const Message3_t *m3, const char* verifier_id, Message4_t *m4) {
    uint8_t k_enc[HATT_HASH_SIZE_BYTES], k_mac[HATT_HASH_SIZE_BYTES];
    hatt_kdf(s->puf_response_r, k_enc, k_mac);

    const uint8_t *i3c[] = {s->n1, s->n2, s->puf_response_r};
    const size_t i3cs[] = {HATT_NONCE_SIZE_BYTES, HATT_NONCE_SIZE_BYTES, HATT_PUF_RESPONSE_SIZE_BYTES};
    uint8_t i3_recalculated[HATT_HASH_SIZE_BYTES];
    hatt_hmac_sha256(k_mac, i3c, i3cs, 3, i3_recalculated);

    if (memcmp(i3_recalculated, m3->auth_tag_i3, HATT_HASH_SIZE_BYTES) != 0) return false;

    uint8_t prover_sigma[HATT_SIGMA_SIZE_BYTES];
    hatt_compute_sigma(prover_sigma, s->memory, s->puf_response_r, s->s_beta, s->s_omega, &s->prng_state);

    uint8_t m4_plaintext[sizeof(m4->encrypted_payload)];
    uint8_t iv[16] = {0};
    memcpy(m4_plaintext, prover_sigma, HATT_SIGMA_SIZE_BYTES);
    memcpy(m4_plaintext + HATT_SIGMA_SIZE_BYTES, s->n1, HATT_NONCE_SIZE_BYTES);
    memcpy(m4_plaintext + HATT_SIGMA_SIZE_BYTES + HATT_NONCE_SIZE_BYTES, s->n2, HATT_NONCE_SIZE_BYTES);
    hatt_aes_crypt(true, k_enc, iv, m4_plaintext, sizeof(m4_plaintext), m4->encrypted_payload);

    const uint8_t *i4c[] = {(uint8_t*)s->device_id, (uint8_t*)verifier_id, m4->encrypted_payload, s->puf_response_r};
    const size_t i4cs[] = {strlen(s->device_id), strlen(verifier_id), sizeof(m4->encrypted_payload), HATT_PUF_RESPONSE_SIZE_BYTES};
    hatt_hmac_sha256(k_mac, i4c, i4cs, 4, m4->auth_tag_i4);
    
    return true;
}

/**
 * @brief Handles a full attestation session from the Prover's perspective.
 * @param sock The connected socket file descriptor for the session with the Verifier.
 * @return void
 */
static void handle_prover_session(const int sock) {
    Message1_t* msg1 = malloc(sizeof(Message1_t));
    Message2_t* msg2 = malloc(sizeof(Message2_t));
    Message3_t* msg3 = malloc(sizeof(Message3_t));
    Message4_t* msg4 = malloc(sizeof(Message4_t));
    ProverState_t* prover_state = malloc(sizeof(ProverState_t));
    
    if (!msg1 || !msg2 || !msg3 || !msg4 || !prover_state) {
        ESP_LOGE(TAG, "Verifier: Failed to allocate memory for HAtt structs.");
        if (msg1) free(msg1);
        if (msg2) free(msg2);
        if (msg3) free(msg3);
        if (msg4) free(msg4);
        if (prover_state) free(prover_state);
        return;
    }

    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));
    prover_init(prover_state, my_ip);

    ESP_LOGI(TAG, "Prover session started on socket %d", sock);
    if (read(sock, msg1, sizeof(Message1_t)) <= 0) { ESP_LOGE(TAG, "Prover: read Message1 failed."); goto CLEAN_UP; }
    
    if (!prover_handle_message1(prover_state, msg1, msg2)) { ESP_LOGE(TAG, "Prover: Failed to process Message 1."); goto CLEAN_UP; }
    
    if (write(sock, msg2, sizeof(Message2_t)) <= 0) { ESP_LOGE(TAG, "Prover: write Message2 failed."); goto CLEAN_UP; }
    ESP_LOGD(TAG, "Prover: Sent Message 2.");
    
    if (read(sock, msg3, sizeof(Message3_t)) <= 0) { ESP_LOGE(TAG, "Prover: read Message3 failed."); goto CLEAN_UP; }
    
    if (!prover_handle_message3(prover_state, msg3, msg1->verifier_id, msg4)) { ESP_LOGE(TAG, "Prover: Failed to process Message 3."); goto CLEAN_UP; }
    
    if (write(sock, msg4, sizeof(Message4_t)) <= 0) { ESP_LOGE(TAG, "Prover: write Message4 failed."); goto CLEAN_UP; }
    ESP_LOGI(TAG, "Prover: Sent Message 4. Session complete on socket %d.", sock);

CLEAN_UP:
    if (msg1) free(msg1);
    if (msg2) free(msg2);
    if (msg3) free(msg3);
    if (msg4) free(msg4);
    if (prover_state) free(prover_state);
}

/**
 * @brief A FreeRTOS task that manages a single, complete HAtt prover session with a connected Verifier.
 * @details This function serves as the entry point for a dedicated task created for each
 * incoming Verifier connection. It receives the connected socket descriptor as its
 * parameter, executes the entire blocking `handle_prover_session` logic, and then
 * performs all necessary cleanup. After closing the socket, the task deletes itself,
 * freeing its resources. This one-shot task model allows the main server to handle
 * multiple attestation requests concurrently.
 * @param pvParameters A void pointer to the connected client socket descriptor. This is cast
 * to an integer (`int`).
 * @return void
 */
static void prover_session_task(void *pvParameters) {
    int sock = (int)pvParameters;
    handle_prover_session(sock);
    shutdown(sock, 0);
    close(sock);
    vTaskDelete(NULL);
}

/**
 * @brief A background task that runs the Prover's server side, listening for Verifier connections.
 * @param pvParameters Unused task parameters.
 */
static void prover_task(void *pvParameters) {
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(HATT_PORT);

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0) { ESP_LOGE(TAG, "Prover: Unable to create socket."); vTaskDelete(NULL); return; }
    if (bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) { ESP_LOGE(TAG, "Prover: Unable to bind socket."); close(listen_sock); vTaskDelete(NULL); return; }
    if (listen(listen_sock, 5) != 0) { ESP_LOGE(TAG, "Prover: Error during listen."); close(listen_sock); vTaskDelete(NULL); return; }
    
    ESP_LOGI(TAG, "PROVER TASK STARTED: Listening on port %d", HATT_PORT);

    while (1) {
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr); 
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
        if (sock < 0) { 
            ESP_LOGE(TAG, "Prover: Unable to accept connection: %s", strerror(errno));
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        xTaskCreate(prover_session_task, "hatt_session", 4096, (void*)sock, 5, NULL);
    }
    close(listen_sock);
    vTaskDelete(NULL);
}

/**
 * @brief Starts the background task for the HAtt Prover.
 * @details This task listens for incoming attestation requests on the dedicated HAtt port
 * and handles the full 4-message protocol exchange for any connecting Verifier.
 * @return void
 */
void hatt_prover_start_task(void) {
    xTaskCreate(prover_task, "hatt_prover_task", 4096, NULL, 5, NULL);
}

/**
 * @brief Runs a full attestation protocol from the Verifier's perspective.
 * @details This function connects to a Prover, executes the 4-message exchange,
 * and verifies the integrity of the Prover's memory based on its golden image.
 * This is a blocking function that returns only after the protocol completes or fails.
 * @param prover_ip The IP address of the Prover node to attest.
 * @return true if the attestation is successful and the Prover is deemed honest, false otherwise.
 */
bool hatt_verifier_run_attestation(const char *prover_ip) {
    ESP_LOGI(TAG, "Verifier: Starting attestation for Prover at %s", prover_ip);
    Message1_t* msg1 = malloc(sizeof(Message1_t));
    Message2_t* msg2 = malloc(sizeof(Message2_t));
    Message3_t* msg3 = malloc(sizeof(Message3_t));
    Message4_t* msg4 = malloc(sizeof(Message4_t));
    VerifierState_t* verifier_state = malloc(sizeof(VerifierState_t));
    
    if (!msg1 || !msg2 || !msg3 || !msg4 || !verifier_state) {
        ESP_LOGE(TAG, "Verifier: Failed to allocate memory for HAtt structs.");
        if (msg1) free(msg1);
        if (msg2) free(msg2);
        if (msg3) free(msg3);
        if (msg4) free(msg4);
        if (verifier_state) free(verifier_state);
        return false;
    }

    CRPNode *stored_crp = db_get_random_crp_for_node(prover_ip);
    
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));
    verifier_init(verifier_state, my_ip, prover_ip);

    if (stored_crp) {
        ESP_LOGI(TAG, "Verifier: Found stored CRP for %s. Using NORMAL mode.", prover_ip);
        strncpy((char*)verifier_state->puf_response_r, stored_crp->response, HATT_PUF_RESPONSE_SIZE_BYTES);
        free(stored_crp);
    } else {
        ESP_LOGW(TAG, "Verifier: No CRP found for %s. Using BOOTSTRAP/TEST mode (Shared Secret).", prover_ip);
        memcpy(verifier_state->puf_response_r, SHARED_HATT_CHALLENGE, HATT_PUF_RESPONSE_SIZE_BYTES);
    }

    int sock;
    bool success = false;
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(prover_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(HATT_PORT);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) { ESP_LOGE(TAG, "Verifier: Unable to create socket."); goto CLEAN_UP; }
    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) { ESP_LOGE(TAG, "Verifier: Unable to connect."); close(sock); goto CLEAN_UP; }
    
    ESP_LOGI(TAG, "Verifier: Successfully connected to Prover.");
    
    verifier_create_message1(verifier_state, msg1);

    if (write(sock, msg1, sizeof(Message1_t)) < 0) { ESP_LOGE(TAG, "Verifier: write Message1 failed"); goto CLEAN_UP; }
    ESP_LOGD(TAG, "Verifier: Sent Message 1");
    
    if (read(sock, msg2, sizeof(Message2_t)) <= 0) { ESP_LOGE(TAG, "Verifier: read Message2 failed"); goto CLEAN_UP; }
    
    if (!verifier_handle_message2(verifier_state, msg2, msg3)) { ESP_LOGE(TAG, "Verifier: Failed to process Message 2"); goto CLEAN_UP; }
    
    if (write(sock, msg3, sizeof(Message3_t)) < 0) { ESP_LOGE(TAG, "Verifier: write Message3 failed"); goto CLEAN_UP; }
    ESP_LOGD(TAG, "Verifier: Sent Message 3");
    
    if (read(sock, msg4, sizeof(Message4_t)) <= 0) { ESP_LOGE(TAG, "Verifier: read Message4 failed"); goto CLEAN_UP; }

    success = verifier_handle_message4(verifier_state, msg4);

CLEAN_UP:
    ESP_LOGI(TAG, "Verifier: Connection closed. Attestation result: %s", success ? "PASSED" : "FAILED");
    if (sock >= 0) {
        close(sock);
    }

    if (msg1) free(msg1);
    if (msg2) free(msg2);
    if (msg3) free(msg3);
    if (msg4) free(msg4);
    if (verifier_state) free(verifier_state);
    return success;
}