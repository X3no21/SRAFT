/* =============================
 * File: hatt_protocol.c
 * Description: Implements the HAtt hybrid remote attestation protocol.
 * ============================= */

#include "hatt_protocol.h"
#include "attestation_test_region.h"
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_image_format.h"
#include "freertos/semphr.h"
#include "psa/crypto.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "utility.h"
#include "auth_db.h"
#include "auth_join.h"
#include "raft_state.h"

static const char *TAG = "HATT_PROTOCOL";

// Part of the network-access credential provisioned to every device (A1), in the gitignored
// main/esp32_config/network_secret.h. It keys the attestations made by a device that holds no CRP
// of the Prover (voters, checks of the Coordinator).
#if __has_include("network_secret.h")
#include "network_secret.h"
#endif
#ifndef SRAFT_NETWORK_SECRET
#warning "network_secret.h not found: the attestations without a CRP use a placeholder secret (see README)"
#define SRAFT_NETWORK_SECRET { 0x5A }
#endif
static const uint8_t NETWORK_SECRET[HATT_HASH_SIZE_BYTES] = SRAFT_NETWORK_SECRET;


static SemaphoreHandle_t hatt_mem_mutex = NULL;
static SemaphoreHandle_t hatt_sigma_mutex = NULL;
static portMUX_TYPE hatt_block_lock = portMUX_INITIALIZER_UNLOCKED;

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
 * @brief Key of an attestation made by a device that holds no CRP of the Prover.
 * @details It is derived from the network secret and from the identities of the two devices. The Prover
 * always uses its own identity, so a device that forwards a request to another device does not obtain a
 * proof valid for itself, and a device without the network secret cannot complete the exchange.
 * @param verifier_id Identity of the attesting device.
 * @param prover_id Identity of the attested device.
 * @param out Buffer of HATT_PUF_RESPONSE_SIZE_BYTES bytes, used in place of the PUF response.
 */
static void hatt_network_response(const char *verifier_id, const char *prover_id, uint8_t *out) {
    static const char label[] = "SRAFT-HATT-NETWORK";
    // The terminating zeros separate the fields.
    const uint8_t *chunks[] = {(const uint8_t *)label, (const uint8_t *)verifier_id, (const uint8_t *)prover_id};
    const size_t sizes[] = {sizeof(label), strlen(verifier_id) + 1, strlen(prover_id) + 1};
    uint8_t mac[HATT_HASH_SIZE_BYTES];
    hatt_hmac_sha256(NETWORK_SECRET, chunks, sizes, 3, mac);
    memcpy(out, mac, HATT_PUF_RESPONSE_SIZE_BYTES);
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
    uint32_t x = *state ? *state : 0x9E3779B9u;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint32_t hatt_mix32(uint32_t x) {
    x ^= x >> 16; x *= 0x85EBCA6Bu;
    x ^= x >> 13; x *= 0xC2B2AE35u;
    x ^= x >> 16;
    return x;
}

/**
 * @brief Keyed permutation of the block numbers 0..n-1 (Feistel network with cycle walking).
 * @details It gives the i-th element of the permutation rho without storing rho, so that a
 * measurement needs no memory proportional to the number of blocks.
 */
static uint32_t hatt_permute(uint32_t i, uint32_t n, uint32_t half_bits, uint32_t key) {
    const uint32_t mask = (1u << half_bits) - 1;
    uint32_t x = i;
    do {
        uint32_t l = x >> half_bits, r = x & mask;
        for (uint32_t round = 0; round < 4; round++) {
            uint32_t f = hatt_mix32(key + r * 0x9E3779B1u + round) & mask;
            uint32_t t = l ^ f;
            l = r;
            r = t;
        }
        x = (l << half_bits) | r;
    } while (x >= n);
    return x;
}

/**
 * @brief Maps the firmware image of the running application, i.e., the memory attested by HAtt.
 * @details The image is mapped once and the mapping is kept. Every device runs the same firmware,
 * so a Verifier uses its own image as the reference copy of the memory of the Prover.
 * @param image Output pointer to the first byte of the image.
 * @param image_len Output length of the image in bytes.
 * @return true if the image is available, false otherwise.
 */
static bool hatt_get_attested_memory(const uint8_t **image, size_t *image_len) {
    static const uint8_t *mapped = NULL;
    static size_t mapped_len = 0;

    if (!hatt_mem_mutex || !hatt_sigma_mutex) return false;
    xSemaphoreTake(hatt_mem_mutex, portMAX_DELAY);
    if (!mapped) {
        const esp_partition_t *part = esp_ota_get_running_partition();
        esp_image_metadata_t meta;
        const void *ptr = NULL;
        esp_partition_mmap_handle_t handle;
        if (part) {
            const esp_partition_pos_t pos = { .offset = part->address, .size = part->size };
            if (esp_image_get_metadata(&pos, &meta) == ESP_OK && meta.image_len > 0 && meta.image_len <= part->size &&
                esp_partition_mmap(part, 0, meta.image_len, ESP_PARTITION_MMAP_DATA, &ptr, &handle) == ESP_OK) {
                mapped = ptr;
                mapped_len = meta.image_len;
                // The SHA-256 digest appended to the image is derived from the image itself and is not
                // checked at run time, so it is not attested: a modification is detected only through
                // the code and data it changes.
                if (meta.image.hash_appended && mapped_len > HATT_HASH_SIZE_BYTES) {
                    mapped_len -= HATT_HASH_SIZE_BYTES;
                }
                ESP_LOGI(TAG, "Attested memory: firmware image of %u bytes, %u blocks of %d words.",
                         (unsigned)mapped_len, (unsigned)((mapped_len + HATT_MEMORY_BLOCK_SIZE_BYTES - 1) / HATT_MEMORY_BLOCK_SIZE_BYTES),
                         HATT_WORDS_PER_BLOCK);
            }
        }
    }
    xSemaphoreGive(hatt_mem_mutex);

    if (!mapped) {
        ESP_LOGE(TAG, "Cannot access the firmware image to attest.");
        return false;
    }
    *image = mapped;
    *image_len = mapped_len;
    return true;
}

/**
 * @brief Computes the verification bits of HAtt over the firmware image.
 * @details The image is divided in blocks of HATT_WORDS_PER_BLOCK words. In each iteration the blocks are visited
 * in the order given by a permutation seeded with S_beta xor R, and HATT_BITS_PER_WORD bits are read from every
 * word of a block at positions drawn from a generator seeded with S_omega xor the block number. The bits of all
 * iterations form the string sigma, which is compressed with SHA-256 so that the proof has a fixed size.
 * @param sigma_output Buffer of HATT_SIGMA_SIZE_BYTES that receives the digest of sigma.
 * @return true on success, false if the image cannot be read.
 */
static bool hatt_compute_sigma(uint8_t *sigma_output, const uint8_t *puf_response_r, const uint8_t *s_beta, const uint8_t *s_omega, uint32_t* prng_state_ptr) {
    const int64_t wait_start_us = esp_timer_get_time();
    const uint8_t *image = NULL;
    size_t image_len = 0;
    if (!hatt_get_attested_memory(&image, &image_len)) return false;

    const size_t num_blocks = (image_len + HATT_MEMORY_BLOCK_SIZE_BYTES - 1) / HATT_MEMORY_BLOCK_SIZE_BYTES;
    if (num_blocks < 2) return false;
    uint32_t half_bits = 1;
    while ((1ull << (2 * half_bits)) < num_blocks) half_bits++;

    // One measurement at a time on a device; the others wait their turn.
    xSemaphoreTake(hatt_sigma_mutex, portMAX_DELAY);
    const int64_t measure_start_us = esp_timer_get_time();

    uint8_t xor_beta[HATT_SEED_SIZE_BYTES];
    for (int i = 0; i < HATT_SEED_SIZE_BYTES; i++) xor_beta[i] = s_beta[i] ^ puf_response_r[i];

    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_hash_setup(&op, PSA_ALG_SHA_256);
    uint8_t bits[64];
    size_t bit_idx = 0;
    memset(bits, 0, sizeof(bits));

    for (uint8_t iter = 0; iter < HATT_ITERATIONS; iter++) {
        // Permutation rho of the block numbers, seeded with S_beta xor R.
        prng_seed(prng_state_ptr, xor_beta, sizeof(xor_beta), &iter, sizeof(iter));
        const uint32_t rho_key = *prng_state_ptr;

        uint32_t omega_base = 0;
        prng_seed(&omega_base, s_omega, HATT_SEED_SIZE_BYTES, &iter, sizeof(iter));

        for (size_t i = 0; i < num_blocks; ++i) {
            const uint32_t rho_i = hatt_permute((uint32_t)i, (uint32_t)num_blocks, half_bits, rho_key);
            const size_t block_off = (size_t)rho_i * HATT_MEMORY_BLOCK_SIZE_BYTES;
            // Generator of the bit positions Omega, seeded with S_omega xor rho_i.
            uint32_t omega_state = hatt_mix32(omega_base ^ rho_i);
            uint8_t block[HATT_MEMORY_BLOCK_SIZE_BYTES];
            size_t avail = image_len - block_off;
            if (avail > sizeof(block)) avail = sizeof(block);

            // The measurement of a block is not interrupted, as required by HAtt.
            portENTER_CRITICAL(&hatt_block_lock);
            memcpy(block, image + block_off, avail);
            portEXIT_CRITICAL(&hatt_block_lock);
            if (avail < sizeof(block)) memset(block + avail, 0, sizeof(block) - avail);

            for (int w = 0; w < HATT_WORDS_PER_BLOCK; ++w) {
                uint32_t word;
                memcpy(&word, block + w * HATT_WORD_SIZE_BYTES, sizeof(word));
                for (int b = 0; b < HATT_BITS_PER_WORD; ++b) {
                    uint32_t pos = prng_get_random(&omega_state) >> 27;
                    if ((word >> pos) & 1u) bits[bit_idx / 8] |= (uint8_t)(1u << (bit_idx % 8));
                    if (++bit_idx == sizeof(bits) * 8) {
                        psa_hash_update(&op, bits, sizeof(bits));
                        memset(bits, 0, sizeof(bits));
                        bit_idx = 0;
                    }
                }
            }
        }
        vTaskDelay(1);
    }

    if (bit_idx > 0) psa_hash_update(&op, bits, (bit_idx + 7) / 8);
    size_t hash_len = 0;
    psa_status_t st = psa_hash_finish(&op, sigma_output, HATT_SIGMA_SIZE_BYTES, &hash_len);

    xSemaphoreGive(hatt_sigma_mutex);
    ESP_LOGI(TAG, "HATT_STAT measure blocks=%u wait_ms=%lld measure_ms=%lld", (unsigned)num_blocks,
             (long long)((measure_start_us - wait_start_us) / 1000), (long long)((esp_timer_get_time() - measure_start_us) / 1000));
    return st == PSA_SUCCESS;
}

/**
 * @brief Reads exactly len bytes from a socket.
 * @return true if all the bytes were read, false on error, timeout, or closed connection.
 */
static bool hatt_read_full(int sock, void *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        int n = read(sock, (uint8_t *)buf + done, len - done);
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

uint32_t hatt_measurement_timeout_ms(void) {
    // During the bootstrap the network state is still empty, so the devices known to Raft are counted too.
    int devices = db_get_node_count();
    int peers = raft_state_get_peer_count();
    if (peers > devices) devices = peers;
    if (devices < 1) devices = 1;
    return HATT_SOCKET_TIMEOUT_S * 1000u + (uint32_t)devices * HATT_MEASUREMENT_BUDGET_MS;
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

    memset(m1, 0, sizeof(Message1_t));
    strncpy(m1->verifier_id, s->verifier_id, HATT_MAX_ID_LEN -1);
    m1->verifier_id[HATT_MAX_ID_LEN-1] = '\0';
    strncpy(m1->challenge, s->challenge, HATT_MAX_CHALLENGE_LEN - 1);
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
static hatt_result_t verifier_handle_message4(VerifierState_t *s, const Message4_t *m4) {
    uint8_t k_enc[HATT_HASH_SIZE_BYTES], k_mac[HATT_HASH_SIZE_BYTES];
    hatt_kdf(s->puf_response_r, k_enc, k_mac);

    const uint8_t *i4c[] = {(uint8_t*)s->prover_id_on_record, (uint8_t*)s->verifier_id, m4->encrypted_payload, s->puf_response_r};
    const size_t i4cs[] = {strlen(s->prover_id_on_record), strlen(s->verifier_id), sizeof(m4->encrypted_payload), HATT_PUF_RESPONSE_SIZE_BYTES};
    uint8_t i4_recalculated[HATT_HASH_SIZE_BYTES];
    hatt_hmac_sha256(k_mac, i4c, i4cs, 4, i4_recalculated);

    // A message whose tag is not valid may come from anyone, so it proves nothing about the Prover.
    if (memcmp(i4_recalculated, m4->auth_tag_i4, HATT_HASH_SIZE_BYTES) != 0) return HATT_NO_ANSWER;

    uint8_t iv[16] = {0};
    uint8_t m4_decrypted[sizeof(m4->encrypted_payload)];
    if (hatt_aes_crypt(false, k_enc, iv, m4->encrypted_payload, sizeof(m4->encrypted_payload), m4_decrypted) != 0) return HATT_NO_ANSWER;

    if (!s->expected_sigma_ready) return HATT_NO_ANSWER;

    // The proof is authentic: the attestation is decided by comparing it with the expected one.
    return (memcmp(m4_decrypted, s->expected_sigma, HATT_SIGMA_SIZE_BYTES) == 0) ? HATT_PASSED : HATT_FAILED;
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
    
    // The Verifier names the challenge it holds. The Prover uses it only if the network state
    // assigns that challenge to that Verifier; the response itself never leaves the device.
    char named_challenge[HATT_MAX_CHALLENGE_LEN];
    memcpy(named_challenge, m1->challenge, HATT_MAX_CHALLENGE_LEN);
    named_challenge[HATT_MAX_CHALLENGE_LEN - 1] = '\0';

    if (named_challenge[0] != '\0' &&
        (db_cnode_exists(named_challenge, s->device_id, m1->verifier_id) || join_is_pending_challenge(m1->verifier_id, named_challenge))) {
        ESP_LOGI(TAG, "Using the challenge named by verifier %s", m1->verifier_id);
        char full_response[64] = {0};
        simulate_puf_response((const uint8_t *)named_challenge, strlen(named_challenge), full_response);
        memset(s->puf_response_r, 0, sizeof(s->puf_response_r));
        strncpy((char *)s->puf_response_r, full_response, HATT_PUF_RESPONSE_SIZE_BYTES);
    } else {
        ESP_LOGW(TAG, "No assigned challenge named by verifier %s, using the network key.", m1->verifier_id);
        char verifier_id[HATT_MAX_ID_LEN];
        memcpy(verifier_id, m1->verifier_id, sizeof(verifier_id));
        verifier_id[sizeof(verifier_id) - 1] = '\0';
        memset(s->puf_response_r, 0, sizeof(s->puf_response_r));
        hatt_network_response(verifier_id, s->device_id, s->puf_response_r);
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
    if (!hatt_compute_sigma(prover_sigma, s->puf_response_r, s->s_beta, s->s_omega, &s->prng_state)) return false;

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
    if (!hatt_read_full(sock, msg1, sizeof(Message1_t))) { ESP_LOGE(TAG, "Prover: read Message1 failed."); goto CLEAN_UP; }
    
    if (!prover_handle_message1(prover_state, msg1, msg2)) { ESP_LOGE(TAG, "Prover: Failed to process Message 1."); goto CLEAN_UP; }
    
    if (write(sock, msg2, sizeof(Message2_t)) <= 0) { ESP_LOGE(TAG, "Prover: write Message2 failed."); goto CLEAN_UP; }
    ESP_LOGD(TAG, "Prover: Sent Message 2.");
    
    if (!hatt_read_full(sock, msg3, sizeof(Message3_t))) { ESP_LOGE(TAG, "Prover: read Message3 failed."); goto CLEAN_UP; }
    
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
static void prover_session_task_body(int sock) {
    // A Verifier that opens a session and then stays silent must not keep it open forever.
    struct timeval io_timeout = { .tv_sec = HATT_SOCKET_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
    handle_prover_session(sock);
    shutdown(sock, 0);
    close(sock);
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
    if (listen(listen_sock, HATT_LISTEN_BACKLOG) != 0) { ESP_LOGE(TAG, "Prover: Error during listen."); close(listen_sock); vTaskDelete(NULL); return; }
    
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

        // Sessions are served one at a time: the Verifiers that connect meanwhile wait in the listen queue,
        // and the device never measures its memory for two Verifiers at once.
        prover_session_task_body(sock);
    }
    close(listen_sock);
    vTaskDelete(NULL);
}

/**
 * @brief Creates the locks of the attested memory; called before the first measurement.
 */
void hatt_init(void) {
    // Keeps the test region in the image (it is otherwise unreferenced and would be discarded by the linker).
    (void)*(volatile const uint8_t *)&sraft_attested_test_region[0];
    if (!hatt_mem_mutex) hatt_mem_mutex = xSemaphoreCreateMutex();
    if (!hatt_sigma_mutex) hatt_sigma_mutex = xSemaphoreCreateMutex();
}

/**
 * @brief Starts the background task for the HAtt Prover (once).
 * @details This task listens for incoming attestation requests on the dedicated HAtt port
 * and handles the full 4-message protocol exchange for any connecting Verifier.
 * @return void
 */
void hatt_prover_start_task(void) {
    static bool started = false;
    hatt_init();
    if (started) return;
    if (xTaskCreate(prover_task, "hatt_prover_task", 4096, NULL, 5, NULL) == pdPASS) {
        started = true;
    } else {
        ESP_LOGE(TAG, "Failed to create the HAtt Prover task.");
    }
}

/**
 * @brief SHA-256 digest of the attested memory, used by the tests to identify the image of a device.
 */
bool hatt_attested_image_digest(uint8_t digest[HATT_HASH_SIZE_BYTES]) {
    const uint8_t *image = NULL;
    size_t image_len = 0;
    hatt_init();
    if (!hatt_get_attested_memory(&image, &image_len)) return false;

    // The image is read from flash through a small buffer in RAM.
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS) return false;
    uint8_t chunk[256];
    for (size_t off = 0; off < image_len; off += sizeof(chunk)) {
        size_t n = image_len - off < sizeof(chunk) ? image_len - off : sizeof(chunk);
        memcpy(chunk, image + off, n);
        psa_hash_update(&op, chunk, n);
    }
    size_t hash_len = 0;
    return psa_hash_finish(&op, digest, HATT_HASH_SIZE_BYTES, &hash_len) == PSA_SUCCESS;
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
    return hatt_verifier_run_attestation_with_crp(prover_ip, NULL);
}

bool hatt_verifier_run_attestation_with_crp(const char *prover_ip, const CRPNode *enrolled_crp) {
    return hatt_verifier_attest(prover_ip, enrolled_crp) == HATT_PASSED;
}

hatt_result_t hatt_verifier_attest(const char *prover_ip, const CRPNode *enrolled_crp) {
    const int64_t attest_start_us = esp_timer_get_time();
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
        return HATT_NO_ANSWER;
    }

    CRPNode *stored_crp = NULL;
    if (enrolled_crp) {
        stored_crp = malloc(sizeof(CRPNode));
        if (stored_crp) memcpy(stored_crp, enrolled_crp, sizeof(CRPNode));
    } else {
        stored_crp = db_get_random_crp_for_node(prover_ip);
    }
    
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));
    verifier_init(verifier_state, my_ip, prover_ip);
    memset(verifier_state->challenge, 0, sizeof(verifier_state->challenge));

    if (stored_crp) {
        ESP_LOGI(TAG, "Verifier: Found stored CRP for %s. Using NORMAL mode.", prover_ip);
        memset(verifier_state->puf_response_r, 0, sizeof(verifier_state->puf_response_r));
        strncpy((char*)verifier_state->puf_response_r, stored_crp->response, HATT_PUF_RESPONSE_SIZE_BYTES);
        strncpy(verifier_state->challenge, stored_crp->challenge, HATT_MAX_CHALLENGE_LEN - 1);
        free(stored_crp);
    } else {
        ESP_LOGW(TAG, "Verifier: No CRP found for %s. Using the network key.", prover_ip);
        memset(verifier_state->puf_response_r, 0, sizeof(verifier_state->puf_response_r));
        hatt_network_response(my_ip, prover_ip, verifier_state->puf_response_r);
    }

    int sock;
    hatt_result_t result = HATT_NO_ANSWER;
    verifier_state->expected_sigma_ready = false;
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(prover_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(HATT_PORT);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) { ESP_LOGE(TAG, "Verifier: Unable to create socket."); goto CLEAN_UP; }

    // A Prover that accepts the connection and then stays silent must not block the Verifier. The Prover
    // serves one Verifier at a time, so the first answer may also wait for the sessions queued before this one.
    const uint32_t io_timeout_ms = hatt_measurement_timeout_ms();
    struct timeval io_timeout = { .tv_sec = io_timeout_ms / 1000, .tv_usec = (io_timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) { ESP_LOGE(TAG, "Verifier: Unable to connect."); close(sock); sock = -1; goto CLEAN_UP; }
    
    ESP_LOGI(TAG, "Verifier: Successfully connected to Prover.");
    
    verifier_create_message1(verifier_state, msg1);

    if (write(sock, msg1, sizeof(Message1_t)) < 0) { ESP_LOGE(TAG, "Verifier: write Message1 failed"); goto CLEAN_UP; }
    ESP_LOGD(TAG, "Verifier: Sent Message 1");
    
    if (!hatt_read_full(sock, msg2, sizeof(Message2_t))) { ESP_LOGE(TAG, "Verifier: read Message2 failed"); goto CLEAN_UP; }
    
    if (!verifier_handle_message2(verifier_state, msg2, msg3)) { ESP_LOGE(TAG, "Verifier: Failed to process Message 2"); goto CLEAN_UP; }
    
    if (write(sock, msg3, sizeof(Message3_t)) < 0) { ESP_LOGE(TAG, "Verifier: write Message3 failed"); goto CLEAN_UP; }
    ESP_LOGD(TAG, "Verifier: Sent Message 3");

    // The expected proof is computed on the reference image while the Prover measures its memory.
    verifier_state->expected_sigma_ready = hatt_compute_sigma(verifier_state->expected_sigma, verifier_state->puf_response_r,
                                                              verifier_state->s_beta, verifier_state->s_omega, &verifier_state->prng_state);

    // The Prover may be serving other Verifiers, so the proof is awaited for a time that depends on the size of the network.
    const uint32_t proof_timeout_ms = hatt_measurement_timeout_ms();
    struct timeval proof_timeout = { .tv_sec = proof_timeout_ms / 1000, .tv_usec = (proof_timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &proof_timeout, sizeof(proof_timeout));
    if (!hatt_read_full(sock, msg4, sizeof(Message4_t))) { ESP_LOGE(TAG, "Verifier: read Message4 failed"); goto CLEAN_UP; }

    result = verifier_handle_message4(verifier_state, msg4);

CLEAN_UP:
    ESP_LOGI(TAG, "Verifier: Connection closed. Attestation result: %s",
             result == HATT_PASSED ? "PASSED" : (result == HATT_FAILED ? "FAILED" : "NO ANSWER"));
    ESP_LOGI(TAG, "HATT_STAT verifier prover=%s result=%s total_ms=%lld", prover_ip,
             result == HATT_PASSED ? "PASSED" : (result == HATT_FAILED ? "FAILED" : "NO_ANSWER"),
             (long long)((esp_timer_get_time() - attest_start_us) / 1000));
    if (sock >= 0) {
        close(sock);
    }

    if (msg1) free(msg1);
    if (msg2) free(msg2);
    if (msg3) free(msg3);
    if (msg4) free(msg4);
    if (verifier_state) free(verifier_state);
    return result;
}