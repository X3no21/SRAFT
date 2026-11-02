/* =============================
 * File: auth_puf.c
 * Description: Implements the "push" model for PUF-based authentication.
 * ============================= */

#include "auth_puf.h"
#include "utility.h"
#include "auth_db.h"
#include "connection_pool.h"
#include "nonce_manager.h"
#include "attacker.h"
#include "raft_state.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "psa/crypto.h"
#include "esp_random.h"


static const char *TAG = "AUTH_PUF";

#define AUTH_NONCE_SIZE 16
#define AUTH_TAG_SIZE 32
#define AUTH_GCM_NONCE_SIZE 12
#define AUTH_GCM_TAG_SIZE 16
#define AUTH_AAD_SIZE 160

#define MAX_PENDING_AUTH 16
#define PENDING_AUTH_TTL_MS 15000

/**
 * @brief (Verifier) An authentication run that is waiting for the Prover's answer.
 */
typedef struct {
    bool in_use;
    char operation_id[64];
    char challenge[64];
    char target_ip[INET_ADDRSTRLEN];
    uint8_t verifier_nonce[AUTH_NONCE_SIZE];
    uint8_t response_key[AUTH_KEY_SIZE];
    TickType_t started;
} pending_auth_t;

static pending_auth_t pending_auth[MAX_PENDING_AUTH];
static SemaphoreHandle_t pending_auth_mutex = NULL;

#define MAX_CHANNELS 16
#define CHANNEL_TTL_MS 30000
#define MAX_ENROLL_KEYS 32
#define ENROLL_KEY_TTL_MS 60000

/**
 * @brief (Prover) Session key of an authentication run started by a Verifier to open a channel.
 */
typedef struct {
    bool in_use;
    char peer_ip[INET_ADDRSTRLEN];
    char operation_id[64];
    uint8_t key[AUTH_KEY_SIZE];
    TickType_t created;
} channel_t;

/**
 * @brief Key that protects the enrollment of CRPs between this device and a peer.
 */
typedef struct {
    bool in_use;
    uint32_t transaction_id;
    char peer_ip[INET_ADDRSTRLEN];
    uint8_t key[AUTH_KEY_SIZE];
    TickType_t created;
} enroll_key_t;

static channel_t channels[MAX_CHANNELS];
static enroll_key_t enroll_keys[MAX_ENROLL_KEYS];
static SemaphoreHandle_t key_tables_mutex = NULL;
static uint8_t local_check_key[AUTH_KEY_SIZE];

SemaphoreHandle_t auth_result_sem = NULL;
bool auth_result_success = false;

static portMUX_TYPE auth_init_spinlock = portMUX_INITIALIZER_UNLOCKED;

static QueueHandle_t auth_message_queue = NULL;

static SemaphoreHandle_t local_check_mutex = NULL;
static SemaphoreHandle_t local_check_done_sem = NULL;
static portMUX_TYPE local_check_spinlock = portMUX_INITIALIZER_UNLOCKED;
static char local_check_op_id[64] = {0};
static bool local_check_result = false;

static void auth_worker_task(void *pvParameters);

#ifdef SRAFT_ATTACK_HOOKS
// When set, the next time this node answers as Prover it computes the proof from this response
// instead of the one of its PUF, emulating a captured credential used for a challenge whose
// genuine response the adversary does not hold.
static char forced_prover_response[64] = {0};
void attacker_force_prover_response(const char *response_or_null) {
    if (response_or_null && response_or_null[0]) {
        strncpy(forced_prover_response, response_or_null, sizeof(forced_prover_response) - 1);
        forced_prover_response[sizeof(forced_prover_response) - 1] = '\0';
    } else {
        forced_prover_response[0] = '\0';
    }
}
#endif

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
void auth_puf_init(void) {
    ESP_LOGI(TAG, "Initializing Node AUTH Module...");

    taskENTER_CRITICAL(&auth_init_spinlock);
    if (auth_result_sem == NULL) {
        auth_result_sem = xSemaphoreCreateBinary();
    }

    if (local_check_mutex == NULL) {
        local_check_mutex = xSemaphoreCreateMutex();
    }

    if (local_check_done_sem == NULL) {
        local_check_done_sem = xSemaphoreCreateBinary();
    }

    if (pending_auth_mutex == NULL) {
        pending_auth_mutex = xSemaphoreCreateMutex();
    }

    if (key_tables_mutex == NULL) {
        key_tables_mutex = xSemaphoreCreateMutex();
    }
    
    if (auth_message_queue == NULL) {
        auth_message_queue = xQueueCreate(10, sizeof(auth_message_t*));
        if (auth_message_queue) {
            xTaskCreate(auth_worker_task, "auth_worker", 6144, NULL, 6, NULL);
        } else {
            ESP_LOGE(TAG, "FATAL: Failed to create auth message queue!");
        }
    }
    
    taskEXIT_CRITICAL(&auth_init_spinlock);

    if (auth_result_sem == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create AUTH_RESULT semaphore!");
        return;
    }

    ESP_LOGI(TAG, "Auth module initialized.");
}

/**
 * @brief Computes HMAC-SHA256 over a list of data chunks.
 * @return true on success.
 */
static bool auth_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t **chunks, const size_t *chunk_sizes, int num_chunks, uint8_t *output) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t key_id;
    if (psa_import_key(&attr, key, key_len, &key_id) != PSA_SUCCESS) return false;

    size_t out_len = 0;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_status_t status = psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    for (int i = 0; i < num_chunks && status == PSA_SUCCESS; i++) {
        status = psa_mac_update(&op, chunks[i], chunk_sizes[i]);
    }
    if (status == PSA_SUCCESS) {
        status = psa_mac_sign_finish(&op, output, AUTH_KEY_SIZE, &out_len);
    } else {
        psa_mac_abort(&op);
    }
    psa_destroy_key(key_id);
    return status == PSA_SUCCESS;
}

/**
 * @brief Encrypts (or decrypts and verifies) a buffer with AES-256-GCM.
 * @param seal true to encrypt, false to decrypt.
 * @param output On encryption receives input_len + AUTH_GCM_TAG_SIZE bytes; on decryption input_len - AUTH_GCM_TAG_SIZE.
 * @return true on success. On decryption, false also means that the tag did not verify.
 */
static bool auth_aead(bool seal, const uint8_t *key, const uint8_t *nonce, const char *aad, const uint8_t *input, size_t input_len, uint8_t *output, size_t output_size) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, seal ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, AUTH_KEY_SIZE * 8);
    psa_key_id_t key_id;
    if (psa_import_key(&attr, key, AUTH_KEY_SIZE, &key_id) != PSA_SUCCESS) return false;

    size_t out_len = 0;
    psa_status_t status = seal
        ? psa_aead_encrypt(key_id, PSA_ALG_GCM, nonce, AUTH_GCM_NONCE_SIZE, (const uint8_t *)aad, strlen(aad), input, input_len, output, output_size, &out_len)
        : psa_aead_decrypt(key_id, PSA_ALG_GCM, nonce, AUTH_GCM_NONCE_SIZE, (const uint8_t *)aad, strlen(aad), input, input_len, output, output_size, &out_len);
    psa_destroy_key(key_id);
    return status == PSA_SUCCESS;
}

/**
 * @brief Derives the key of an authentication run from a PUF response.
 * @details The response is the only secret input. It is condensed into a key that both parties
 * can compute, the Verifier from the stored response and the Prover from its PUF.
 */
static bool auth_derive_response_key(const char *response, uint8_t *response_key) {
    static const char *label = "SRAFT-AUTH-PSK";
    const uint8_t *chunks[] = {(const uint8_t *)response};
    const size_t sizes[] = {strlen(response)};
    return auth_hmac_sha256((const uint8_t *)label, strlen(label), chunks, sizes, 1, response_key);
}

/**
 * @brief Computes one of the values of an authentication run with HMAC-SHA256 under the response key.
 * @details The value covers the role that produces it, the identifier of the run, the challenge,
 * the two identities, and the nonces, so that it cannot be reused in another run, for another
 * challenge, between another pair of devices, or in the opposite direction.
 * @param role "V" for the Verifier's proof, "P" for the Prover's proof, "SK" for the session key.
 * @param prover_nonce The Prover's nonce, or NULL for the Verifier's proof, which precedes it.
 */
static bool auth_compute_tag(const uint8_t *response_key, const char *role, const char *operation_id, const char *challenge,
                             const char *verifier_ip, const char *prover_ip, const uint8_t *verifier_nonce,
                             const uint8_t *prover_nonce, uint8_t *tag) {
    static const uint8_t separator = 0;
    const uint8_t *chunks[] = {(const uint8_t *)role, &separator, (const uint8_t *)operation_id, &separator,
                               (const uint8_t *)challenge, &separator, (const uint8_t *)verifier_ip, &separator,
                               (const uint8_t *)prover_ip, &separator, verifier_nonce, prover_nonce};
    const size_t sizes[] = {strlen(role), 1, strlen(operation_id), 1, strlen(challenge), 1, strlen(verifier_ip), 1,
                            strlen(prover_ip), 1, AUTH_NONCE_SIZE, AUTH_NONCE_SIZE};
    return auth_hmac_sha256(response_key, AUTH_KEY_SIZE, chunks, sizes, prover_nonce ? 12 : 11, tag);
}

/**
 * @brief Compares two tags in constant time.
 */
static bool auth_tags_equal(const uint8_t *a, const uint8_t *b) {
    uint8_t difference = 0;
    for (int i = 0; i < AUTH_TAG_SIZE; i++) {
        difference |= a[i] ^ b[i];
    }
    return difference == 0;
}

/**
 * @brief Removes a trailing line terminator from the last field of a message.
 */
static void strip_line_end(char *field) {
    size_t len = strlen(field);
    while (len > 0 && (field[len - 1] == '\n' || field[len - 1] == '\r')) {
        field[--len] = '\0';
    }
}

/**
 * @brief (Prover) Remembers the session key of a run that a Verifier started to open a channel.
 */
static void channel_store(const char *peer_ip, const char *operation_id, const uint8_t *key) {
    xSemaphoreTake(key_tables_mutex, portMAX_DELAY);
    TickType_t now = xTaskGetTickCount();
    int slot = 0;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (!channels[i].in_use || (now - channels[i].created) * portTICK_PERIOD_MS > CHANNEL_TTL_MS) {
            slot = i;
            break;
        }
        if (channels[i].created < channels[slot].created) slot = i;
    }
    memset(&channels[slot], 0, sizeof(channel_t));
    channels[slot].in_use = true;
    strncpy(channels[slot].peer_ip, peer_ip, INET_ADDRSTRLEN - 1);
    strncpy(channels[slot].operation_id, operation_id, sizeof(channels[slot].operation_id) - 1);
    memcpy(channels[slot].key, key, AUTH_KEY_SIZE);
    channels[slot].created = now;
    xSemaphoreGive(key_tables_mutex);
}

/**
 * @brief (Prover) Takes the session key of a channel. A key can be taken once.
 */
static bool channel_take(const char *peer_ip, const char *operation_id, uint8_t *key) {
    bool found = false;
    xSemaphoreTake(key_tables_mutex, portMAX_DELAY);
    TickType_t now = xTaskGetTickCount();
    for (int i = 0; i < MAX_CHANNELS && !found; i++) {
        if (channels[i].in_use && (now - channels[i].created) * portTICK_PERIOD_MS <= CHANNEL_TTL_MS &&
            strcmp(channels[i].peer_ip, peer_ip) == 0 && strcmp(channels[i].operation_id, operation_id) == 0) {
            memcpy(key, channels[i].key, AUTH_KEY_SIZE);
            memset(&channels[i], 0, sizeof(channel_t));
            found = true;
        }
    }
    xSemaphoreGive(key_tables_mutex);
    return found;
}

static void enroll_key_put(uint32_t transaction_id, const char *peer_ip, const uint8_t *key) {
    xSemaphoreTake(key_tables_mutex, portMAX_DELAY);
    TickType_t now = xTaskGetTickCount();
    int slot = 0;
    for (int i = 0; i < MAX_ENROLL_KEYS; i++) {
        if (!enroll_keys[i].in_use || (now - enroll_keys[i].created) * portTICK_PERIOD_MS > ENROLL_KEY_TTL_MS) {
            slot = i;
            break;
        }
        if (enroll_keys[i].created < enroll_keys[slot].created) slot = i;
    }
    memset(&enroll_keys[slot], 0, sizeof(enroll_key_t));
    enroll_keys[slot].in_use = true;
    enroll_keys[slot].transaction_id = transaction_id;
    strncpy(enroll_keys[slot].peer_ip, peer_ip, INET_ADDRSTRLEN - 1);
    memcpy(enroll_keys[slot].key, key, AUTH_KEY_SIZE);
    enroll_keys[slot].created = now;
    xSemaphoreGive(key_tables_mutex);
}

bool auth_puf_enroll_key_wait(uint32_t transaction_id, const char *peer_ip, uint8_t *key, uint32_t timeout_ms) {
    if (!key_tables_mutex) return false;

    TickType_t start = xTaskGetTickCount();
    while (1) {
        bool found = false;
        xSemaphoreTake(key_tables_mutex, portMAX_DELAY);
        TickType_t now = xTaskGetTickCount();
        for (int i = 0; i < MAX_ENROLL_KEYS && !found; i++) {
            if (enroll_keys[i].in_use && (now - enroll_keys[i].created) * portTICK_PERIOD_MS <= ENROLL_KEY_TTL_MS &&
                enroll_keys[i].transaction_id == transaction_id && strcmp(enroll_keys[i].peer_ip, peer_ip) == 0) {
                memcpy(key, enroll_keys[i].key, AUTH_KEY_SIZE);
                found = true;
            }
        }
        xSemaphoreGive(key_tables_mutex);

        if (found) return true;
        if ((xTaskGetTickCount() - start) * portTICK_PERIOD_MS >= timeout_ms) return false;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

void auth_puf_enroll_key_drop(uint32_t transaction_id, const char *peer_ip) {
    if (!key_tables_mutex) return;

    xSemaphoreTake(key_tables_mutex, portMAX_DELAY);
    for (int i = 0; i < MAX_ENROLL_KEYS; i++) {
        if (enroll_keys[i].in_use && enroll_keys[i].transaction_id == transaction_id && strcmp(enroll_keys[i].peer_ip, peer_ip) == 0) {
            memset(&enroll_keys[i], 0, sizeof(enroll_key_t));
        }
    }
    xSemaphoreGive(key_tables_mutex);
}

bool auth_puf_seal(const uint8_t *key, const char *aad, const uint8_t *plaintext, size_t len, char *out_hex, size_t out_hex_size) {
    size_t raw_size = AUTH_GCM_NONCE_SIZE + len + AUTH_GCM_TAG_SIZE;
    if (out_hex_size < raw_size * 2 + 1) return false;

    uint8_t *raw = malloc(raw_size);
    if (!raw) return false;

    generate_nonce(raw, AUTH_GCM_NONCE_SIZE);
    bool ok = auth_aead(true, key, raw, aad, plaintext, len, raw + AUTH_GCM_NONCE_SIZE, len + AUTH_GCM_TAG_SIZE);
    if (ok) {
        bytes_to_hex(raw, out_hex, raw_size);
    }
    free(raw);
    return ok;
}

int auth_puf_open(const uint8_t *key, const char *aad, const char *in_hex, uint8_t *out, size_t out_size) {
    size_t hex_len = strlen(in_hex);
    if (hex_len % 2 != 0 || hex_len / 2 <= AUTH_GCM_NONCE_SIZE + AUTH_GCM_TAG_SIZE) return -1;

    size_t raw_size = hex_len / 2;
    size_t plain_len = raw_size - AUTH_GCM_NONCE_SIZE - AUTH_GCM_TAG_SIZE;
    if (out_size < plain_len) return -1;

    uint8_t *raw = malloc(raw_size);
    if (!raw) return -1;

    hex_to_bytes(in_hex, raw, raw_size);
    bool ok = auth_aead(false, key, raw, aad, raw + AUTH_GCM_NONCE_SIZE, raw_size - AUTH_GCM_NONCE_SIZE, out, out_size);
    free(raw);
    return ok ? (int)plain_len : -1;
}

/**
 * @brief (Verifier) Sends the first message of an authentication run to a Prover.
 * @details The Verifier picks one of its CRPs for the Prover and sends the challenge, a fresh
 * nonce, and its proof: an HMAC over the run under the key derived from the stored response. Only
 * a party that knows the response can produce this message, and the response is never transmitted.
 * @param operation_id The identifier of the run.
 * @param targetIp The IP address of the Prover.
 * @return true if the message was sent and the run registered as pending.
 */
static bool verifier_send_challenge(const char *operation_id, const char *targetIp, const CRPNode *use_crp) {
    // With no CRP given, one of the CRPs held for the Prover is drawn at random.
    CRPNode *crp = NULL;
    if (use_crp) {
        crp = malloc(sizeof(CRPNode));
        if (crp) memcpy(crp, use_crp, sizeof(CRPNode));
    } else {
        crp = db_get_random_crp_for_node(targetIp);
    }
    if (!crp) return false;

    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));

    uint8_t response_key[AUTH_KEY_SIZE], verifier_nonce[AUTH_NONCE_SIZE], verifier_tag[AUTH_TAG_SIZE];
    generate_nonce(verifier_nonce, sizeof(verifier_nonce));

    bool ok = auth_derive_response_key(crp->response, response_key) &&
              auth_compute_tag(response_key, "V", operation_id, crp->challenge, my_ip, targetIp, verifier_nonce, NULL, verifier_tag);
    if (!ok) {
        ESP_LOGE(TAG, "Could not prepare the challenge for %s.", targetIp);
        free(crp);
        return false;
    }

    bool registered = false;
    xSemaphoreTake(pending_auth_mutex, portMAX_DELAY);
    TickType_t now = xTaskGetTickCount();
    for (int i = 0; i < MAX_PENDING_AUTH; i++) {
        if (pending_auth[i].in_use && (now - pending_auth[i].started) * portTICK_PERIOD_MS > PENDING_AUTH_TTL_MS) {
            memset(&pending_auth[i], 0, sizeof(pending_auth_t));
        }
    }
    for (int i = 0; i < MAX_PENDING_AUTH && !registered; i++) {
        if (!pending_auth[i].in_use) {
            memset(&pending_auth[i], 0, sizeof(pending_auth_t));
            pending_auth[i].in_use = true;
            strncpy(pending_auth[i].operation_id, operation_id, sizeof(pending_auth[i].operation_id) - 1);
            strncpy(pending_auth[i].challenge, crp->challenge, sizeof(pending_auth[i].challenge) - 1);
            strncpy(pending_auth[i].target_ip, targetIp, INET_ADDRSTRLEN - 1);
            memcpy(pending_auth[i].verifier_nonce, verifier_nonce, AUTH_NONCE_SIZE);
            memcpy(pending_auth[i].response_key, response_key, AUTH_KEY_SIZE);
            pending_auth[i].started = now;
            registered = true;
        }
    }
    xSemaphoreGive(pending_auth_mutex);
    memset(response_key, 0, sizeof(response_key));

    if (!registered) {
        ESP_LOGE(TAG, "Too many authentication runs in progress. Cannot challenge %s.", targetIp);
        free(crp);
        return false;
    }

    char nonce_hex[AUTH_NONCE_SIZE * 2 + 1], tag_hex[AUTH_TAG_SIZE * 2 + 1];
    bytes_to_hex(verifier_nonce, nonce_hex, sizeof(verifier_nonce));
    bytes_to_hex(verifier_tag, tag_hex, sizeof(verifier_tag));

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%s|%s|%s|%s|%s\n", MSG_AUTH_REQ, operation_id, crp->challenge, my_ip, nonce_hex, tag_hex);
    free(crp);

    ESP_LOGI(TAG, "Queueing %s for target %s", MSG_AUTH_REQ, targetIp);
    return connection_pool_send(targetIp, msg);
}

#ifdef SRAFT_ATTACK_HOOKS
bool attacker_build_authreq(const char *prover_ip, char *out, size_t out_size) {
    CRPNode *crp = db_get_random_crp_for_node(prover_ip);
    if (!crp) return false;

    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));

    uint8_t response_key[AUTH_KEY_SIZE], verifier_nonce[AUTH_NONCE_SIZE], verifier_tag[AUTH_TAG_SIZE];
    generate_nonce(verifier_nonce, sizeof(verifier_nonce));
    char op_id[48];
    snprintf(op_id, sizeof(op_id), "attack_probe_%lu", (unsigned long)esp_random());

    bool ok = auth_derive_response_key(crp->response, response_key) &&
              auth_compute_tag(response_key, "V", op_id, crp->challenge, my_ip, prover_ip, verifier_nonce, NULL, verifier_tag);
    memset(response_key, 0, sizeof(response_key));
    if (ok) {
        char nonce_hex[AUTH_NONCE_SIZE * 2 + 1], tag_hex[AUTH_TAG_SIZE * 2 + 1];
        bytes_to_hex(verifier_nonce, nonce_hex, sizeof(verifier_nonce));
        bytes_to_hex(verifier_tag, tag_hex, sizeof(verifier_tag));
        snprintf(out, out_size, "%s|%s|%s|%s|%s|%s\n", MSG_AUTH_REQ, op_id, crp->challenge, my_ip, nonce_hex, tag_hex);
    }
    free(crp);
    return ok;
}
#endif

/**
 * @brief Initiates an authentication challenge from an authenticator to a target node.
 * @param targetIp The IP address of the node to be authenticated.
 * @return void
 */
static void node_authenticator_start(const char* operation_id, const char* targetIp, const char* targetMac) {
    if (!verifier_send_challenge(operation_id, targetIp, NULL)) {
        ESP_LOGE(TAG, "Cannot start authentication of node %s (no CRP available or send failed).", targetIp);
        char result_msg[PUF_MAX_MSG_SIZE];
        char nonce_hex[NONCE_HEX_SIZE];
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
        
        snprintf(result_msg, sizeof(result_msg), "%s|%d|%s\n", MSG_AUTH_FINAL_RESULT, 0, nonce_hex);
        connection_pool_send(targetIp, result_msg);

        char event_msg[PUF_MAX_MSG_SIZE];
        snprintf(event_msg, sizeof(event_msg), "AUTH_RESULT_EVENT|0|%s|%s|SRAFT", operation_id, targetMac);
        send_monitoring_tcp_event(event_msg);
    }
}

/**
 * @brief (Prover) Answers the first message of an authentication run.
 * @details The Prover evaluates its PUF on the challenge and derives the key of the run. It answers
 * only if the Verifier's proof is valid, i.e., only to a party that already knows the response: the
 * device cannot be used to learn responses to chosen challenges. The answer carries the Prover's
 * nonce and its proof, an HMAC over the run that includes both nonces.
 * @param challenge The challenge string received from the authenticator.
 * @param myIp The IP address of this node (the prover).
 * @param authenticatorIp The IP address of the authenticator to send the response to.
 * @param nonce_hex The nonce of the authenticator.
 * @param tag_hex The proof of the authenticator.
 * @return void
 */
static void node_to_authenticate_respond(const char *operation_id, const char *challenge, const char* myIp, const char* authenticatorIp, const char *nonce_hex, const char *tag_hex) {
    if (strlen(nonce_hex) != AUTH_NONCE_SIZE * 2 || strlen(tag_hex) != AUTH_TAG_SIZE * 2) {
        ESP_LOGW(TAG, "Malformed %s from %s", MSG_AUTH_REQ, authenticatorIp);
        return;
    }

    char response[64] = {0};
    simulate_puf_response((const uint8_t*)challenge, strlen(challenge), response);
#ifdef SRAFT_ATTACK_HOOKS
    // A captured credential: the proof is computed from a stored response that is not the one of
    // this challenge, so the Verifier, which recomputes with the genuine response, rejects it.
    if (forced_prover_response[0]) {
        strncpy(response, forced_prover_response, sizeof(response) - 1);
        response[sizeof(response) - 1] = '\0';
        forced_prover_response[0] = '\0';
    }
#endif

    uint8_t response_key[AUTH_KEY_SIZE], verifier_nonce[AUTH_NONCE_SIZE];
    uint8_t received_tag[AUTH_TAG_SIZE], expected_tag[AUTH_TAG_SIZE];
    hex_to_bytes(nonce_hex, verifier_nonce, sizeof(verifier_nonce));
    hex_to_bytes(tag_hex, received_tag, sizeof(received_tag));

    bool verifier_knows_response = auth_derive_response_key(response, response_key) &&
                                   auth_compute_tag(response_key, "V", operation_id, challenge, authenticatorIp, myIp, verifier_nonce, NULL, expected_tag) &&
                                   auth_tags_equal(received_tag, expected_tag);
    memset(response, 0, sizeof(response));
    if (!verifier_knows_response) {
        ESP_LOGW(TAG, "%s from %s does not prove knowledge of the response. Ignored.", MSG_AUTH_REQ, authenticatorIp);
        memset(response_key, 0, sizeof(response_key));
        return;
    }

    uint8_t prover_nonce[AUTH_NONCE_SIZE], prover_tag[AUTH_TAG_SIZE], session_key[AUTH_KEY_SIZE];
    generate_nonce(prover_nonce, sizeof(prover_nonce));
    bool ok = auth_compute_tag(response_key, "P", operation_id, challenge, authenticatorIp, myIp, verifier_nonce, prover_nonce, prover_tag) &&
              auth_compute_tag(response_key, "SK", operation_id, challenge, authenticatorIp, myIp, verifier_nonce, prover_nonce, session_key);
    memset(response_key, 0, sizeof(response_key));
    if (!ok) {
        ESP_LOGE(TAG, "Could not prepare the answer for %s.", authenticatorIp);
        return;
    }

    if (strncmp(operation_id, AUTH_CHANNEL_OP_PREFIX, strlen(AUTH_CHANNEL_OP_PREFIX)) == 0) {
        channel_store(authenticatorIp, operation_id, session_key);
    }
    memset(session_key, 0, sizeof(session_key));

    char my_mac[MAC_ADDR_STR_LEN];
    get_my_mac(my_mac, sizeof(my_mac));

    char prover_nonce_hex[AUTH_NONCE_SIZE * 2 + 1], prover_tag_hex[AUTH_TAG_SIZE * 2 + 1];
    bytes_to_hex(prover_nonce, prover_nonce_hex, sizeof(prover_nonce));
    bytes_to_hex(prover_tag, prover_tag_hex, sizeof(prover_tag));

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%s|%s|%s|%s|%s|%s\n", MSG_AUTH_RESPONSE, operation_id, challenge, myIp, my_mac, prover_nonce_hex, prover_tag_hex);

    ESP_LOGI(TAG, "Queueing PUF %s to authenticator %s", MSG_AUTH_RESPONSE, authenticatorIp);
    connection_pool_send(authenticatorIp, msg);
}

/**
 * @brief (Verifier) Verifies the Prover's answer to a pending authentication run.
 * @details The answer is accepted only if it belongs to a run this Verifier started and the
 * Prover's proof matches the HMAC that the Verifier computes with its own nonce. Since that nonce
 * is fresh in every run, an answer cannot be replayed.
 * @param challenge The challenge string the answer refers to.
 * @param responseFromIp The IP address of the node that sent the response.
 * @param nonce_hex The nonce of the Prover.
 * @param tag_hex The proof of the Prover.
 * @return void
 */
static void node_authenticator_check_response(const char *operation_id, const char *challenge, const char* responseFromIp, const char* responseFromMac, const char* nonce_hex, const char *tag_hex) {
    pending_auth_t run;
    bool found = false;
    xSemaphoreTake(pending_auth_mutex, portMAX_DELAY);
    for (int i = 0; i < MAX_PENDING_AUTH; i++) {
        if (pending_auth[i].in_use && strcmp(pending_auth[i].operation_id, operation_id) == 0) {
            run = pending_auth[i];
            memset(&pending_auth[i], 0, sizeof(pending_auth_t));
            found = true;
            break;
        }
    }
    xSemaphoreGive(pending_auth_mutex);

    if (!found) {
        ESP_LOGW(TAG, "%s from %s does not match any pending authentication. Ignored.", MSG_AUTH_RESPONSE, responseFromIp);
        return;
    }

    int result = 0;
    uint8_t session_key[AUTH_KEY_SIZE] = {0};
    if (strcmp(run.challenge, challenge) == 0 && strcmp(run.target_ip, responseFromIp) == 0 &&
        strlen(nonce_hex) == AUTH_NONCE_SIZE * 2 && strlen(tag_hex) == AUTH_TAG_SIZE * 2) {
        char my_ip[INET_ADDRSTRLEN];
        get_my_ip(my_ip, sizeof(my_ip));

        uint8_t prover_nonce[AUTH_NONCE_SIZE], received_tag[AUTH_TAG_SIZE], expected_tag[AUTH_TAG_SIZE];
        hex_to_bytes(nonce_hex, prover_nonce, sizeof(prover_nonce));
        hex_to_bytes(tag_hex, received_tag, sizeof(received_tag));

        if (auth_compute_tag(run.response_key, "P", operation_id, challenge, my_ip, responseFromIp, run.verifier_nonce, prover_nonce, expected_tag) &&
            auth_tags_equal(received_tag, expected_tag) &&
            auth_compute_tag(run.response_key, "SK", operation_id, challenge, my_ip, responseFromIp, run.verifier_nonce, prover_nonce, session_key)) {
            result = 1;
        }
    }
    memset(&run, 0, sizeof(run));

    ESP_LOGI(TAG, "[RESULT] Authentication of node %s %s", responseFromIp, result ? "SUCCEEDED" : "FAILED");

    if (strncmp(operation_id, AUTH_CHECK_OP_PREFIX, strlen(AUTH_CHECK_OP_PREFIX)) == 0 ||
        strncmp(operation_id, AUTH_CHANNEL_OP_PREFIX, strlen(AUTH_CHANNEL_OP_PREFIX)) == 0) {
        bool is_pending = false;
        taskENTER_CRITICAL(&local_check_spinlock);
        if (local_check_op_id[0] != '\0' && strcmp(local_check_op_id, operation_id) == 0) {
            local_check_result = (result == 1);
            memcpy(local_check_key, session_key, AUTH_KEY_SIZE);
            local_check_op_id[0] = '\0';
            is_pending = true;
        }
        taskEXIT_CRITICAL(&local_check_spinlock);
        memset(session_key, 0, sizeof(session_key));
        if (is_pending) {
            xSemaphoreGive(local_check_done_sem);
        }
        return;
    }
    memset(session_key, 0, sizeof(session_key));

    char result_msg[PUF_MAX_MSG_SIZE];
    char result_nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, result_nonce_hex, NONCE_SIZE);
    
    snprintf(result_msg, sizeof(result_msg), "%s|%d|%s\n", MSG_AUTH_FINAL_RESULT, result, result_nonce_hex);
    connection_pool_send(responseFromIp, result_msg);

    char event_msg[PUF_MAX_MSG_SIZE];
    snprintf(event_msg, sizeof(event_msg), "AUTH_RESULT_EVENT|%d|%s|%s|SRAFT", result, operation_id, responseFromMac);
    send_monitoring_tcp_event(event_msg);
}

bool auth_puf_is_verifier_of(const char *target_ip) {
    CRPNode *crp = db_get_random_crp_for_node(target_ip);
    if (!crp) return false;
    free(crp);
    return true;
}

/**
 * @brief (Verifier) Runs the authentication exchange with a Prover and waits for its outcome.
 * @param op_prefix Prefix of the run identifier: a check of the Prover or the opening of a channel.
 * @param operation_id_out If not NULL, receives the identifier of the run.
 * @param key_out If not NULL, receives the session key of a successful run.
 * @return true only if the Prover answered in time and the key confirmation matched.
 */
static bool run_local_exchange(const char *target_ip, const CRPNode *use_crp, const char *op_prefix, uint32_t timeout_ms, char *operation_id_out, size_t operation_id_size, uint8_t *key_out) {
    if (!local_check_mutex || !local_check_done_sem) {
        ESP_LOGE(TAG, "Auth module not initialized. Cannot challenge %s.", target_ip);
        return false;
    }

    if (!auth_puf_is_verifier_of(target_ip)) {
        ESP_LOGW(TAG, "No CRP stored for %s. This node is not one of its verifiers.", target_ip);
        return false;
    }

    bool result = false;
    xSemaphoreTake(local_check_mutex, portMAX_DELAY);
    xSemaphoreTake(local_check_done_sem, 0);

    char operation_id[64];
    snprintf(operation_id, sizeof(operation_id), "%s%lu", op_prefix, (uint32_t)esp_timer_get_time());

    taskENTER_CRITICAL(&local_check_spinlock);
    strncpy(local_check_op_id, operation_id, sizeof(local_check_op_id) - 1);
    local_check_op_id[sizeof(local_check_op_id) - 1] = '\0';
    local_check_result = false;
    taskEXIT_CRITICAL(&local_check_spinlock);

    if (verifier_send_challenge(operation_id, target_ip, use_crp) &&
        xSemaphoreTake(local_check_done_sem, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        taskENTER_CRITICAL(&local_check_spinlock);
        result = local_check_result;
        if (result && key_out) {
            memcpy(key_out, local_check_key, AUTH_KEY_SIZE);
        }
        memset(local_check_key, 0, AUTH_KEY_SIZE);
        taskEXIT_CRITICAL(&local_check_spinlock);
    } else {
        ESP_LOGW(TAG, "Prover %s did not answer the local challenge within %lu ms.", target_ip, timeout_ms);
    }

    if (operation_id_out) {
        strncpy(operation_id_out, operation_id, operation_id_size - 1);
        operation_id_out[operation_id_size - 1] = '\0';
    }

    taskENTER_CRITICAL(&local_check_spinlock);
    local_check_op_id[0] = '\0';
    taskEXIT_CRITICAL(&local_check_spinlock);

    xSemaphoreGive(local_check_mutex);
    return result;
}

bool auth_puf_challenge_prover(const char *target_ip, uint32_t timeout_ms) {
    return run_local_exchange(target_ip, NULL, AUTH_CHECK_OP_PREFIX, timeout_ms, NULL, 0, NULL);
}

bool auth_puf_challenge_prover_with_crp(const char *target_ip, const CRPNode *crp, uint32_t timeout_ms) {
    return run_local_exchange(target_ip, crp, AUTH_CHECK_OP_PREFIX, timeout_ms, NULL, 0, NULL);
}

/**
 * @brief (Intermediary) Opens a channel with a device and sends it the key of an enrollment.
 * @param peer_ip The device that receives the key. This node must hold CRPs of it.
 * @param other_ip The other party of the enrollment.
 */
static bool deliver_enroll_key(uint32_t transaction_id, const char *peer_ip, const char *other_ip, const uint8_t *enroll_key) {
    char channel_id[64];
    uint8_t channel_key[AUTH_KEY_SIZE];
    if (!run_local_exchange(peer_ip, NULL, AUTH_CHANNEL_OP_PREFIX, ENROLL_KEY_WAIT_MS / 2, channel_id, sizeof(channel_id), channel_key)) {
        ESP_LOGE(TAG, "[TID: %lu] Could not open a channel with %s.", transaction_id, peer_ip);
        return false;
    }

    char aad[AUTH_AAD_SIZE];
    char sealed_hex[(AUTH_GCM_NONCE_SIZE + AUTH_KEY_SIZE + AUTH_GCM_TAG_SIZE) * 2 + 1];
    snprintf(aad, sizeof(aad), "%lu|%s|%s", transaction_id, other_ip, channel_id);
    bool sealed = auth_puf_seal(channel_key, aad, enroll_key, AUTH_KEY_SIZE, sealed_hex, sizeof(sealed_hex));
    memset(channel_key, 0, sizeof(channel_key));
    if (!sealed) return false;

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%lu|%s|%s|%s\n", MSG_ENROLL_KEY, transaction_id, other_ip, channel_id, sealed_hex);
    return connection_pool_send(peer_ip, msg);
}

bool auth_puf_broker_enrollment(uint32_t transaction_id, const char *prover_ip, const char *verifier_ip) {
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));

    uint8_t enroll_key[AUTH_KEY_SIZE];
    generate_nonce(enroll_key, sizeof(enroll_key));

    bool ok = deliver_enroll_key(transaction_id, verifier_ip, prover_ip, enroll_key);
    if (ok) {
        if (strcmp(my_ip, prover_ip) == 0) {
            enroll_key_put(transaction_id, verifier_ip, enroll_key);
        } else {
            ok = deliver_enroll_key(transaction_id, prover_ip, verifier_ip, enroll_key);
        }
    }

    memset(enroll_key, 0, sizeof(enroll_key));
    return ok;
}

/**
 * @brief A node (Prover) initiates its own authentication process against a random verifier.
 * @details This function looks up a random verifier from the database and queues an
 * authentication request to it via the connection pool.
 * @return void
 */
void initiate_authentication_as_prover() {
    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));
    ESP_LOGI(TAG, "Node %s is initiating its own authentication.", my_ip);

    char operation_id[64];
    snprintf(operation_id, sizeof(operation_id), "auth_%s_%lu", my_mac, (uint32_t)esp_timer_get_time());

    char event_msg[128];
    snprintf(event_msg, sizeof(event_msg), "AUTH_START|%s|%s|SRAFT", operation_id, my_mac);
    send_monitoring_tcp_event(event_msg);

    char* verifier_ip = db_get_random_verifier_for_me(my_ip);
    if (!verifier_ip) {
        ESP_LOGE(TAG, "Could not find a valid verifier for myself. Authentication failed.");
        snprintf(event_msg, sizeof(event_msg), "AUTH_RESULT_EVENT|0|%s|%s|SRAFT", operation_id, my_mac);
        send_monitoring_tcp_event(event_msg);
        return;
    }

    ESP_LOGI(TAG, "Selected %s as the verifier. Queueing initiation request.", verifier_ip);

    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%s|%s|%s|%s\n", MSG_INITIATE_AUTH_REQ, operation_id, my_ip, my_mac, nonce_hex);
    connection_pool_send(verifier_ip, msg);
    
    free(verifier_ip);
}

/**
 * @brief A node (Prover) initiates its own authentication process against a *specific* verifier.
 * @details This function is called by an API handler when commanded by the monitoring server.
 * It sends an authentication request to the specified verifier.
 * @param verifier_ip The IP address of the verifier to use.
 * @return void
 */
void initiate_authentication_as_prover_specific(const char* verifier_ip) {
    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));
    ESP_LOGI(TAG, "Node %s is initiating server-commanded authentication against %s.", my_ip, verifier_ip);

    char operation_id[64];
    snprintf(operation_id, sizeof(operation_id), "auth_%s_%lu", my_mac, (uint32_t)esp_timer_get_time());

    char event_msg[128];
    snprintf(event_msg, sizeof(event_msg), "AUTH_START|%s|%s|SRAFT", operation_id, my_mac);
    send_monitoring_tcp_event(event_msg);

    if (verifier_ip == NULL || strlen(verifier_ip) == 0) {
        ESP_LOGE(TAG, "No valid verifier IP provided. Authentication failed.");
        snprintf(event_msg, sizeof(event_msg), "AUTH_RESULT_EVENT|0|%s|%s|SRAFT", operation_id, my_mac);
        send_monitoring_tcp_event(event_msg);
        return;
    }

    ESP_LOGI(TAG, "Selected %s as the verifier. Queueing initiation request.", verifier_ip);

    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%s|%s|%s|%s\n", MSG_INITIATE_AUTH_REQ, operation_id, my_ip, my_mac, nonce_hex);
    connection_pool_send(verifier_ip, msg);
}

/**
 * @brief Handles incoming authentication-related messages, to be called from the main server task.
 * @details This function acts as a dispatcher for the PUF authentication protocol, parsing
 * messages and calling the appropriate logic for Prover or Verifier roles.
 * @param message The raw, null-terminated message string received from a peer.
 * @param from_ip The IP address of the node that sent the message.
 * @param myIp The IP address of the current node, used when acting as an authenticator.
 * @return void
 */
static void auth_handle_message_internal(char *message, const char *from_ip) {
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));
    
    char* saveptr;
    char* command = strtok_r(message, "|", &saveptr);
    if (!command) return;

    if (strcmp(command, MSG_INITIATE_AUTH_REQ) == 0) {
        char* operation_id = strtok_r(NULL, "|", &saveptr);
        char* target_ip = strtok_r(NULL, "|", &saveptr);
        char* target_mac = strtok_r(NULL, "|", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);
        if (!target_ip || !target_mac || !nonce || !nonce_is_valid_and_store(nonce)) {
            ESP_LOGW(TAG, "Malformed or replayed %s from %s", MSG_INITIATE_AUTH_REQ, from_ip);
            return;
        }

        ESP_LOGI(TAG, "Received %s from %s. Starting authentication process for them.", MSG_INITIATE_AUTH_REQ, target_ip);
        node_authenticator_start(operation_id, target_ip, target_mac);
    } else if (strcmp(command, MSG_AUTH_REQ) == 0) {
        char* operation_id = strtok_r(NULL, "|", &saveptr);
        char* challenge = strtok_r(NULL, "|", &saveptr);
        char* authenticator_ip = strtok_r(NULL, "|", &saveptr);
        char* nonce_hex = strtok_r(NULL, "|", &saveptr);
        char* tag_hex = strtok_r(NULL, "", &saveptr);
        if (!operation_id || !challenge || !authenticator_ip || !nonce_hex || !tag_hex || !nonce_is_valid_and_store(nonce_hex)) {
            ESP_LOGW(TAG, "Malformed or replayed %s from %s", MSG_AUTH_REQ, from_ip);
            return;
        }
        strip_line_end(tag_hex);

        ESP_LOGI(TAG, "Received %s from authenticator %s", MSG_AUTH_REQ, authenticator_ip);
        node_to_authenticate_respond(operation_id, challenge, my_ip, authenticator_ip, nonce_hex, tag_hex);
    } else if (strcmp(command, MSG_AUTH_RESPONSE) == 0) {
        char* operation_id = strtok_r(NULL, "|", &saveptr);
        char* challenge = strtok_r(NULL, "|", &saveptr);
        char* prover_ip = strtok_r(NULL, "|", &saveptr);
        char* prover_mac = strtok_r(NULL, "|", &saveptr);
        char* nonce_hex = strtok_r(NULL, "|", &saveptr);
        char* tag_hex = strtok_r(NULL, "", &saveptr);
        if (!operation_id || !challenge || !prover_ip || !prover_mac || !nonce_hex || !tag_hex) {
            ESP_LOGW(TAG, "Malformed %s from %s", MSG_AUTH_RESPONSE, from_ip);
            return;
        }
        strip_line_end(tag_hex);

        ESP_LOGI(TAG, "Received PUF %s from prover %s", MSG_AUTH_RESPONSE, prover_ip);
#ifdef SRAFT_ATTACK_HOOKS
        attacker_on_auth_response_seen(operation_id);
#endif
        node_authenticator_check_response(operation_id, challenge, prover_ip, prover_mac, nonce_hex, tag_hex);
    } else if (strcmp(command, MSG_ENROLL_KEY) == 0) {
        char* transaction_id_str = strtok_r(NULL, "|", &saveptr);
        char* other_ip = strtok_r(NULL, "|", &saveptr);
        char* channel_id = strtok_r(NULL, "|", &saveptr);
        char* sealed_hex = strtok_r(NULL, "", &saveptr);
        if (!transaction_id_str || !other_ip || !channel_id || !sealed_hex) {
            ESP_LOGW(TAG, "Malformed %s from %s", MSG_ENROLL_KEY, from_ip);
            return;
        }
        strip_line_end(sealed_hex);

        uint8_t channel_key[AUTH_KEY_SIZE], enroll_key[AUTH_KEY_SIZE];
        if (!channel_take(from_ip, channel_id, channel_key)) {
            ESP_LOGW(TAG, "%s from %s refers to no open channel. Ignored.", MSG_ENROLL_KEY, from_ip);
            return;
        }

        char aad[AUTH_AAD_SIZE];
        snprintf(aad, sizeof(aad), "%s|%s|%s", transaction_id_str, other_ip, channel_id);
        if (auth_puf_open(channel_key, aad, sealed_hex, enroll_key, sizeof(enroll_key)) == AUTH_KEY_SIZE) {
            enroll_key_put(strtoul(transaction_id_str, NULL, 10), other_ip, enroll_key);
            ESP_LOGI(TAG, "[TID: %s] Received the enrollment key for peer %s from %s.", transaction_id_str, other_ip, from_ip);
        } else {
            ESP_LOGW(TAG, "%s from %s does not verify. Ignored.", MSG_ENROLL_KEY, from_ip);
        }
        memset(channel_key, 0, sizeof(channel_key));
        memset(enroll_key, 0, sizeof(enroll_key));
    } else if (strcmp(command, MSG_AUTH_FINAL_RESULT) == 0) {
        char* result_str = strtok_r(NULL, "|", &saveptr);
        char* nonce = strtok_r(NULL, "", &saveptr);

        if (!result_str || !nonce || !nonce_is_valid_and_store(nonce)) {
            ESP_LOGW(TAG, "Malformed or replayed %s from %s", MSG_AUTH_FINAL_RESULT, from_ip);
            return;
        }

        ESP_LOGI(TAG, "Received final authentication result from verifier %s.", from_ip);
        auth_result_success = (atoi(result_str) == 1);
        xSemaphoreGive(auth_result_sem);
    } else {
        ESP_LOGW(TAG, "Unrecognized auth message format from %s: %s", from_ip, command);
    }
}

static void auth_worker_task(void *pvParameters) {
    auth_message_t *msg;
    ESP_LOGI(TAG, "Auth Worker Task started.");
    while (1) {
        if (xQueueReceive(auth_message_queue, &msg, portMAX_DELAY) == pdTRUE) {
            ESP_LOGD(TAG, "Auth Worker processing: %s", msg->message);
            auth_handle_message_internal(msg->message, msg->from_ip);
            
            free(msg->message);
            free(msg);
        }
    }
}

/**
 * @brief Queues an incoming authentication message for processing by the worker task.
 * @details This function is thread-safe and non-blocking. It copies the message pointer
 * and sender IP into the queue. The worker task is responsible for freeing the message memory.
 * @param message The dynamically allocated message string. Ownership is transferred to the queue.
 * @param from_ip The IP address of the sender.
 * @return void
 */
void auth_puf_queue_message(char *message, const char *from_ip) {
    if (!auth_message_queue) {
        ESP_LOGE(TAG, "Auth queue not initialized! Message dropped.");
        free(message);
        return;
    }

    auth_message_t *msg = malloc(sizeof(auth_message_t));
    if (!msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for auth message wrapper! Message dropped.");
        free(message);
        return;
    }

    msg->message = message;
    strncpy(msg->from_ip, from_ip, INET_ADDRSTRLEN - 1);
    msg->from_ip[INET_ADDRSTRLEN - 1] = '\0';

    if (xQueueSend(auth_message_queue, &msg, pdMS_TO_TICKS(100)) != pdPASS) {
        ESP_LOGE(TAG, "Auth message queue full! Message dropped.");
        free(msg->message);
        free(msg);
    }
}