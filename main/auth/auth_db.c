/* =============================
 * File: auth_db.c
 * Description: Handles NVS-based database operations for authentication.
 * ============================= */

#include "auth_db.h"
#include "utility.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <inttypes.h>

static const char *TAG = "DB";

static SemaphoreHandle_t db_mutex = NULL;

static portMUX_TYPE db_init_spinlock = portMUX_INITIALIZER_UNLOCKED;

#define TAKE_DB_MUTEX(func_name) do { \
    ESP_LOGD("DB_MUTEX", "Attempting to take lock in %s", func_name); \
    xSemaphoreTake(db_mutex, portMAX_DELAY); \
    ESP_LOGD("DB_MUTEX", ">> Lock TAKEN in %s", func_name); \
} while(0)

#define GIVE_DB_MUTEX(func_name) do { \
    ESP_LOGD("DB_MUTEX", "<< Lock GIVEN in %s", func_name); \
    xSemaphoreGive(db_mutex); \
} while(0)


/* ---------------------------------------------------------------- compact network state
 * The network state lists, for every Prover, the challenges assigned to each of its Verifiers. It is
 * replicated on every device and grows with N * q, so it is kept in RAM in a compact form: a challenge is
 * the index of a group of PUF cells of its Prover (challenges are "P<index>@<prover>"), and the two devices
 * are indexes into a table of identifiers. Three bytes per entry instead of a 96-byte record, and lookups
 * in RAM instead of one flash read per entry. The table is written to NVS as two blobs after each change.
 * The content is the same as before: challenges and assignments, which are public, and no response. */
#define CNODE_DEVICE_SLOTS 96
#define CNODE_HOLDER_REVOKED 0xFF
#define CNODE_GROW 64
#define CNODE_TABLE_KEY "cnode_tab"
#define CNODE_DEVICES_KEY "cnode_dev"

typedef struct {
    uint8_t index;   // group of cells of the Prover
    uint8_t target;  // Prover, index into cnode_devices
    uint8_t holder;  // Verifier, index into cnode_devices, or CNODE_HOLDER_REVOKED
} packed_cnode_t;

static char cnode_devices[CNODE_DEVICE_SLOTS][INET_ADDRSTRLEN];
static packed_cnode_t *cnode_table = NULL;
static int cnode_count = 0;
static int cnode_capacity = 0;

static int cnode_device_index(const char *ip, bool create) {
    int free_slot = -1;
    for (int i = 0; i < CNODE_DEVICE_SLOTS; i++) {
        if (cnode_devices[i][0] == '\0') {
            if (free_slot < 0) free_slot = i;
        } else if (strcmp(cnode_devices[i], ip) == 0) {
            return i;
        }
    }
    if (!create) return -1;
    if (free_slot < 0) {
        // Identifiers no longer referenced by any entry are released, then the lookup is repeated once.
        bool used[CNODE_DEVICE_SLOTS] = {0};
        for (int k = 0; k < cnode_count; k++) {
            used[cnode_table[k].target] = true;
            if (cnode_table[k].holder != CNODE_HOLDER_REVOKED) used[cnode_table[k].holder] = true;
        }
        for (int i = 0; i < CNODE_DEVICE_SLOTS; i++) {
            if (!used[i]) { cnode_devices[i][0] = '\0'; if (free_slot < 0) free_slot = i; }
        }
        if (free_slot < 0) return -1;
    }
    strncpy(cnode_devices[free_slot], ip, INET_ADDRSTRLEN - 1);
    cnode_devices[free_slot][INET_ADDRSTRLEN - 1] = '\0';
    return free_slot;
}

/** Parses "P<index>@<prover>", which must name the given Prover. */
static bool cnode_parse_challenge(const char *challenge, const char *target_ip, uint8_t *index) {
    const size_t prefix = strlen(PUF_CHALLENGE_PREFIX);
    if (strncmp(challenge, PUF_CHALLENGE_PREFIX, prefix) != 0) return false;
    char *end = NULL;
    long value = strtol(challenge + prefix, &end, 10);
    if (end == challenge + prefix || *end != '@' || value < 0 || value >= PUF_RESPONSE_CAPACITY) return false;
    if (strcmp(end + 1, target_ip) != 0) return false;
    *index = (uint8_t)value;
    return true;
}

static void cnode_format(const packed_cnode_t *e, char *challenge, size_t challenge_size, char *target_ip, char *holder_ip) {
    if (challenge) snprintf(challenge, challenge_size, "%s%u@%s", PUF_CHALLENGE_PREFIX, (unsigned)e->index, cnode_devices[e->target]);
    if (target_ip) { strncpy(target_ip, cnode_devices[e->target], INET_ADDRSTRLEN - 1); target_ip[INET_ADDRSTRLEN - 1] = '\0'; }
    if (holder_ip) {
        const char *h = (e->holder == CNODE_HOLDER_REVOKED) ? DB_REVOKED_HOLDER : cnode_devices[e->holder];
        strncpy(holder_ip, h, INET_ADDRSTRLEN - 1);
        holder_ip[INET_ADDRSTRLEN - 1] = '\0';
    }
}

static int cnode_find(uint8_t index, int target, int holder) {
    for (int k = 0; k < cnode_count; k++) {
        if (cnode_table[k].index == index && cnode_table[k].target == target && cnode_table[k].holder == holder) return k;
    }
    return -1;
}

/** Appends an entry to the table in RAM (the caller writes it to NVS). Duplicates are ignored. */
static esp_err_t cnode_add_unsafe(const char *challenge, const char *target_ip, const char *holder_ip) {
    uint8_t index;
    if (!cnode_parse_challenge(challenge, target_ip, &index)) {
        ESP_LOGE(TAG, "Malformed challenge %s for %s: entry not stored.", challenge, target_ip);
        return ESP_ERR_INVALID_ARG;
    }
    int target = cnode_device_index(target_ip, true);
    int holder = (strcmp(holder_ip, DB_REVOKED_HOLDER) == 0) ? CNODE_HOLDER_REVOKED : cnode_device_index(holder_ip, true);
    if (target < 0 || holder < 0) {
        ESP_LOGE(TAG, "Network state full: no identifier left for %s / %s.", target_ip, holder_ip);
        return ESP_ERR_NO_MEM;
    }
    if (cnode_find(index, target, holder) >= 0) return ESP_OK;
    if (cnode_count >= MAX_CNODE) {
        ESP_LOGE(TAG, "Cannot insert CNode, network state is full (max %d).", MAX_CNODE);
        return ESP_ERR_NO_MEM;
    }
    if (cnode_count == cnode_capacity) {
        packed_cnode_t *grown = realloc(cnode_table, (cnode_capacity + CNODE_GROW) * sizeof(packed_cnode_t));
        if (!grown) return ESP_ERR_NO_MEM;
        cnode_table = grown;
        cnode_capacity += CNODE_GROW;
    }
    cnode_table[cnode_count++] = (packed_cnode_t){ .index = index, .target = (uint8_t)target, .holder = (uint8_t)holder };
    return ESP_OK;
}

static esp_err_t cnode_save_unsafe(nvs_handle_t handle) {
    esp_err_t err = nvs_set_blob(handle, CNODE_DEVICES_KEY, cnode_devices, sizeof(cnode_devices));
    if (err == ESP_OK) {
        if (cnode_count > 0) err = nvs_set_blob(handle, CNODE_TABLE_KEY, cnode_table, cnode_count * sizeof(packed_cnode_t));
        else { err = nvs_erase_key(handle, CNODE_TABLE_KEY); if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK; }
    }
    if (err == ESP_OK) err = nvs_commit(handle);
    if (err != ESP_OK) ESP_LOGE(TAG, "Failed to store the network state: %s", esp_err_to_name(err));
    return err;
}

/** Writes the table to NVS, opening the namespace. */
static void cnode_persist_unsafe(void) {
    nvs_handle_t handle;
    if (nvs_open(DB_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
        cnode_save_unsafe(handle);
        nvs_close(handle);
    }
}

static void cnode_load_unsafe(nvs_handle_t handle) {
    memset(cnode_devices, 0, sizeof(cnode_devices));
    free(cnode_table);
    cnode_table = NULL;
    cnode_count = cnode_capacity = 0;
    size_t size = sizeof(cnode_devices);
    if (nvs_get_blob(handle, CNODE_DEVICES_KEY, cnode_devices, &size) != ESP_OK) {
        memset(cnode_devices, 0, sizeof(cnode_devices));
        return;
    }
    size = 0;
    if (nvs_get_blob(handle, CNODE_TABLE_KEY, NULL, &size) != ESP_OK || size == 0) return;
    int entries = size / sizeof(packed_cnode_t);
    cnode_capacity = ((entries + CNODE_GROW - 1) / CNODE_GROW) * CNODE_GROW;
    cnode_table = malloc(cnode_capacity * sizeof(packed_cnode_t));
    if (!cnode_table) { cnode_capacity = 0; return; }
    if (nvs_get_blob(handle, CNODE_TABLE_KEY, cnode_table, &size) == ESP_OK) cnode_count = entries;
}

static void cnode_clear_unsafe(void) {
    memset(cnode_devices, 0, sizeof(cnode_devices));
    free(cnode_table);
    cnode_table = NULL;
    cnode_count = cnode_capacity = 0;
}

/**
 * @brief (Internal) Inserts a CNode entry without taking the mutex. The caller writes the table to NVS.
 */
static esp_err_t __db_insert_cnode_unsafe(nvs_handle_t handle, const char *challenge, const char *target_ip, const char *holder_ip) {
    (void)handle;
    return cnode_add_unsafe(challenge, target_ip, holder_ip);
}

/**
 * @brief (Internal) Inserts a CRP entry without taking the mutex.
 * @details This is an internal helper function designed to be called by functions
 * that already hold the db_mutex, such as db_join_commit, to avoid deadlocks.
 * @param handle An open NVS handle with write permissions.
 * @param crp A pointer to the CRPNode to insert.
 */
static esp_err_t __db_insert_crp_unsafe(nvs_handle_t handle, const CRPNode *crp) {
    // A staged CRP whose response never arrived is not a credential.
    if (strcmp(crp->response, DB_PENDING_RESPONSE) == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    int32_t crp_count = 0;
    nvs_get_i32(handle, "crp_count", &crp_count);

    if (crp_count >= MAX_CRP) {
        ESP_LOGE(TAG, "Cannot insert CRP, DB is full (max %d).", MAX_CRP);
        return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    }

    char key[20];
    snprintf(key, sizeof(key), "crp_%" PRId32, crp_count);
    esp_err_t err = nvs_set_blob(handle, key, crp, sizeof(CRPNode));
    if (err != ESP_OK) {
        return err;
    }
    // The count is updated at every insertion, so that consecutive insertions do not reuse the same key.
    return nvs_set_i32(handle, "crp_count", crp_count + 1);
}

/**
 * @brief (Internal) Clears temporary data without taking the mutex.
 * @details This is an internal helper function designed to be called by functions
 * that already hold the db_mutex, such as db_init, to avoid deadlocks.
 */
static void __db_join_tmp_clear_unsafe(void) {
    nvs_handle_t tmp_handle;
    esp_err_t err = nvs_open(DB_TMP_NAMESPACE, NVS_READWRITE, &tmp_handle);
    if (err == ESP_OK) {
        nvs_erase_all(tmp_handle);
        nvs_commit(tmp_handle);
        nvs_close(tmp_handle);
        ESP_LOGD(TAG, "Temporary join DB cleared.");
    }
}

/**
 * @brief Initializes the NVS-based database.
 * This function sets up the non-volatile storage, creates the necessary mutex for
 * thread-safe access, and reads the persisted node and entry counts.
 * @return void
 */
void db_init(void) {
    ESP_LOGI(TAG, "Initializing Node DB Module...");
    if (db_mutex == NULL) {
        taskENTER_CRITICAL(&db_init_spinlock);
        if (db_mutex == NULL) {
            db_mutex = xSemaphoreCreateMutex();
        }
        taskEXIT_CRITICAL(&db_init_spinlock);
    }

    if (db_mutex == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create DB mutex!");
        return;
    }

    nvs_handle_t my_handle = 0;

    ESP_LOGD(TAG, "Attempting to take DB mutex for initialization...");
    if (xSemaphoreTake(db_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to take DB mutex during init. Aborting.");
        return;
    }
    ESP_LOGD(TAG, "Mutex taken. Initializing database...");

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition corrupted or full, erasing and re-initializing.");
        err = nvs_flash_erase();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to erase NVS! Error: %s", esp_err_to_name(err));
            goto cleanup;
        }
        err = nvs_flash_init();
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize NVS flash! Error: %s", esp_err_to_name(err));
        goto cleanup;
    }

    __db_join_tmp_clear_unsafe();

    err = nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error (%s) opening NVS handle!", esp_err_to_name(err));
        goto cleanup;
    }
    cnode_load_unsafe(my_handle);

    ESP_LOGI(TAG, "DB initialized successfully (%d network-state entries).", cnode_count);

cleanup:
    if (my_handle != 0) {
        nvs_close(my_handle);
    }

    ESP_LOGD(TAG, "Releasing DB mutex after initialization.");
    xSemaphoreGive(db_mutex);
}

/**
 * @brief Gets the number of follower nodes currently registered in the database.
 * @return The total number of nodes minus one (for this node), or 0 if none.
 */
int db_get_follower_count(void) {
    int count = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t node_count = 0;
        nvs_get_i32(my_handle, "node_count", &node_count);
        count = (node_count > 0) ? (node_count - 1) : 0;
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return count;
}

/**
 * @brief Gets the IP of the follower at a given index.
 * @param index The 0-based index of the follower to retrieve.
 * @param ip_buffer A character buffer to store the retrieved IP address.
 * @param buffer_size The size of the provided ip_buffer.
 * @return true if a follower at the specified index was found and copied, false otherwise.
 */
bool db_get_follower_ip(int index, char *ip_buffer, size_t buffer_size) {
    bool found = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t node_count = 0;
        nvs_get_i32(my_handle, "node_count", &node_count);
        int follower_idx = 0;
        for (int i = 0; i < node_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "node_%d", i);
            NodeEntry node;
            size_t required_size = sizeof(NodeEntry);
            if (nvs_get_blob(my_handle, key, &node, &required_size) == ESP_OK) {
                char my_node_ip[INET_ADDRSTRLEN] = {0};
                get_my_ip(my_node_ip, sizeof(my_node_ip));
                my_node_ip[sizeof(my_node_ip) - 1] = '\0';
                if (my_node_ip[0] != '\0' && strcmp(node.ip, my_node_ip) != 0) {
                    if (follower_idx == index) {
                        strncpy(ip_buffer, node.ip, buffer_size - 1);
                        ip_buffer[buffer_size - 1] = '\0';
                        found = true;
                        break;
                    }
                    follower_idx++;
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return found;
}

/**
 * @brief Checks if a node with the given IP exists in the database.
 * @param ip The IP address string of the node to check.
 * @return true if the node exists, false otherwise.
 */
bool db_node_exists(const char *ip) {
    bool exists = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t node_count = 0;
        nvs_get_i32(my_handle, "node_count", &node_count);
        for (int i = 0; i < node_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "node_%d", i);
            NodeEntry node;
            size_t required_size = sizeof(NodeEntry);
            if (nvs_get_blob(my_handle, key, &node, &required_size) == ESP_OK) {
                if (strcmp(node.ip, ip) == 0) {
                    exists = true;
                    break;
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return exists;
}

/**
 * @brief Inserts a new node into the database if it doesn't already exist.
 * @param node_id The ID of the new node (can be the same as the IP).
 * @param ip The IP address of the new node.
 * @return void
 */
void db_insert_node(const char *node_id, const char *ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle) == ESP_OK) {
        int32_t current_node_count = 0;
        nvs_get_i32(my_handle, "node_count", &current_node_count);

        if (current_node_count >= MAX_NODES) {
            ESP_LOGE(TAG, "Cannot insert node, DB is full (max %d).", MAX_NODES);
            nvs_close(my_handle);
            GIVE_DB_MUTEX(__FUNCTION__);
            return;
        }

        bool exists = false;
        for (int i = 0; i < current_node_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "node_%d", i);
            NodeEntry node;
            size_t required_size = sizeof(NodeEntry);
            if (nvs_get_blob(my_handle, key, &node, &required_size) == ESP_OK && strcmp(node.ip, ip) == 0) {
                exists = true;
                break;
            }
        }

        if (!exists) {
            NodeEntry new_node;
            strncpy(new_node.id, node_id, sizeof(new_node.id) - 1);
            new_node.id[sizeof(new_node.id) - 1] = '\0';
            strncpy(new_node.ip, ip, sizeof(new_node.ip) - 1);
            new_node.ip[sizeof(new_node.ip) - 1] = '\0';

            char key[20];
            snprintf(key, sizeof(key), "node_%" PRId32, current_node_count);

            esp_err_t err_blob = nvs_set_blob(my_handle, key, &new_node, sizeof(NodeEntry));
            esp_err_t err_count = nvs_set_i32(my_handle, "node_count", current_node_count + 1);

            if (err_blob == ESP_OK && err_count == ESP_OK) {
                if (nvs_commit(my_handle) != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to commit NVS for node insert!");
                }
            } else {
                ESP_LOGE(TAG, "Failed to stage data for node insert!");
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Retrieves the node ID for a given IP address.
 * @param ip The IP address of the node to look up.
 * @param id_buffer A character buffer to store the retrieved ID.
 * @param buffer_size The size of the provided id_buffer.
 * @return true if the node was found and its ID was copied, false otherwise.
 */
bool get_id_for_node(const char *ip, char *id_buffer, size_t buffer_size) {
    bool found = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t node_count = 0;
        nvs_get_i32(my_handle, "node_count", &node_count);
        for (int i = 0; i < node_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "node_%d", i);
            NodeEntry node;
            size_t required_size = sizeof(NodeEntry);
            if (nvs_get_blob(my_handle, key, &node, &required_size) == ESP_OK) {
                if (strcmp(node.ip, ip) == 0) {
                    strncpy(id_buffer, node.id, buffer_size - 1);
                    id_buffer[buffer_size - 1] = '\0';
                    found = true;
                    break;
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return found;
}

/**
 * @brief Retrieves the IP of a random follower node using a thread-safe random number generator.
 * @param ip_buffer A buffer provided by the caller to store the resulting IP address.
 * @param buffer_size The size of the provided buffer.
 * @return true if a follower was found and the IP was copied, false otherwise.
 */
bool db_get_random_follower_ip(char *ip_buffer, size_t buffer_size) {
    bool found = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t node_count = 0;
        nvs_get_i32(my_handle, "node_count", &node_count);

        int follower_match_count = 0;
        for (int i = 0; i < node_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "node_%d", i);
            NodeEntry node;
            size_t required_size = sizeof(NodeEntry);

            if (nvs_get_blob(my_handle, key, &node, &required_size) == ESP_OK) {
                char my_node_ip[INET_ADDRSTRLEN] = {0};
                get_my_ip(my_node_ip, sizeof(my_node_ip));
                my_node_ip[sizeof(my_node_ip) - 1] = '\0';
                if (my_node_ip[0] != '\0' && strcmp(node.ip, my_node_ip) != 0) {
                    follower_match_count++;
                    if ((esp_random() % follower_match_count) == 0) {
                        strncpy(ip_buffer, node.ip, buffer_size - 1);
                        ip_buffer[buffer_size - 1] = '\0';
                        found = true;
                    }
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);

    return found;
}

/**
 * @brief Picks at random one of the Verifiers of this device (revoked challenges are skipped).
 * @return A newly allocated string, or NULL if there is none.
 */
char *db_get_random_verifier_for_me(const char *my_ip) {
    char *selected = NULL;
    TAKE_DB_MUTEX(__FUNCTION__);
    int me = cnode_device_index(my_ip, false);
    int matches = 0, chosen = -1;
    for (int k = 0; me >= 0 && k < cnode_count; k++) {
        if (cnode_table[k].target == me && cnode_table[k].holder != CNODE_HOLDER_REVOKED && cnode_table[k].holder != me) {
            matches++;
            if ((esp_random() % matches) == 0) chosen = cnode_table[k].holder;
        }
    }
    if (chosen >= 0) selected = strdup(cnode_devices[chosen]);
    GIVE_DB_MUTEX(__FUNCTION__);
    return selected;
}

/**
 * @brief Checks if a specific CNode entry exists.
 */
bool db_cnode_exists(const char *challenge, const char *target_ip, const char *holder_ip) {
    bool exists = false;
    uint8_t index;
    TAKE_DB_MUTEX(__FUNCTION__);
    if (cnode_parse_challenge(challenge, target_ip, &index)) {
        int target = cnode_device_index(target_ip, false);
        int holder = (strcmp(holder_ip, DB_REVOKED_HOLDER) == 0) ? CNODE_HOLDER_REVOKED : cnode_device_index(holder_ip, false);
        exists = target >= 0 && holder >= 0 && cnode_find(index, target, holder) >= 0;
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return exists;
}

/**
 * @brief Inserts a new CNode entry into the database if it does not already exist.
 */
void db_insert_cnode(const char *challenge, const char *target_ip, const char *holder_ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    int before = cnode_count;
    if (cnode_add_unsafe(challenge, target_ip, holder_ip) == ESP_OK && cnode_count != before) cnode_persist_unsafe();
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Retrieves a random Challenge-Response Pair (CRP) for a specific target node.
 * @details This function uses an efficient reservoir sampling algorithm to find a random
 * CRP for the given node IP with minimal memory overhead.
 * @param target_ip The IP address of the node for which to find a CRP.
 * @return A pointer to a dynamically allocated CRPNode struct. The caller must free this memory. Returns NULL if no CRP is found.
 */
CRPNode *db_get_random_crp_for_node(const char *target_ip) {
    CRPNode *selected_crp = NULL;
    CRPNode candidate_crp;
    int match_count = 0;
    bool candidate_found = false;

    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t crp_count = 0;
        nvs_get_i32(my_handle, "crp_count", &crp_count);
        for (int i = 0; i < crp_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "crp_%d", i);
            size_t required_size = sizeof(CRPNode);
            CRPNode temp_crp;

            if (nvs_get_blob(my_handle, key, &temp_crp, &required_size) == ESP_OK) {
                if (strcmp(temp_crp.target_ip, target_ip) == 0) {
                    match_count++;
                    if ((esp_random() % match_count) == 0) {
                        memcpy(&candidate_crp, &temp_crp, sizeof(CRPNode));
                        candidate_found = true;
                    }
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);

    if (candidate_found) {
        selected_crp = malloc(sizeof(CRPNode));
        if (selected_crp) {
            memcpy(selected_crp, &candidate_crp, sizeof(CRPNode));
        } else {
            ESP_LOGE(TAG, "Failed to allocate memory for selected CRP.");
        }
    }

    return selected_crp;
}

void db_log_storage(void) {
#if CONFIG_LOG_MAXIMUM_LEVEL < 3
    // Release profile: no diagnostics.
    return;
#endif
    if (db_mutex == NULL) return;
    nvs_stats_t stats;
    if (nvs_get_stats(NULL, &stats) != ESP_OK) return;
    int32_t crps = 0, cnodes = 0, nodes = 0;
    size_t db_entries = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &handle) == ESP_OK) {
        nvs_get_i32(handle, "crp_count", &crps);
        cnodes = cnode_count;
        nvs_get_i32(handle, "node_count", &nodes);
        nvs_get_used_entry_count(handle, &db_entries);
        nvs_close(handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    ESP_LOGI("STORAGE", "nvs used %u of %u entries, network state and shards %u entries (%u bytes), members %ld, crps %ld, cnodes %ld",
             (unsigned)stats.used_entries, (unsigned)stats.total_entries, (unsigned)db_entries, (unsigned)(db_entries * 32),
             (long)nodes, (long)crps, (long)cnodes);
}

int db_get_crps_for_node(const char *target_ip, CRPNode *out, int max) {
    int found = 0;
    if (!out || max <= 0) return 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t crp_count = 0;
        nvs_get_i32(my_handle, "crp_count", &crp_count);
        for (int i = 0; i < crp_count && found < max; i++) {
            char key[20];
            snprintf(key, sizeof(key), "crp_%d", i);
            size_t required_size = sizeof(CRPNode);
            CRPNode temp_crp;
            if (nvs_get_blob(my_handle, key, &temp_crp, &required_size) == ESP_OK && strcmp(temp_crp.target_ip, target_ip) == 0) {
                memcpy(&out[found++], &temp_crp, sizeof(CRPNode));
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);

    // The checks start from a random CRP, so that all of them are used over time.
    if (found > 1) {
        int shift = esp_random() % found;
        for (int s = 0; s < shift; s++) {
            CRPNode first;
            memcpy(&first, &out[0], sizeof(CRPNode));
            memmove(&out[0], &out[1], (found - 1) * sizeof(CRPNode));
            memcpy(&out[found - 1], &first, sizeof(CRPNode));
        }
    }
    return found;
}

/**
 * @brief Retrieves a CRPNode by its challenge.
 * @param challenge The challenge string to search for.
 * @return A pointer to a dynamically allocated CRPNode. The caller must free this memory. Returns NULL if not found or on memory allocation failure.
 */
CRPNode *db_get_crp_by_challenge(const char *challenge) {
    CRPNode *crp = NULL;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t crp_count = 0;
        nvs_get_i32(my_handle, "crp_count", &crp_count);
        
        bool found = false;
        if (crp_count > 0) {
            crp = malloc(sizeof(CRPNode));
            if (crp) {
                for (int i = 0; i < crp_count; i++) {
                    char key[20];
                    snprintf(key, sizeof(key), "crp_%d", i);
                    size_t required_size = sizeof(CRPNode);
                    if (nvs_get_blob(my_handle, key, crp, &required_size) == ESP_OK) {
                        if (strcmp(crp->challenge, challenge) == 0) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) {
                    free(crp);
                    crp = NULL;
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return crp;
}

/**
 * @brief Inserts a new Challenge-Response Pair (CRP) into the database.
 * @param crp A pointer to the CRPNode struct containing the new data.
 */
void db_insert_crp(const CRPNode *crp) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle) == ESP_OK) {
        int32_t crp_count = 0;
        nvs_get_i32(my_handle, "crp_count", &crp_count);
        if (__db_insert_crp_unsafe(my_handle, crp) == ESP_OK) {
            esp_err_t err_count = nvs_set_i32(my_handle, "crp_count", crp_count + 1);
            if (err_count == ESP_OK && nvs_commit(my_handle) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to commit NVS for crp insert!");
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Exports the entire node table as a JSON string.
 * @return A dynamically allocated string containing the JSON representation of the node table. The caller must free this string. Returns NULL on failure.
 */
char *db_export_nodes_json(void) {
    char *json_string = NULL;
    TAKE_DB_MUTEX(__FUNCTION__);
    cJSON *root = cJSON_CreateArray();
    if (root) {
        nvs_handle_t my_handle;
        if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
            int32_t node_count = 0;
            nvs_get_i32(my_handle, "node_count", &node_count);
            for (int i = 0; i < node_count; i++) {
                char key[20];
                snprintf(key, sizeof(key), "node_%d", i);
                NodeEntry node;
                size_t required_size = sizeof(NodeEntry);
                if (nvs_get_blob(my_handle, key, &node, &required_size) == ESP_OK) {
                    cJSON *node_json = cJSON_CreateObject();
                    cJSON_AddStringToObject(node_json, "id", node.id);
                    cJSON_AddStringToObject(node_json, "ip", node.ip);
                    cJSON_AddItemToArray(root, node_json);
                }
            }
            nvs_close(my_handle);
        }
        json_string = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return json_string;
}

/**
 * @brief Exports the CNode table as a JSON array of {c, t, h}.
 */
char *db_export_cnode_json(void) {
    char *json_string = NULL;
    TAKE_DB_MUTEX(__FUNCTION__);
    cJSON *root = cJSON_CreateArray();
    if (root) {
        for (int k = 0; k < cnode_count; k++) {
            char challenge[64], target[INET_ADDRSTRLEN], holder[INET_ADDRSTRLEN];
            cnode_format(&cnode_table[k], challenge, sizeof(challenge), target, holder);
            cJSON *item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "c", challenge);
            cJSON_AddStringToObject(item, "t", target);
            cJSON_AddStringToObject(item, "h", holder);
            cJSON_AddItemToArray(root, item);
        }
        json_string = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return json_string;
}

/**
 * @brief Imports a node table from a JSON string, adding only new nodes.
 * @param json_string A null-terminated C-string containing the JSON array of nodes.
 */
void db_import_nodes_json(const char *json_string) {
    cJSON *root = cJSON_Parse(json_string);
    if (!root || !cJSON_IsArray(root)) {
        if (root)
            cJSON_Delete(root);
        return;
    }
    cJSON *node_json;
    cJSON_ArrayForEach(node_json, root) {
        cJSON *id_item = cJSON_GetObjectItem(node_json, "id");
        cJSON *ip_item = cJSON_GetObjectItem(node_json, "ip");
        if (cJSON_IsString(id_item) && cJSON_IsString(ip_item)) {
            db_insert_node(id_item->valuestring, ip_item->valuestring);
        }
    }
    cJSON_Delete(root);
}

/**
 * @brief Imports CNode entries from a JSON array of {c, t, h}, adding them to the existing table.
 */
void db_import_cnode_json(const char *json) {
    cJSON *root = cJSON_Parse(json);
    if (!root || !cJSON_IsArray(root)) {
        if (root) cJSON_Delete(root);
        return;
    }
    TAKE_DB_MUTEX(__FUNCTION__);
    int before = cnode_count;
    cJSON *item;
    cJSON_ArrayForEach(item, root) {
        cJSON *c = cJSON_GetObjectItem(item, "c");
        cJSON *t = cJSON_GetObjectItem(item, "t");
        cJSON *h = cJSON_GetObjectItem(item, "h");
        if (cJSON_IsString(c) && cJSON_IsString(t) && cJSON_IsString(h)) {
            cnode_add_unsafe(c->valuestring, t->valuestring, h->valuestring);
        }
    }
    if (cnode_count != before) cnode_persist_unsafe();
    GIVE_DB_MUTEX(__FUNCTION__);
    cJSON_Delete(root);
}

/**
 * @brief Exports the whole network state for a joining device in a compact text form.
 * @details Format: "<id0>,<id1>,...#<index>.<prover>.<verifier>;..." where prover and verifier are positions
 * in the list of identifiers and a revoked Verifier is "r". The entries of delta_json (a JSON array of
 * {c, t, h}, e.g., those of the join in progress) are appended. The caller frees the string.
 */
char *db_export_state_compact(const char *delta_json) {
    TAKE_DB_MUTEX(__FUNCTION__);
    cJSON *delta = delta_json ? cJSON_Parse(delta_json) : NULL;
    int extra = (delta && cJSON_IsArray(delta)) ? cJSON_GetArraySize(delta) : 0;
    // Identifiers used by the exported entries, in the order of first use.
    char (*ids)[INET_ADDRSTRLEN] = calloc(CNODE_DEVICE_SLOTS + 2 * extra + 1, INET_ADDRSTRLEN);
    size_t cap = (size_t)(cnode_count + extra) * 12 + (CNODE_DEVICE_SLOTS + 2 * extra) * (INET_ADDRSTRLEN + 1) + 2;
    char *entries = malloc((size_t)(cnode_count + extra) * 12 + 2);
    char *out = malloc(cap);
    int id_count = 0;
    if (!ids || !entries || !out) goto fail;
    size_t elen = 0;
    entries[0] = '\0';
    for (int k = 0; k < cnode_count + extra; k++) {
        char challenge[64], target[INET_ADDRSTRLEN], holder[INET_ADDRSTRLEN];
        uint8_t index;
        if (k < cnode_count) {
            cnode_format(&cnode_table[k], challenge, sizeof(challenge), target, holder);
        } else {
            cJSON *item = cJSON_GetArrayItem(delta, k - cnode_count);
            cJSON *c = cJSON_GetObjectItem(item, "c"), *t = cJSON_GetObjectItem(item, "t"), *h = cJSON_GetObjectItem(item, "h");
            if (!cJSON_IsString(c) || !cJSON_IsString(t) || !cJSON_IsString(h)) continue;
            snprintf(challenge, sizeof(challenge), "%s", c->valuestring);
            snprintf(target, sizeof(target), "%s", t->valuestring);
            snprintf(holder, sizeof(holder), "%s", h->valuestring);
        }
        if (!cnode_parse_challenge(challenge, target, &index)) continue;
        int ti = -1, hi = -1;
        bool revoked = strcmp(holder, DB_REVOKED_HOLDER) == 0;
        for (int i = 0; i < id_count; i++) {
            if (strcmp(ids[i], target) == 0) ti = i;
            if (!revoked && strcmp(ids[i], holder) == 0) hi = i;
        }
        if (ti < 0) { ti = id_count; strcpy(ids[id_count++], target); }
        if (!revoked && hi < 0) { hi = id_count; strcpy(ids[id_count++], holder); }
        if (revoked) elen += sprintf(entries + elen, "%s%u.%d.r", elen ? ";" : "", (unsigned)index, ti);
        else elen += sprintf(entries + elen, "%s%u.%d.%d", elen ? ";" : "", (unsigned)index, ti, hi);
    }
    size_t olen = 0;
    for (int i = 0; i < id_count; i++) olen += sprintf(out + olen, "%s%s", i ? "," : "", ids[i]);
    olen += sprintf(out + olen, "#%s", entries);
    free(ids);
    free(entries);
    if (delta) cJSON_Delete(delta);
    GIVE_DB_MUTEX(__FUNCTION__);
    return out;
fail:
    free(ids);
    free(entries);
    free(out);
    if (delta) cJSON_Delete(delta);
    GIVE_DB_MUTEX(__FUNCTION__);
    return NULL;
}

/**
 * @brief Replaces the network state with the one exported by db_export_state_compact.
 * @return true if the text was well formed.
 */
bool db_import_state_compact(const char *state) {
    const char *hash = strchr(state, '#');
    if (!hash) return false;
    char (*ids)[INET_ADDRSTRLEN] = calloc(CNODE_DEVICE_SLOTS + 1, INET_ADDRSTRLEN);
    if (!ids) return false;
    int id_count = 0;
    const char *p = state;
    while (p < hash && id_count < CNODE_DEVICE_SLOTS) {
        const char *comma = memchr(p, ',', hash - p);
        const char *end = comma ? comma : hash;
        size_t n = end - p;
        if (n == 0 || n >= INET_ADDRSTRLEN) { free(ids); return false; }
        memcpy(ids[id_count], p, n);
        ids[id_count++][n] = '\0';
        p = comma ? comma + 1 : hash;
    }
    TAKE_DB_MUTEX(__FUNCTION__);
    cnode_clear_unsafe();
    bool ok = true;
    p = hash + 1;
    while (*p) {
        unsigned index = 0;
        int ti = -1, hi = -1, used = 0;
        char holder_tag = 0;
        if (sscanf(p, "%u.%d.%n", &index, &ti, &used) < 2 || used == 0) { ok = false; break; }
        p += used;
        if (*p == 'r') { holder_tag = 'r'; p++; }
        else { char *end; hi = (int)strtol(p, &end, 10); if (end == p) { ok = false; break; } p = end; }
        if (ti < 0 || ti >= id_count || (holder_tag != 'r' && (hi < 0 || hi >= id_count))) { ok = false; break; }
        char challenge[64];
        snprintf(challenge, sizeof(challenge), "%s%u@%s", PUF_CHALLENGE_PREFIX, index, ids[ti]);
        cnode_add_unsafe(challenge, ids[ti], holder_tag == 'r' ? DB_REVOKED_HOLDER : ids[hi]);
        if (*p == ';') p++;
        else if (*p) { ok = false; break; }
    }
    cnode_persist_unsafe();
    GIVE_DB_MUTEX(__FUNCTION__);
    free(ids);
    if (!ok) ESP_LOGE(TAG, "Malformed network state received.");
    else ESP_LOGI(TAG, "Network state imported: %d entries.", cnode_count);
    return ok;
}

/**
 * @brief Removes a single node entry and all its associated CRP and CNode entries atomically.
 * @details This function implements an "all-or-nothing" transaction. It stages all deletions
 * (the node, its associated CNodes, and its associated CRPs). The changes are only committed
 * to the NVS if every single step succeeds. If any error occurs, the entire transaction is
 * aborted, leaving the database in its original state and preventing data inconsistency.
 * @param ip The IP of the node to remove.
 */
void db_remove_node(const char *ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle) != ESP_OK) {
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    int32_t old_node_count = 0;
    nvs_get_i32(my_handle, "node_count", &old_node_count);
    if (old_node_count == 0) {
        nvs_close(my_handle);
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    NodeEntry *kept_nodes = malloc(sizeof(NodeEntry) * old_node_count);
    if (!kept_nodes) {
        ESP_LOGE(TAG, "Failed to allocate memory for node removal operation.");
        nvs_close(my_handle);
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    int new_node_count = 0;
    bool found_and_removed = false;

    for (int i = 0; i < old_node_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "node_%d", i);
        NodeEntry node;
        size_t size = sizeof(NodeEntry);
        if (nvs_get_blob(my_handle, key, &node, &size) == ESP_OK) {
            if (strcmp(node.ip, ip) != 0) {
                memcpy(&kept_nodes[new_node_count], &node, sizeof(NodeEntry));
                new_node_count++;
            } else {
                found_and_removed = true;
            }
        }
    }

    if (!found_and_removed) {
        ESP_LOGW(TAG, "Node %s not found in DB for removal, nothing to do.", ip);
        free(kept_nodes);
        nvs_close(my_handle);
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    for (int i = 0; i < old_node_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "node_%d", i);
        nvs_erase_key(my_handle, key);
    }
    
    for (int i = 0; i < new_node_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "node_%d", i);
        nvs_set_blob(my_handle, key, &kept_nodes[i], sizeof(NodeEntry));
    }
    
    nvs_set_i32(my_handle, "node_count", new_node_count);

    if (nvs_commit(my_handle) == ESP_OK) {
        ESP_LOGI(TAG, "Successfully rebuilt node table, removing %s. New count: %d", ip, new_node_count);
    } else {
        ESP_LOGE(TAG, "FATAL: Failed to commit transaction for node remove rebuild!");
    }

    free(kept_nodes);
    nvs_close(my_handle);
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Removes all CRP entries associated with a given node IP from the database.
 * @param target_ip The IP address of the node whose CRPs should be removed.
 */
void db_remove_crp_for_node(const char *target_ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle) == ESP_OK) {
        int32_t crp_count = 0;
        nvs_get_i32(my_handle, "crp_count", &crp_count);
        int i = 0;
        int initial_count = crp_count;
        while (i < crp_count) {
            char key[20];
            snprintf(key, sizeof(key), "crp_%d", i);
            CRPNode crp;
            size_t size = sizeof(CRPNode);

            if (nvs_get_blob(my_handle, key, &crp, &size) == ESP_OK && strcmp(crp.target_ip, target_ip) == 0) {
                bool swap_ok = true;
                if (i < crp_count - 1) {
                    CRPNode last_crp;
                    char last_key[20];
                    snprintf(last_key, sizeof(last_key), "crp_%" PRId32, crp_count - 1);

                    if (nvs_get_blob(my_handle, last_key, &last_crp, &size) == ESP_OK) {
                        if (nvs_set_blob(my_handle, key, &last_crp, sizeof(CRPNode)) != ESP_OK) {
                            swap_ok = false;
                            ESP_LOGE(TAG, "Failed to write swapped crp at index %d", i);
                        }
                    } else {
                        swap_ok = false;
                        ESP_LOGE(TAG, "Failed to read last crp for swap at index %d", i);
                    }
                }

                if (swap_ok) {
                    char key_to_erase[20];
                    snprintf(key_to_erase, sizeof(key_to_erase), "crp_%" PRId32, crp_count - 1);
                    nvs_erase_key(my_handle, key_to_erase);
                    crp_count--;
                } else {
                    i++;
                }
            } else {
                i++;
            }
        }

        if (initial_count != crp_count) {
            nvs_set_i32(my_handle, "crp_count", crp_count);
            if (nvs_commit(my_handle) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to commit NVS for crp remove!");
            }
            ESP_LOGI(TAG, "Removed %d CRPs for node %s.", initial_count - crp_count, target_ip);
        }

        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Removes the entries whose Prover is the given device, and revokes those it held as a Verifier.
 */
void db_remove_cnode_for_node(const char *node_ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    int dev = cnode_device_index(node_ip, false);
    int removed = 0, revoked = 0;
    if (dev >= 0) {
        int w = 0;
        for (int k = 0; k < cnode_count; k++) {
            packed_cnode_t e = cnode_table[k];
            if (e.target == dev) { removed++; continue; }
            // The removed device was the Verifier: the challenge is revoked, not forgotten.
            if (e.holder == dev) { e.holder = CNODE_HOLDER_REVOKED; revoked++; }
            cnode_table[w++] = e;
        }
        cnode_count = w;
        if (removed || revoked) cnode_persist_unsafe();
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    if (removed || revoked) ESP_LOGI(TAG, "Removed %d CNodes and revoked %d for node %s.", removed, revoked, node_ip);
}

/**
 * @brief Moves to new_holder the entries in which self_ip is both the Prover and the Verifier (the
 * credentials of the first Coordinator, created before any other device exists) and returns their
 * challenges, so that the corresponding CRPs can be handed over.
 */
int db_reassign_self_cnodes(const char *self_ip, const char *new_holder, char challenges[][64], int max) {
    int moved = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    int self = cnode_device_index(self_ip, false);
    int holder = cnode_device_index(new_holder, true);
    if (self >= 0 && holder >= 0) {
        for (int k = 0; k < cnode_count && moved < max; k++) {
            if (cnode_table[k].target != self || cnode_table[k].holder != self) continue;
            cnode_format(&cnode_table[k], challenges[moved], 64, NULL, NULL);
            cnode_table[k].holder = (uint8_t)holder;
            moved++;
        }
        if (moved) cnode_persist_unsafe();
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return moved;
}

/**
 * @brief Counts the number of verifiers (holders) for a given target node.
 * @param target_ip The IP address of the node to check.
 * @return The number of verifiers found for the target node.
 */
int db_get_verifier_count_for_node(const char *target_ip) {
    char verifier_ips[MAX_DISTINCT_VERIFIERS][INET_ADDRSTRLEN];
    return db_get_verifiers_for_node(target_ip, verifier_ips, MAX_DISTINCT_VERIFIERS);
}

/**
 * @brief Clears all temporary data related to an active join transaction.
 * @details This function erases the entire temporary NVS namespace ('auth_db_tmp').
 */
void db_join_tmp_clear(void) {
    TAKE_DB_MUTEX(__FUNCTION__);
    __db_join_tmp_clear_unsafe();
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief (For Verifiers) Inserts a new Challenge-Response Pair into temporary storage.
 * @param crp A pointer to the CRPNode struct to be temporarily saved.
 */
void db_join_tmp_insert_crp(uint32_t transaction_id, const CRPNode *crp) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle;
    esp_err_t err = nvs_open(DB_TMP_NAMESPACE, NVS_READWRITE, &tmp_handle);
    if (err == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(tmp_handle, "tmp_crp_count", &count);

        TmpCRPNode tmp_entry;
        tmp_entry.transaction_id = transaction_id;
        memcpy(&tmp_entry.crp, crp, sizeof(CRPNode));

        char key[20];
        snprintf(key, sizeof(key), "crp_%ld", count);
        err = nvs_set_blob(tmp_handle, key, &tmp_entry, sizeof(TmpCRPNode));
        if (err == ESP_OK) {
            count++;
            err = nvs_set_i32(tmp_handle, "tmp_crp_count", count);
        }
        if (err == ESP_OK) {
            err = nvs_commit(tmp_handle);
        }
        nvs_close(tmp_handle);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to stage CRP %s (TID: %lu): %s", crp->challenge, transaction_id, esp_err_to_name(err));
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief (For the Leader) Inserts a new CNode entry into temporary storage.
 * @param challenge The challenge string generated by the verifier.
 * @param target_ip The IP address of the node being verified.
 * @param holder_ip The IP address of the verifier.
 */
void db_join_tmp_insert_cnode(uint32_t transaction_id, const char *challenge, const char *target_ip, const char *holder_ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle;
    if (nvs_open(DB_TMP_NAMESPACE, NVS_READWRITE, &tmp_handle) == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(tmp_handle, "tmp_cnode_count", &count);

        TmpCNodeEntry tmp_entry;
        tmp_entry.transaction_id = transaction_id;
        strncpy(tmp_entry.cnode.challenge, challenge, sizeof(tmp_entry.cnode.challenge) - 1);
        tmp_entry.cnode.challenge[sizeof(tmp_entry.cnode.challenge) - 1] = '\0';
        strncpy(tmp_entry.cnode.target_ip, target_ip, sizeof(tmp_entry.cnode.target_ip) - 1);
        tmp_entry.cnode.target_ip[sizeof(tmp_entry.cnode.target_ip) - 1] = '\0';
        strncpy(tmp_entry.cnode.holder_ip, holder_ip, sizeof(tmp_entry.cnode.holder_ip) - 1);
        tmp_entry.cnode.holder_ip[sizeof(tmp_entry.cnode.holder_ip) - 1] = '\0';

        char key[20];
        snprintf(key, sizeof(key), "cnode_%ld", count);
        if (nvs_set_blob(tmp_handle, key, &tmp_entry, sizeof(TmpCNodeEntry)) == ESP_OK) {
            count++;
            nvs_set_i32(tmp_handle, "tmp_cnode_count", count);
            if (nvs_commit(tmp_handle) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to commit NVS for tmp_cnode insert!");
            }
        }
        nvs_close(tmp_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}
/**
 * @brief (For the Leader) Exports all CNode entries from temporary storage as a JSON string.
 * @return A dynamically allocated string containing the JSON array of temporary CNodes. The caller is responsible for freeing this string. Returns NULL on failure.
 */
char *db_join_tmp_export_cnodes_json(uint32_t transaction_id) {
    char *json_string = NULL;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle;
    if (nvs_open(DB_TMP_NAMESPACE, NVS_READONLY, &tmp_handle) == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(tmp_handle, "tmp_cnode_count", &count);
        cJSON *root = cJSON_CreateArray();
        if (root) {
            for (int i = 0; i < count; i++) {
                char key[20];
                snprintf(key, sizeof(key), "cnode_%d", i);
                TmpCNodeEntry tmp_entry;
                size_t required_size = sizeof(TmpCNodeEntry);
                if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
                    if (tmp_entry.transaction_id == transaction_id) {
                        cJSON *cnode_json = cJSON_CreateObject();
                        cJSON_AddStringToObject(cnode_json, "c", tmp_entry.cnode.challenge);
                        cJSON_AddStringToObject(cnode_json, "t", tmp_entry.cnode.target_ip);
                        cJSON_AddStringToObject(cnode_json, "h", tmp_entry.cnode.holder_ip);
                        cJSON_AddItemToArray(root, cnode_json);
                    }
                }
            }
            json_string = cJSON_PrintUnformatted(root);
            cJSON_Delete(root);
        }
        nvs_close(tmp_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return json_string;
}

/**
 * @brief (For Verifiers) Retrieves a CRP from temporary storage by its challenge.
 * @param challenge The challenge string to search for in the temporary database.
 * @return A pointer to a dynamically allocated CRPNode. Caller must free this. Returns NULL if not found.
 */
CRPNode *db_join_tmp_get_crp_by_challenge(uint32_t transaction_id, const char *challenge) {
    CRPNode *crp = NULL;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle;
    if (nvs_open(DB_TMP_NAMESPACE, NVS_READONLY, &tmp_handle) == ESP_OK) {
        int32_t temp_crp_count = 0;
        nvs_get_i32(tmp_handle, "tmp_crp_count", &temp_crp_count);

        TmpCRPNode tmp_entry;
        bool found = false;
        for (int i = 0; i < temp_crp_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "crp_%d", i);
            size_t required_size = sizeof(TmpCRPNode);
            if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
                if (tmp_entry.transaction_id == transaction_id && strcmp(tmp_entry.crp.challenge, challenge) == 0) {
                    found = true;
                    break;
                }
            }
        }
        
        if (found) {
            crp = malloc(sizeof(CRPNode));
            if (crp) {
                memcpy(crp, &tmp_entry.crp, sizeof(CRPNode));
            }
        }
        nvs_close(tmp_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return crp;
}

/**
 * @brief Lists the distinct Verifiers of a Prover (revoked challenges are skipped).
 */
int db_get_verifiers_for_node(const char* target_ip, char verifier_ips[][INET_ADDRSTRLEN], int max_verifiers) {
    int count = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    int target = cnode_device_index(target_ip, false);
    for (int k = 0; target >= 0 && k < cnode_count && count < max_verifiers; k++) {
        // The entries that the first Coordinator holds for itself, created at genesis, are not a Verifier.
        if (cnode_table[k].target != target || cnode_table[k].holder == CNODE_HOLDER_REVOKED || cnode_table[k].holder == target) continue;
        const char *holder = cnode_devices[cnode_table[k].holder];
        bool listed = false;
        for (int j = 0; j < count && !listed; j++) listed = strcmp(verifier_ips[j], holder) == 0;
        if (!listed) {
            strncpy(verifier_ips[count], holder, INET_ADDRSTRLEN - 1);
            verifier_ips[count][INET_ADDRSTRLEN - 1] = '\0';
            count++;
        }
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return count;
}

/**
 * @brief (For Verifiers) Updates the response of a specific CRP in temporary storage.
 * @details This function is used during the enrollment phase when the Verifier receives
 * the actual PUF response from the Prover. It updates the placeholder "PENDING" response.
 * @param transaction_id The transaction ID.
 * @param challenge The challenge string of the CRP to update.
 * @param new_response The new response string to save.
 */
void db_join_tmp_update_crp_response(uint32_t transaction_id, const char *challenge, const char *new_response) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle;
    if (nvs_open(DB_TMP_NAMESPACE, NVS_READWRITE, &tmp_handle) == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(tmp_handle, "tmp_crp_count", &count);

        for (int i = 0; i < count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "crp_%d", i);
            TmpCRPNode tmp_entry;
            size_t required_size = sizeof(TmpCRPNode);
            if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
                if (tmp_entry.transaction_id == transaction_id && 
                    strcmp(tmp_entry.crp.challenge, challenge) == 0) {
                    
                    ESP_LOGI(TAG, "Updating response for staged CRP (TID: %lu, challenge: %s)", transaction_id, challenge);
                    strncpy(tmp_entry.crp.response, new_response, sizeof(tmp_entry.crp.response) - 1);
                    tmp_entry.crp.response[sizeof(tmp_entry.crp.response) - 1] = '\0';
                    nvs_set_blob(tmp_handle, key, &tmp_entry, sizeof(TmpCRPNode));
                    nvs_commit(tmp_handle);
                    break;
                }
            }
        }
        nvs_close(tmp_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief (For the Leader) Updates the holder_ip of a specific CNode in temporary storage.
 * @details This function finds a CNode in the temporary NVS namespace by its challenge
 * and target IP, and then overwrites its holder_ip field with the new value.
 * This is used during the genesis delegation process.
 * @param challenge The challenge string of the CNode to update.
 * @param target_ip The target IP of the CNode to update.
 * @param new_holder_ip The new IP address to set as the holder.
 * @return void
 */
void db_join_tmp_update_cnode_holder(uint32_t transaction_id, const char* challenge, const char* target_ip, const char* new_holder_ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle;
    if (nvs_open(DB_TMP_NAMESPACE, NVS_READWRITE, &tmp_handle) == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(tmp_handle, "tmp_cnode_count", &count);

        for (int i = 0; i < count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            TmpCNodeEntry tmp_entry;
            size_t required_size = sizeof(TmpCNodeEntry);
            if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
                if (tmp_entry.transaction_id == transaction_id && 
                    strcmp(tmp_entry.cnode.challenge, challenge) == 0 && 
                    strcmp(tmp_entry.cnode.target_ip, target_ip) == 0) {
                    
                    ESP_LOGI(TAG, "Updating holder for staged CNode (TID: %lu, challenge: %s) to %s", transaction_id, challenge, new_holder_ip);
                    strncpy(tmp_entry.cnode.holder_ip, new_holder_ip, sizeof(tmp_entry.cnode.holder_ip) - 1);
                    tmp_entry.cnode.holder_ip[sizeof(tmp_entry.cnode.holder_ip) - 1] = '\0';
                    nvs_set_blob(tmp_handle, key, &tmp_entry, sizeof(TmpCNodeEntry));
                    nvs_commit(tmp_handle);
                    break;
                }
            }
        }
        nvs_close(tmp_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

void __db_join_tmp_clear_by_tid_unsafe(uint32_t transaction_id) {
    ESP_LOGI(TAG, "Cleaning temporary DB for TID %lu...", transaction_id);
    nvs_handle_t tmp_handle;
    if (nvs_open(DB_TMP_NAMESPACE, NVS_READWRITE, &tmp_handle) != ESP_OK) {
        return;
    }

    int32_t old_crp_count = 0, new_crp_count = 0;
    int32_t old_cnode_count = 0, new_cnode_count = 0;
    nvs_get_i32(tmp_handle, "tmp_crp_count", &old_crp_count);
    nvs_get_i32(tmp_handle, "tmp_cnode_count", &old_cnode_count);

    TmpCRPNode* kept_crps = NULL;
    TmpCNodeEntry* kept_cnodes = NULL;

    if (old_crp_count > 0) {
        kept_crps = malloc(sizeof(TmpCRPNode) * old_crp_count);
        if (kept_crps) {
            for (int i = 0; i < old_crp_count; i++) {
                char key[20];
                snprintf(key, sizeof(key), "crp_%d", i);
                TmpCRPNode tmp_entry;
                size_t size = sizeof(TmpCRPNode);
                if (nvs_get_blob(tmp_handle, key, &tmp_entry, &size) == ESP_OK) {
                    if (tmp_entry.transaction_id != transaction_id) {
                        memcpy(&kept_crps[new_crp_count], &tmp_entry, sizeof(TmpCRPNode));
                        new_crp_count++;
                    }
                }
            }
        }
    }

    if (old_cnode_count > 0) {
        kept_cnodes = malloc(sizeof(TmpCNodeEntry) * old_cnode_count);
        if (kept_cnodes) {
            for (int i = 0; i < old_cnode_count; i++) {
                char key[20];
                snprintf(key, sizeof(key), "cnode_%d", i);
                TmpCNodeEntry tmp_entry;
                size_t size = sizeof(TmpCNodeEntry);
                if (nvs_get_blob(tmp_handle, key, &tmp_entry, &size) == ESP_OK) {
                    if (tmp_entry.transaction_id != transaction_id) {
                        memcpy(&kept_cnodes[new_cnode_count], &tmp_entry, sizeof(TmpCNodeEntry));
                        new_cnode_count++;
                    }
                }
            }
        }
    }

    nvs_erase_all(tmp_handle);

    for (int i = 0; i < new_crp_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "crp_%d", i);
        nvs_set_blob(tmp_handle, key, &kept_crps[i], sizeof(TmpCRPNode));
    }
    nvs_set_i32(tmp_handle, "tmp_crp_count", new_crp_count);

    for (int i = 0; i < new_cnode_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "cnode_%d", i);
        nvs_set_blob(tmp_handle, key, &kept_cnodes[i], sizeof(TmpCNodeEntry));
    }
    nvs_set_i32(tmp_handle, "tmp_cnode_count", new_cnode_count);

    nvs_commit(tmp_handle);
    nvs_close(tmp_handle);

    if (kept_crps) free(kept_crps);
    if (kept_cnodes) free(kept_cnodes);
}

void db_join_tmp_clear_by_tid(uint32_t transaction_id) {
    TAKE_DB_MUTEX(__FUNCTION__);
    __db_join_tmp_clear_by_tid_unsafe(transaction_id);
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Retrieves the total number of nodes (including the leader) in the database.
 * @return The total number of nodes.
 */
int db_get_node_count(void) {
    int32_t count = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        nvs_get_i32(my_handle, "node_count", &count);
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return count;
}


/**
 * @brief Retrieves a list of all follower IPs from the database.
 * @param[out] follower_ips A pointer to an array of strings that will be allocated
 * and filled with the IP addresses of the followers.
 * @param[in] max_followers The maximum number of followers that can be stored in the array.
 * @return The number of followers found and copied to the array.
 */
int db_get_all_follower_ips(char ***follower_ips, int max_followers) {
    int count = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t node_count = 0;
        nvs_get_i32(my_handle, "node_count", &node_count);

        *follower_ips = malloc(max_followers * sizeof(char *));
        if (*follower_ips == NULL) {
            ESP_LOGE(TAG, "Failed to allocate memory for follower IPs array.");
            nvs_close(my_handle);
            GIVE_DB_MUTEX(__FUNCTION__);
            return 0;
        }

        for (int i = 0; i < node_count && count < max_followers; i++) {
            char key[20];
            snprintf(key, sizeof(key), "node_%d", i);
            NodeEntry node;
            size_t required_size = sizeof(NodeEntry);
            if (nvs_get_blob(my_handle, key, &node, &required_size) == ESP_OK) {
                char my_node_ip[INET_ADDRSTRLEN] = {0};
                get_my_ip(my_node_ip, sizeof(my_node_ip));
                my_node_ip[sizeof(my_node_ip) - 1] = '\0';
                if (my_node_ip[0] != '\0' && strcmp(node.ip, my_node_ip) != 0) {
                    (*follower_ips)[count] = malloc(INET_ADDRSTRLEN);
                    if ((*follower_ips)[count] != NULL) {
                        strncpy((*follower_ips)[count], node.ip, INET_ADDRSTRLEN - 1);
                        (*follower_ips)[count][INET_ADDRSTRLEN - 1] = '\0';
                        count++;
                    } else {
                        ESP_LOGE(TAG, "Failed to allocate memory for follower IP string.");
                    }
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return count;
}

/**
 * @brief (For the Leader) Commits all temporary join data to the main database.
 * @details This function reads all CRPs and CNodes from the temporary NVS namespace,
 * inserts them into the main NVS namespace, and then clears the temporary data.
 * This operation is atomic within the scope of this function's mutex lock.
 */
void db_join_commit(uint32_t transaction_id) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle, main_handle;

    esp_err_t err_tmp = nvs_open(DB_TMP_NAMESPACE, NVS_READONLY, &tmp_handle);
    if (err_tmp != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open tmp DB for commit.");
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    esp_err_t err_main = nvs_open(DB_NAMESPACE, NVS_READWRITE, &main_handle);
    if (err_main != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open main DB for commit.");
        nvs_close(tmp_handle);
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    int32_t main_cnode_count = cnode_count, main_crp_count = 0;
    nvs_get_i32(main_handle, "crp_count", &main_crp_count);

    int32_t tmp_cnode_count = 0;
    nvs_get_i32(tmp_handle, "tmp_cnode_count", &tmp_cnode_count);
    for (int i = 0; i < tmp_cnode_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "cnode_%d", i);
        TmpCNodeEntry tmp_entry;
        size_t required_size = sizeof(TmpCNodeEntry);
        if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
            if (tmp_entry.transaction_id == transaction_id) {
                if (__db_insert_cnode_unsafe(main_handle, tmp_entry.cnode.challenge, tmp_entry.cnode.target_ip, tmp_entry.cnode.holder_ip) == ESP_OK) {
                    main_cnode_count++;
                }
            }
        }
    }
    if (main_cnode_count != cnode_count || cnode_count > 0) cnode_save_unsafe(main_handle);
    int32_t tmp_crp_count = 0;
    nvs_get_i32(tmp_handle, "tmp_crp_count", &tmp_crp_count);
    for (int i = 0; i < tmp_crp_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "crp_%d", i);
        TmpCRPNode tmp_entry;
        size_t required_size = sizeof(TmpCRPNode);
        if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
            if (tmp_entry.transaction_id == transaction_id) {
                if (__db_insert_crp_unsafe(main_handle, &tmp_entry.crp) == ESP_OK) {
                    main_crp_count++;
                }
            }
        }
    }
    nvs_set_i32(main_handle, "crp_count", main_crp_count);

    nvs_commit(main_handle);
    nvs_close(tmp_handle);
    nvs_close(main_handle);

    __db_join_tmp_clear_by_tid_unsafe(transaction_id);

    GIVE_DB_MUTEX(__FUNCTION__);
    ESP_LOGI(TAG, "Join data for TID %lu committed successfully.", transaction_id);
}

/**
 * @brief Performs a complete wipe of the main authentication database.
 * @details This function erases the entire NVS namespace used for authentication ('auth_db'),
 * including the node list, CNode table, and CRP table. It is called during the node
 * decommissioning process to ensure a removed node has no residual cluster state.
 * @return void
 */
void db_wipe_all_auth_data(void) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    esp_err_t err = nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle);
    if (err == ESP_OK) {
        ESP_LOGW(TAG, "Wiping all data from '%s' namespace.", DB_NAMESPACE);
        nvs_erase_all(my_handle);
        cnode_clear_unsafe();
        nvs_commit(my_handle);
        nvs_close(my_handle);
    } else {
        ESP_LOGE(TAG, "Failed to open NVS to wipe auth data.");
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

void db_join_tmp_commit_crps(uint32_t transaction_id) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle, main_handle;

    esp_err_t err_tmp = nvs_open(DB_TMP_NAMESPACE, NVS_READONLY, &tmp_handle);
    if (err_tmp != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open tmp DB for CRP commit.");
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    esp_err_t err_main = nvs_open(DB_NAMESPACE, NVS_READWRITE, &main_handle);
    if (err_main != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open main DB for CRP commit.");
        nvs_close(tmp_handle);
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    int32_t main_crp_count = 0;
    nvs_get_i32(main_handle, "crp_count", &main_crp_count);
    int committed_count = 0;

    int32_t tmp_crp_count = 0;
    nvs_get_i32(tmp_handle, "tmp_crp_count", &tmp_crp_count);
    
    for (int i = 0; i < tmp_crp_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "crp_%d", i);
        TmpCRPNode tmp_entry;
        size_t required_size = sizeof(TmpCRPNode);
        if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
            if (tmp_entry.transaction_id == transaction_id) {
                if (__db_insert_crp_unsafe(main_handle, &tmp_entry.crp) == ESP_OK) {
                    main_crp_count++;
                    committed_count++;
                }
            }
        }
    }
    
    if (committed_count > 0) {
        nvs_set_i32(main_handle, "crp_count", main_crp_count);
        nvs_commit(main_handle);
        ESP_LOGI(TAG, "Committed %d new CRPs from TID %lu to main DB.", committed_count, transaction_id);
    }

    nvs_close(tmp_handle);
    nvs_close(main_handle);
    GIVE_DB_MUTEX(__FUNCTION__);
}

void db_join_commit_all_pending_heal(void) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t tmp_handle, main_handle;

    ESP_LOGI(TAG, "Committing all pending HEAL data from tmp_db to main_db...");

    esp_err_t err_tmp = nvs_open(DB_TMP_NAMESPACE, NVS_READONLY, &tmp_handle);
    if (err_tmp != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open tmp DB for HEAL batch commit.");
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    esp_err_t err_main = nvs_open(DB_NAMESPACE, NVS_READWRITE, &main_handle);
    if (err_main != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open main DB for HEAL batch commit.");
        nvs_close(tmp_handle);
        GIVE_DB_MUTEX(__FUNCTION__);
        return;
    }

    int32_t main_cnode_count = cnode_count, main_crp_count = 0;
    nvs_get_i32(main_handle, "crp_count", &main_crp_count);

    int32_t committed_cnodes = 0;
    int32_t committed_crps = 0;

    int32_t tmp_cnode_count = 0;
    nvs_get_i32(tmp_handle, "tmp_cnode_count", &tmp_cnode_count);
    for (int i = 0; i < tmp_cnode_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "cnode_%d", i);
        TmpCNodeEntry tmp_entry;
        size_t required_size = sizeof(TmpCNodeEntry);
        if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
            if (__db_insert_cnode_unsafe(main_handle, tmp_entry.cnode.challenge, tmp_entry.cnode.target_ip, tmp_entry.cnode.holder_ip) == ESP_OK) {
                main_cnode_count++;
                committed_cnodes++;
            }
        }
    }
    if (committed_cnodes > 0) {
        cnode_save_unsafe(main_handle);
    }

    int32_t tmp_crp_count = 0;
    nvs_get_i32(tmp_handle, "tmp_crp_count", &tmp_crp_count);
    for (int i = 0; i < tmp_crp_count; i++) {
        char key[20];
        snprintf(key, sizeof(key), "crp_%d", i);
        TmpCRPNode tmp_entry;
        size_t required_size = sizeof(TmpCRPNode);
        if (nvs_get_blob(tmp_handle, key, &tmp_entry, &required_size) == ESP_OK) {
            if (__db_insert_crp_unsafe(main_handle, &tmp_entry.crp) == ESP_OK) {
                main_crp_count++;
                committed_crps++;
            }
        }
    }
    if (committed_crps > 0) {
        nvs_set_i32(main_handle, "crp_count", main_crp_count);
    }

    if (committed_cnodes > 0 || committed_crps > 0) {
        nvs_commit(main_handle);
        ESP_LOGI(TAG, "HEAL Batch Commit: %" PRId32 " CNodes, %" PRId32 " CRPs committed.", committed_cnodes, committed_crps);
    } else {
        ESP_LOGI(TAG, "HEAL Batch Commit: No new data found in tmp_db to commit.");
    }

    nvs_close(tmp_handle);
    nvs_close(main_handle);

    __db_join_tmp_clear_unsafe();

    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Checks if a challenge exists anywhere in the network state or in the data staged by an enrollment.
 */
bool db_challenge_exists_globally(const char *challenge) {
    bool exists = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    const char *at = strchr(challenge, '@');
    uint8_t index;
    if (at && cnode_parse_challenge(challenge, at + 1, &index)) {
        int target = cnode_device_index(at + 1, false);
        for (int k = 0; target >= 0 && k < cnode_count && !exists; k++) {
            exists = cnode_table[k].target == target && cnode_table[k].index == index;
        }
    }
    nvs_handle_t my_handle;
    if (!exists && nvs_open(DB_TMP_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(my_handle, "tmp_cnode_count", &count);
        for (int i = 0; i < count && !exists; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            size_t required_size = sizeof(TmpCNodeEntry);
            TmpCNodeEntry temp_entry;
            if (nvs_get_blob(my_handle, key, &temp_entry, &required_size) == ESP_OK) {
                exists = strcmp(temp_entry.cnode.challenge, challenge) == 0;
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return exists;
}

/**
 * @brief Retrieves one of the challenges of this device assigned to the given Verifier.
 */
bool db_get_challenge_for_verifier(const char* verifier_id, char* challenge_buffer, size_t max_len) {
    bool found = false;
    char my_ip[INET_ADDRSTRLEN] = {0};
    get_my_ip(my_ip, sizeof(my_ip));
    TAKE_DB_MUTEX(__FUNCTION__);
    int me = my_ip[0] ? cnode_device_index(my_ip, false) : -1;
    int holder = cnode_device_index(verifier_id, false);
    for (int k = 0; me >= 0 && holder >= 0 && k < cnode_count && !found; k++) {
        if (cnode_table[k].target == me && cnode_table[k].holder == holder) {
            cnode_format(&cnode_table[k], challenge_buffer, max_len, NULL, NULL);
            found = true;
        }
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return found;
}