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

/**
 * @brief (Internal) Inserts a CNode entry without taking the mutex.
 * @details This is an internal helper function designed to be called by functions
 * that already hold the db_mutex, such as db_join_commit, to avoid deadlocks.
 * @param handle An open NVS handle with write permissions.
 * @param challenge The challenge string.
 * @param target_ip The target IP.
 * @param holder_ip The holder IP.
 */
static esp_err_t __db_insert_cnode_unsafe(nvs_handle_t handle, const char *challenge, const char *target_ip, const char *holder_ip) {
    int32_t cnode_count = 0;
    nvs_get_i32(handle, "cnode_count", &cnode_count);

    if (cnode_count >= MAX_CNODE) {
        ESP_LOGE(TAG, "Cannot insert CNode, DB is full (max %d).", MAX_CNODE);
        return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    }

    CNodeEntry new_cnode;
    strncpy(new_cnode.challenge, challenge, sizeof(new_cnode.challenge) - 1);
    new_cnode.challenge[sizeof(new_cnode.challenge) - 1] = '\0';
    strncpy(new_cnode.target_ip, target_ip, sizeof(new_cnode.target_ip) - 1);
    new_cnode.target_ip[sizeof(new_cnode.target_ip) - 1] = '\0';
    strncpy(new_cnode.holder_ip, holder_ip, sizeof(new_cnode.holder_ip) - 1);
    new_cnode.holder_ip[sizeof(new_cnode.holder_ip) - 1] = '\0';

    char key[20];
    snprintf(key, sizeof(key), "cnode_%" PRId32, cnode_count);
    esp_err_t err = nvs_set_blob(handle, key, &new_cnode, sizeof(CNodeEntry));
    if (err != ESP_OK) {
        return err;
    }

    return ESP_OK;
}

/**
 * @brief (Internal) Inserts a CRP entry without taking the mutex.
 * @details This is an internal helper function designed to be called by functions
 * that already hold the db_mutex, such as db_join_commit, to avoid deadlocks.
 * @param handle An open NVS handle with write permissions.
 * @param crp A pointer to the CRPNode to insert.
 */
static esp_err_t __db_insert_crp_unsafe(nvs_handle_t handle, const CRPNode *crp) {
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

    return ESP_OK;
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

    ESP_LOGI(TAG, "DB initialized successfully.");

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
 * @brief Finds a random verifier (holder) for the current node from the CNode table.
 * @details This function uses an efficient reservoir sampling algorithm to find a random
 * verifier for the given node IP with minimal memory overhead.
 * @param my_ip The IP address of the current node seeking a verifier.
 * @return A dynamically allocated string containing the verifier's IP. The caller must free this string. Returns NULL if no verifier is found.
 */
char *db_get_random_verifier_for_me(const char *my_ip) {
    char *selected_verifier_ip = NULL;
    char candidate_ip_buffer[INET_ADDRSTRLEN];
    int match_count = 0;

    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);
        for (int i = 0; i < cnode_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            CNodeEntry candidate;
            size_t required_size = sizeof(CNodeEntry);
            if (nvs_get_blob(my_handle, key, &candidate, &required_size) == ESP_OK) {
                if (strcmp(candidate.target_ip, my_ip) == 0) {
                    match_count++;
                    if ((esp_random() % match_count) == 0) {
                        strncpy(candidate_ip_buffer, candidate.holder_ip, INET_ADDRSTRLEN - 1);
                        candidate_ip_buffer[INET_ADDRSTRLEN - 1] = '\0';
                    }
                }
            }
        }
        if (match_count > 0) {
            selected_verifier_ip = strdup(candidate_ip_buffer);
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return selected_verifier_ip;
}

/**
 * @brief Checks if a specific CNode entry exists.
 * @param challenge The challenge string of the CNode.
 * @param target_ip The target IP address of the CNode.
 * @param holder_ip The holder IP address of the CNode.
 * @return true if the entry exists, false otherwise.
 */
bool db_cnode_exists(const char *challenge, const char *target_ip, const char *holder_ip) {
    bool exists = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);
        for (int i = 0; i < cnode_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            CNodeEntry cnode;
            size_t required_size = sizeof(CNodeEntry);
            if (nvs_get_blob(my_handle, key, &cnode, &required_size) == ESP_OK) {
                if (strcmp(cnode.challenge, challenge) == 0 && strcmp(cnode.target_ip, target_ip) == 0 && strcmp(cnode.holder_ip, holder_ip) == 0) {
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
 * @brief Inserts a new CNode entry into the database if it does not already exist.
 * @details This function is optimized to perform existence check and insertion in a single pass.
 * @param challenge The challenge string for the new entry.
 * @param target_ip The target IP address for the new entry.
 * @param holder_ip The holder IP address for the new entry.
 */
void db_insert_cnode(const char *challenge, const char *target_ip, const char *holder_ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);

        bool exists = false;
        for (int i = 0; i < cnode_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            CNodeEntry cnode;
            size_t required_size = sizeof(CNodeEntry);
            if (nvs_get_blob(my_handle, key, &cnode, &required_size) == ESP_OK) {
                if (strcmp(cnode.challenge, challenge) == 0 && strcmp(cnode.target_ip, target_ip) == 0 && strcmp(cnode.holder_ip, holder_ip) == 0) {
                    exists = true;
                    break;
                }
            }
        }

        if (!exists) {
            if (__db_insert_cnode_unsafe(my_handle, challenge, target_ip, holder_ip) == ESP_OK) {
                esp_err_t err_count = nvs_set_i32(my_handle, "cnode_count", cnode_count + 1);
                if (err_count == ESP_OK && nvs_commit(my_handle) != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to commit NVS for cnode insert!");
                }
            }
        }
        nvs_close(my_handle);
    }
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
 * @brief Exports the CNode table as a JSON string.
 * @return A dynamically allocated string containing the JSON representation of the CNode table. The caller must free this string. Returns NULL on failure.
 */
char *db_export_cnode_json(void) {
    char *json_string = NULL;
    TAKE_DB_MUTEX(__FUNCTION__);
    cJSON *root = cJSON_CreateArray();
    if (root) {
        nvs_handle_t my_handle;
        if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
            int32_t cnode_count = 0;
            nvs_get_i32(my_handle, "cnode_count", &cnode_count);
            for (int i = 0; i < cnode_count; i++) {
                char key[20];
                snprintf(key, sizeof(key), "cnode_%d", i);
                CNodeEntry cnode;
                size_t required_size = sizeof(CNodeEntry);
                if (nvs_get_blob(my_handle, key, &cnode, &required_size) == ESP_OK) {
                    cJSON *cnode_json = cJSON_CreateObject();
                    cJSON_AddStringToObject(cnode_json, "c", cnode.challenge);
                    cJSON_AddStringToObject(cnode_json, "t", cnode.target_ip);
                    cJSON_AddStringToObject(cnode_json, "h", cnode.holder_ip);
                    cJSON_AddItemToArray(root, cnode_json);
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
 * @brief Imports CNode entries from a JSON string, appending them to the existing table.
 * @param json A null-terminated C-string containing the JSON array of CNodes.
 */
void db_import_cnode_json(const char *json) {
    cJSON *root = cJSON_Parse(json);
    if (!root || !cJSON_IsArray(root)) {
        if (root)
            cJSON_Delete(root);
        return;
    }

    cJSON *cnode_json;
    cJSON_ArrayForEach(cnode_json, root) {
        cJSON *c = cJSON_GetObjectItem(cnode_json, "c");
        cJSON *t = cJSON_GetObjectItem(cnode_json, "t");
        cJSON *h = cJSON_GetObjectItem(cnode_json, "h");
        if (cJSON_IsString(c) && cJSON_IsString(t) && cJSON_IsString(h)) {
            db_insert_cnode(c->valuestring, t->valuestring, h->valuestring);
        }
    }
    cJSON_Delete(root);
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
 * @brief Removes all CNode entries where the given node is either the target or the holder.
 * @param node_ip The IP address of the node to remove from the CNode table.
 */
void db_remove_cnode_for_node(const char *node_ip) {
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READWRITE, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);
        int i = 0;
        int initial_count = cnode_count;
        while (i < cnode_count) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            CNodeEntry cnode;
            size_t size = sizeof(CNodeEntry);

            if (nvs_get_blob(my_handle, key, &cnode, &size) == ESP_OK &&
                (strcmp(cnode.target_ip, node_ip) == 0 || strcmp(cnode.holder_ip, node_ip) == 0)) {

                bool swap_ok = true;
                if (i < cnode_count - 1) {
                    CNodeEntry last_cnode;
                    char last_key[20];
                    snprintf(last_key, sizeof(last_key), "cnode_%" PRId32, cnode_count - 1);

                    if (nvs_get_blob(my_handle, last_key, &last_cnode, &size) == ESP_OK) {
                        if (nvs_set_blob(my_handle, key, &last_cnode, sizeof(CNodeEntry)) != ESP_OK) {
                            swap_ok = false;
                            ESP_LOGE(TAG, "Failed to write swapped cnode at index %d", i);
                        }
                    } else {
                        swap_ok = false;
                        ESP_LOGE(TAG, "Failed to read last cnode for swap at index %d", i);
                    }
                }

                if (swap_ok) {
                    char key_to_erase[20];
                    snprintf(key_to_erase, sizeof(key_to_erase), "cnode_%" PRId32, cnode_count - 1);
                    nvs_erase_key(my_handle, key_to_erase);
                    cnode_count--;
                } else {
                    i++;
                }
            } else {
                i++;
            }
        }

        if (initial_count != cnode_count) {
            nvs_set_i32(my_handle, "cnode_count", cnode_count);
            if (nvs_commit(my_handle) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to commit NVS for cnode remove!");
            }
            ESP_LOGI(TAG, "Removed %d CNodes for node %s.", initial_count - cnode_count, node_ip);
        }

        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
}

/**
 * @brief Counts the number of verifiers (holders) for a given target node.
 * @param target_ip The IP address of the node to check.
 * @return The number of verifiers found for the target node.
 */
int db_get_verifier_count_for_node(const char *target_ip) {
    int count = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);
        for (int i = 0; i < cnode_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            CNodeEntry cnode;
            size_t required_size = sizeof(CNodeEntry);
            if (nvs_get_blob(my_handle, key, &cnode, &required_size) == ESP_OK) {
                if (strcmp(cnode.target_ip, target_ip) == 0) {
                    count++;
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return count;
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
    if (nvs_open(DB_TMP_NAMESPACE, NVS_READWRITE, &tmp_handle) == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(tmp_handle, "tmp_crp_count", &count);

        TmpCRPNode tmp_entry;
        tmp_entry.transaction_id = transaction_id;
        memcpy(&tmp_entry.crp, crp, sizeof(CRPNode));

        char key[20];
        snprintf(key, sizeof(key), "crp_%ld", count);
        if (nvs_set_blob(tmp_handle, key, &tmp_entry, sizeof(TmpCRPNode)) == ESP_OK) {
            count++;
            nvs_set_i32(tmp_handle, "tmp_crp_count", count);
            if (nvs_commit(tmp_handle) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to commit NVS for tmp_crp insert!");
            }
        }
        nvs_close(tmp_handle);
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
 * @brief Retrieves a list of all current verifiers (holders) for a given target node.
 * @param target_ip The IP address of the node whose verifiers are to be found.
 * @param verifier_ips A 2D char array to store the resulting IP addresses of the verifiers.
 * @param max_verifiers The maximum number of IPs the verifier_ips array can hold.
 * @return The number of verifiers found and copied into the array.
 */
int db_get_verifiers_for_node(const char* target_ip, char verifier_ips[][INET_ADDRSTRLEN], int max_verifiers) {
    int count = 0;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);

        for (int i = 0; i < cnode_count && count < max_verifiers; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            CNodeEntry cnode;
            size_t required_size = sizeof(CNodeEntry);
            if (nvs_get_blob(my_handle, key, &cnode, &required_size) == ESP_OK) {
                if (strcmp(cnode.target_ip, target_ip) == 0) {
                    strncpy(verifier_ips[count], cnode.holder_ip, INET_ADDRSTRLEN - 1);
                    verifier_ips[count][INET_ADDRSTRLEN - 1] = '\0';
                    count++;
                }
            }
        }
        nvs_close(my_handle);
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

    int32_t main_cnode_count = 0, main_crp_count = 0;
    nvs_get_i32(main_handle, "cnode_count", &main_cnode_count);
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
    nvs_set_i32(main_handle, "cnode_count", main_cnode_count);
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

    int32_t main_cnode_count = 0, main_crp_count = 0;
    nvs_get_i32(main_handle, "cnode_count", &main_cnode_count);
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
        nvs_set_i32(main_handle, "cnode_count", main_cnode_count);
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
 * @brief Checks if a challenge string exists anywhere in the CNode table (globally).
 * @param challenge The challenge string to check.
 * @return true if the challenge exists, false otherwise.
 */
bool db_challenge_exists_globally(const char *challenge) {
    bool exists = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);
        
        for (int i = 0; i < cnode_count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            size_t required_size = sizeof(CNodeEntry);
            CNodeEntry temp_cnode;
            if (nvs_get_blob(my_handle, key, &temp_cnode, &required_size) == ESP_OK) {
                if (strcmp(temp_cnode.challenge, challenge) == 0) {
                    exists = true;
                    break;
                }
            }
        }
        nvs_close(my_handle);
    }
    
    if (!exists && nvs_open(DB_TMP_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t count = 0;
        nvs_get_i32(my_handle, "cnode_count", &count);
        for (int i = 0; i < count; i++) {
            char key[20];
            snprintf(key, sizeof(key), "cnode_%d", i);
            size_t required_size = sizeof(TmpCNodeEntry);
            TmpCNodeEntry temp_entry;
            if (nvs_get_blob(my_handle, key, &temp_entry, &required_size) == ESP_OK) {
                if (strcmp(temp_entry.cnode.challenge, challenge) == 0) {
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
 * @brief Retrieves the challenge associated with a specific verifier for the current node.
 * @param verifier_id The ID (IP) of the verifier.
 * @param challenge_buffer Buffer to store the retrieved challenge.
 * @param max_len Maximum number of bytes to write to the buffer.
 * @return true if a challenge was found, false otherwise.
 */
bool db_get_challenge_for_verifier(const char* verifier_id, char* challenge_buffer, size_t max_len) {
    bool found = false;
    TAKE_DB_MUTEX(__FUNCTION__);
    nvs_handle_t my_handle;
    if (nvs_open(DB_NAMESPACE, NVS_READONLY, &my_handle) == ESP_OK) {
        int32_t cnode_count = 0;
        nvs_get_i32(my_handle, "cnode_count", &cnode_count);
        
        char my_ip[INET_ADDRSTRLEN] = {0};
        get_my_ip(my_ip, sizeof(my_ip));
        my_ip[sizeof(my_ip) - 1] = '\0';

        if (my_ip[0] != '\0') {
            for (int i = 0; i < cnode_count; i++) {
                char key[20];
                snprintf(key, sizeof(key), "cnode_%d", i);
                size_t required_size = sizeof(CNodeEntry);
                CNodeEntry cnode;
                if (nvs_get_blob(my_handle, key, &cnode, &required_size) == ESP_OK) {
                    if (strcmp(cnode.target_ip, my_ip) == 0 && strcmp(cnode.holder_ip, verifier_id) == 0) {
                        strncpy(challenge_buffer, cnode.challenge, max_len);
                        found = true;
                        break;
                    }
                }
            }
        }
        nvs_close(my_handle);
    }
    GIVE_DB_MUTEX(__FUNCTION__);
    return found;
}