/* =============================
 * File: rest_api.c
 * Description: Runs two independent web servers: 
 * a standard HTTP server for general APIs and a dedicated HTTPS server for TLS tests.
 * All original functionalities have been preserved and integrated.
 * ============================= */

#include "rest_api.h"
#include "stats_sampler.h"
#include "raft_state.h"
#include "hatt_protocol.h"
#include "cJSON.h"
#include "esp_log.h"
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_heap_caps.h"

#include "raft.h"
#include "auth_join.h"
#include "auth_puf.h"
#include "auth_remove.h"
#include "auth_db.h"
#include "nonce_manager.h"
#include "integrity_verification.h"
#include "tls_auth.h"
#include "mqtts_auth.h"
#include "utility.h" 
#include "connection_pool.h"
#include "device_integrity_verification/hatt_protocol.h"
#include "discovery.h"


static const char *TAG = "REST_API";

typedef struct {
    char mode[16];
    int cluster_size;
} startup_params_t;


extern EventGroupHandle_t auth_event_group;
static bool app_logic_started = false;

static httpd_handle_t http_server = NULL;
static httpd_handle_t https_server = NULL;

/**
 * @brief Top-level callback to handle the discovery of a new peer.
 * @details This function serves as the central callback passed to the discovery
 * service. When a new peer is discovered, this function orchestrates the
 * necessary updates across different modules.
 * @param peer_ip The null-terminated IP address string of the newly discovered peer.
 */
static void on_new_peer_discovered(const char* peer_ip) {
    if (db_node_exists(peer_ip)) {
        ESP_LOGI(TAG, "Re-discovered known peer %s. Ensuring connection is active.", peer_ip);
        connection_pool_add_peer(peer_ip);
    } else {
        ESP_LOGI(TAG, "Discovered unknown peer %s. Ignoring. It must join formally via the API.", peer_ip);
    }
}

/**
 * @brief A background task that periodically sends a discovery broadcast message.
 * @details This task runs in a continuous loop, calling discovery_send_broadcast() at fixed intervals
 * to announce the node's presence on the network for peer discovery.
 * @param pvParameters Unused task parameters.
 */
static void periodic_discovery_task(void *pvParameters) {
    while(1) {
        discovery_send_broadcast();
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

/**
 * @brief Task that orchestrates the startup of all distributed services.
 * @details This task initializes the core services and then starts the peer discovery,
 * which dynamically populates the connection pool as new peers are found.
 * @param pvParameters
 */
static void distributed_startup_task(void *pvParameters) {
    startup_params_t *params = (startup_params_t*)pvParameters;
    char *mode = params->mode;
    int cluster_size = params->cluster_size;

    ESP_LOGI(TAG, "Starting hybrid startup...");
    ESP_LOGI(TAG, "Running timed discovery phase (10 seconds)...");
    discovery_service_start(NULL);
    xTaskCreate(periodic_discovery_task, "discovery_bcast", 3072, NULL, 5, NULL);
    vTaskDelay(pdMS_TO_TICKS(10000));

    int peer_count = 0;
    char** peer_list = discovery_get_peer_list_copy(&peer_count);

    ESP_LOGI(TAG, "Discovery finished. Found %d peers. Initializing services.", peer_count);
    db_init();
    nonce_manager_init();
    auth_join_init();
    auth_remove_init();
    auth_puf_init();

    if (strcmp(mode, "bootstrap") == 0) {
        auth_join_set_healing_mode(true, cluster_size);
    }

    if (strcmp(mode, "normal") == 0 || strcmp(mode, "bootstrap") == 0) {
        ESP_LOGI(TAG, "Normal mode: starting full Raft protocol.");
        if (peer_list && peer_count > 0) {
            raft_state_init();
            char my_ip[INET_ADDRSTRLEN];
            get_my_ip(my_ip, sizeof(my_ip));
            db_insert_node(my_ip, my_ip);
            
            connection_pool_start(peer_list, peer_count, raft_message_handler);
            raft_init_with_peers(peer_list, peer_count);
        } else {
            ESP_LOGW(TAG, "Normal mode: No peers found. Starting as a single-node cluster.");
            char my_ip[INET_ADDRSTRLEN];
            get_my_ip(my_ip, sizeof(my_ip));
            char* self_list[] = { my_ip };
            
            raft_state_init();
            db_insert_node(my_ip, my_ip);
            connection_pool_start(self_list, 1, raft_message_handler);
            raft_init_with_peers(self_list, 1);
        }
    } else {
        ESP_LOGI(TAG, "Join mode: starting base services only. Waiting for join command.");
        if (peer_list && peer_count > 0) {
            connection_pool_start(peer_list, peer_count, raft_message_handler);
        }
    }

    if (peer_list) {
        for (int i = 0; i < peer_count; i++) {
            if(peer_list[i]) free(peer_list[i]);
        }
        free(peer_list);
    }
    
    free(params);
    
    ESP_LOGI(TAG, "Initial services startup complete.");
    ESP_LOGI(TAG, "Switching to dynamic discovery mode.");
    discovery_register_new_peer_callback(on_new_peer_discovered);
    
    ESP_LOGI(TAG, "System is now fully live");
    vTaskDelete(NULL);
}

/**
 * @brief HTTP GET handler for the /raft/state endpoint.
 * @details Retrieves the current state of the RAFT node in a thread-safe manner using the
 * raft_state module and returns it as a JSON object.
 * @param req The HTTP request object provided by the server.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t get_raft_state_handler(httpd_req_t *req) {
    cJSON *resp_root = cJSON_CreateObject();
    if (!resp_root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON object creation failed");
        return ESP_FAIL;
    }

    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), my_mac, sizeof(my_mac));
    if (strcmp(my_ip, "0.0.0.0") == 0) {
        cJSON_Delete(resp_root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Raft node not fully initialized");
        return ESP_FAIL;
    }

    const char *state_str;
    switch (raft_state_get_state()) {
        case LEADER:    state_str = "leader";    break;
        case FOLLOWER:  state_str = "follower";  break;
        case CANDIDATE: state_str = "candidate"; break;
        default:        state_str = "unknown";   break;
    }
    
    char voted_for[INET_ADDRSTRLEN];
    raft_state_get_voted_for(voted_for, sizeof(voted_for));

    char leader_ip[INET_ADDRSTRLEN];
    char leader_mac[MAC_ADDR_STR_LEN];
    raft_state_get_leader_info(leader_ip, sizeof(leader_ip), leader_mac, sizeof(leader_mac));
    
    uint32_t last_log_idx, last_log_term;
    raft_state_get_log_info(&last_log_idx, &last_log_term);

    int peer_count = 0;
    char** peers = raft_state_get_peers_copy(&peer_count);

    cJSON_AddStringToObject(resp_root, "state", state_str);
    cJSON_AddNumberToObject(resp_root, "current_term", raft_state_get_current_term());
    cJSON_AddStringToObject(resp_root, "esp_ip", my_ip);
    cJSON_AddStringToObject(resp_root, "esp_mac", my_mac);
    cJSON_AddStringToObject(resp_root, "leader_ip", leader_ip);
    cJSON_AddStringToObject(resp_root, "voted_for", voted_for);
    cJSON_AddNumberToObject(resp_root, "vote_count", raft_state_get_vote_count());
    cJSON_AddNumberToObject(resp_root, "last_log_index", last_log_idx);
    cJSON_AddNumberToObject(resp_root, "last_log_term", last_log_term);
    
    if (peers) {
        cJSON *peers_array = cJSON_CreateStringArray((const char * const*)peers, peer_count);
        cJSON_AddItemToObject(resp_root, "peer_ips", peers_array);
        cJSON_AddNumberToObject(resp_root, "peer_count", peer_count);
        for(int i=0; i<peer_count; i++) free(peers[i]);
        free(peers);
    } else {
        cJSON_AddItemToObject(resp_root, "peer_ips", cJSON_CreateArray());
        cJSON_AddNumberToObject(resp_root, "peer_count", 0);
    }
    
    char *json_resp_str = cJSON_PrintUnformatted(resp_root);
    cJSON_Delete(resp_root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_resp_str);
    free(json_resp_str);

    return ESP_OK;
}

/**
 * @brief HTTP GET handler for the /system/stats endpoint.
 * @details This handler retrieves pre-calculated aggregate statistics (average and AUC)
 * from the stats_sampler module. It reads all data collected since the last
 * call and then clears the sampler's buffer.
 *
 * @param req The HTTP request object.
 * @return 
 * - ESP_OK on success.
 * - ESP_FAIL on internal errors (e.g., JSON creation failed).
 */
static esp_err_t get_system_stats_handler(httpd_req_t *req) {
    aggregate_stats_t stats;
    if (stats_sampler_end_phase_and_get_aggregates(&stats) != ESP_OK) {
        httpd_resp_set_status(req, "204 No Content");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to create JSON object");
        return ESP_FAIL;
    }

    cJSON_AddNumberToObject(root, "samples_processed", stats.sample_count);

    // CPU Stats
    cJSON *cpu_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(cpu_obj, "average_percent", stats.avg_cpu);
    cJSON_AddNumberToObject(cpu_obj, "auc_percent_seconds", stats.auc_cpu);
    cJSON_AddItemToObject(root, "cpu", cpu_obj);

    // Memory Stats
    cJSON *memory_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(memory_obj, "average_percent", stats.avg_memory);
    cJSON_AddNumberToObject(memory_obj, "auc_percent_seconds", stats.auc_memory);
    cJSON_AddItemToObject(root, "memory", memory_obj);

    // Power Stats
    cJSON *power_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(power_obj, "average_mw", stats.avg_power);
    cJSON_AddNumberToObject(power_obj, "auc_mw_seconds", stats.auc_power);
    cJSON_AddItemToObject(root, "power", power_obj);

    char *json_str = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_str);

    free(json_str);
    cJSON_Delete(root);
    return ESP_OK;
}

/**
 * @brief HTTP POST handler to start a new statistics measurement phase.
 */
static esp_err_t start_stats_phase_handler(httpd_req_t *req) {
    if (stats_sampler_start_phase() == ESP_OK) {
        httpd_resp_sendstr(req, "{\"status\": \"ok\", \"message\": \"New stats phase started\"}");
    } else {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Checkpoint stack overflow");
    }
    return ESP_OK;
}

/**
 * @brief Handler to start the main application logic (RAFT, HATT, etc.).
 * @param req The HTTP request object.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t start_handler(httpd_req_t *req) {
    if (app_logic_started) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Application already started");
        return ESP_FAIL;
    }

    char buf[128] = {0};
    httpd_req_recv(req, buf, sizeof(buf) - 1);

    startup_params_t *params = malloc(sizeof(startup_params_t));
    if (!params) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to allocate memory for startup params");
        return ESP_FAIL;
    }
    strncpy(params->mode, "normal", sizeof(params->mode) - 1);
    params->cluster_size = 0;

    cJSON *root = cJSON_Parse(buf);
    if (root) {
        cJSON *mode_item = cJSON_GetObjectItem(root, "mode");
        if (cJSON_IsString(mode_item)) {
            if (strcmp(mode_item->valuestring, "join") == 0) {
                strncpy(params->mode, "join", sizeof(params->mode) - 1);
            } else if (strcmp(mode_item->valuestring, "bootstrap") == 0) {
                strncpy(params->mode, "bootstrap", sizeof(params->mode) - 1);
                cJSON *size_item = cJSON_GetObjectItem(root, "cluster_size");
                if (cJSON_IsNumber(size_item)) {
                    params->cluster_size = size_item->valueint;
                }
            }
        }
        cJSON_Delete(root);
    }

    app_logic_started = true;
    ESP_LOGI(TAG, "/start endpoint called in '%s' mode (cluster size: %d). Starting background services...", params->mode, params->cluster_size);
    
    xTaskCreate(distributed_startup_task, "dist_startup", 4096, (void*)params, 5, NULL);
    hatt_prover_start_task();
    mqtts_auth_start_responder();

    const char* resp_str = "{\"status\": \"ok\", \"message\": \"Dynamic services startup initiated\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

/**
 * @brief HTTP POST handler for the /cluster/heal endpoint.
 * @details This function is callable only on the cluster leader. When invoked,
 * it triggers the `leader_start_network_heal` function, which asynchronously scans
 * the network for under-protected nodes and assigns new verifiers as needed.
 * It immediately returns a confirmation response, as the healing process runs
 * in the background.
 * @param req The HTTP request object provided by the server.
 * @return ESP_OK on success, or ESP_FAIL if the node is not the leader.
 */
static esp_err_t cluster_heal_handler(httpd_req_t *req) {
    char my_ip[INET_ADDRSTRLEN];
    char leader_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    bool has_leader = raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0);

    if (!has_leader || strcmp(my_ip, leader_ip) != 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "This node is not the leader.");
        return ESP_FAIL;
    }

    leader_start_network_heal();
    ESP_LOGI(TAG, "API /cluster/heal: Asynchronous healing process initiated.");

    const char* resp_str = "{\"status\": \"ok\", \"message\": \"Network healing process initiated\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp_str, strlen(resp_str));

    return ESP_OK;
}

/**
 * @brief Handler for a new node to be commanded to join a cluster.
 * @param req The HTTP request object.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t join_request_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) { return ESP_FAIL; }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); return ESP_FAIL; }

    const cJSON *master_ip_json = cJSON_GetObjectItem(root, "master_ip");
    if (!cJSON_IsString(master_ip_json) || !master_ip_json->valuestring) { 
        cJSON_Delete(root); 
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing 'master_ip'"); 
        return ESP_FAIL; 
    }

    char my_node_id_buf[INET_ADDRSTRLEN];
    get_my_node_id(my_node_id_buf, sizeof(my_node_id_buf));
    xSemaphoreTake(join_result_semaphore, 0);

    node_to_add_send_join_request(my_node_id_buf, master_ip_json->valuestring);
    cJSON_Delete(root);

    ESP_LOGI(TAG, "Join request sent. Waiting for final result...");
    if (xSemaphoreTake(join_result_semaphore, pdMS_TO_TICKS(60000)) == pdTRUE) {
        if (join_result_success) {
            const char* resp_str = "{\"status\": \"ok\", \"message\": \"Join successful\"}";
            httpd_resp_send(req, resp_str, strlen(resp_str));
        } else {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Join failed by leader's decision");
        }
    } else {
        httpd_resp_send_err(req, HTTPD_408_REQ_TIMEOUT, "Join process timed out");
    }
    return ESP_OK;
}

/**
 * @brief Handler for a node to request its own authentication from a known verifier.
 * @param req The HTTP request object.
 * @return ESP_OK on success.
 */
static esp_err_t request_authentication_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Received /request_authentication. Initiating process.");
    xSemaphoreTake(auth_result_sem, 0);

    initiate_authentication_as_prover();
    if (xSemaphoreTake(auth_result_sem, pdMS_TO_TICKS(30000)) == pdTRUE) {
        if (auth_result_success) {
            const char* resp_str = "{\"status\": \"ok\", \"authentication_passed\": true}";
            httpd_resp_send(req, resp_str, strlen(resp_str));
        } else {
            httpd_resp_set_status(req, "401 Unauthorized");
            const char* resp_str = "{\"status\": \"fail\", \"authentication_passed\": false}";
            httpd_resp_send(req, resp_str, strlen(resp_str));
        }
    } else {
        httpd_resp_send_err(req, HTTPD_408_REQ_TIMEOUT, "Authentication process timed out");
    }

    return ESP_OK;
}

/**
 * @brief HTTP POST handler for /request_auth_from_verifier (SERVER-INITIATED)
 * @details This endpoint is called by the monitoring server to command this node
 * (as a Prover) to authenticate itself against a *specific* Verifier.
 * @param req The HTTP request object.
 * @return ESP_OK on success.
 */
static esp_err_t request_auth_from_verifier_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    const cJSON *verifier_ip_json = cJSON_GetObjectItem(root, "verifier_ip");
    if (!cJSON_IsString(verifier_ip_json) || !verifier_ip_json->valuestring) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing 'verifier_ip'");
        return ESP_FAIL;
    }

    char verifier_ip[INET_ADDRSTRLEN];
    strncpy(verifier_ip, verifier_ip_json->valuestring, sizeof(verifier_ip) - 1);
    verifier_ip[sizeof(verifier_ip) - 1] = '\0';
    cJSON_Delete(root);

    ESP_LOGI(TAG, "Received /request_auth_from_verifier. Initiating process against: %s", verifier_ip);
    xSemaphoreTake(auth_result_sem, 0);

    initiate_authentication_as_prover_specific(verifier_ip);

    if (xSemaphoreTake(auth_result_sem, pdMS_TO_TICKS(10000)) == pdTRUE) {
        if (auth_result_success) {
            const char* resp_str = "{\"status\": \"ok\", \"authentication_passed\": true}";
            httpd_resp_send(req, resp_str, strlen(resp_str));
        } else {
            httpd_resp_set_status(req, "401 Unauthorized");
            const char* resp_str = "{\"status\": \"fail\", \"authentication_passed\": false}";
            httpd_resp_send(req, resp_str, strlen(resp_str));
        }
    } else {
        httpd_resp_send_err(req, HTTPD_408_REQ_TIMEOUT, "Authentication process timed out");
    }

    return ESP_OK;
}

/**
 * @brief Handler to trigger a TLS-based authentication check.
 * @param req The HTTP request object.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t tls_authentication_handler(httpd_req_t *req) {
    char buf[256];
    char target_ip[INET_ADDRSTRLEN] = {0};
    
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        cJSON *root = cJSON_Parse(buf);
        if (root) {
            const cJSON *target_ip_json = cJSON_GetObjectItem(root, "target_ip");
            if (cJSON_IsString(target_ip_json) && target_ip_json->valuestring) {
                strncpy(target_ip, target_ip_json->valuestring, INET_ADDRSTRLEN - 1);
            }
            cJSON_Delete(root);
        }
    }
    
    if (strlen(target_ip) == 0) {
        if (!db_get_random_follower_ip(target_ip, sizeof(target_ip))) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No peers available for TLS auth");
            return ESP_FAIL;
        }
    }
    
    ESP_LOGI(TAG, "TLS authentication requested against %s", target_ip);
    bool auth_passed = run_tls_authentication(target_ip);

    cJSON *resp_root = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp_root, "authentication_passed", auth_passed);
    char* json_resp_str = cJSON_PrintUnformatted(resp_root);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_resp_str);
    cJSON_Delete(resp_root);
    free(json_resp_str);
    return ESP_OK;
}

/**
 * @brief Handler for the master node to initiate the removal of another node.
 * @param req The HTTP request object.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t remove_node_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body");
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    const cJSON *target_ip_json = cJSON_GetObjectItem(root, "target_ip");
    if (!cJSON_IsString(target_ip_json) || !target_ip_json->valuestring) { 
        cJSON_Delete(root); 
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing 'target_ip'"); 
        return ESP_FAIL; 
    }

    char ip_to_remove[INET_ADDRSTRLEN];
    strncpy(ip_to_remove, target_ip_json->valuestring, INET_ADDRSTRLEN -1);
    ip_to_remove[INET_ADDRSTRLEN - 1] = '\0';
    cJSON_Delete(root);
    
    char my_ip[INET_ADDRSTRLEN];
    char leader_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    bool is_leader = raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0) && (strcmp(my_ip, leader_ip) == 0);

    if (!is_leader) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "This node is not the leader.");
        return ESP_OK;
    }
    
    xSemaphoreTake(remove_result_semaphore, 0);
    if (xQueueSend(remove_request_queue, ip_to_remove, pdMS_TO_TICKS(100)) != pdPASS) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_send(req, "Removal request queue is full.", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    
    if (xSemaphoreTake(remove_result_semaphore, pdMS_TO_TICKS(90000)) == pdTRUE) {
        if (remove_result_success) {
            const char* resp_str = "{\"status\": \"ok\", \"message\": \"Node removal and healing completed successfully\"}";
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, resp_str, strlen(resp_str));
        } else {
            httpd_resp_set_status(req, "500 Internal Server Error");
            const char* resp_str = "{\"status\": \"fail\", \"message\": \"Node removal process failed\"}";
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, resp_str, strlen(resp_str));
        }
    } else {
        httpd_resp_send_err(req, HTTPD_408_REQ_TIMEOUT, "Removal process timed out");
    }

    return ESP_OK;
}

/**
 * @brief Handler to reboot the ESP32 node.
 * @param req The HTTP request object.
 * @return ESP_OK.
 */
static esp_err_t reboot_handler(httpd_req_t *req) {
    ESP_LOGW(TAG, "Received /reboot request. Rebooting now...");
    const char* resp_str = "{\"status\": \"ok\", \"message\": \"Rebooting...\"}";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
    return ESP_OK;
}

/**
 * @brief Handler to trigger an MQTTS-based authentication check.
 * @param req The HTTP request object.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t mqtts_authentication_handler(httpd_req_t *req) {
    char buf[256];
    char target_ip[INET_ADDRSTRLEN] = {0};
    
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        cJSON *root = cJSON_Parse(buf);
        if (root) {
            const cJSON *target_ip_json = cJSON_GetObjectItem(root, "target_ip");
            if (cJSON_IsString(target_ip_json) && target_ip_json->valuestring) {
                strncpy(target_ip, target_ip_json->valuestring, INET_ADDRSTRLEN - 1);
            }
            cJSON_Delete(root);
        }
    }
    
    if (strlen(target_ip) == 0) {
        if (!db_get_random_follower_ip(target_ip, sizeof(target_ip))) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No peers available for MQTTS auth");
            return ESP_FAIL;
        }
    }

    ESP_LOGI(TAG, "MQTTS authentication requested against %s", target_ip);

    char broker_uri[64];
    snprintf(broker_uri, sizeof(broker_uri), "mqtts://%s:%d", MQTT_BROKER_IP, MQTT_BROKER_PORT);

    bool auth_passed = run_mqtts_authentication(broker_uri, target_ip);

    cJSON *resp_root = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp_root, "authentication_passed", auth_passed);
    char* json_resp_str = cJSON_PrintUnformatted(resp_root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json_resp_str);
    
    cJSON_Delete(resp_root);
    free(json_resp_str);

    return ESP_OK;
}

static esp_err_t tamper_secret_handler(httpd_req_t *req) {
    hatt_test_tamper_secret();
    const char* resp_str = "{\"status\": \"ok\", \"message\": \"HAtt secret has been randomized\"}";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

// --- URI Definitions ---
static const httpd_uri_t raft_state_uri = { .uri = "/raft/state", .method = HTTP_GET, .handler = get_raft_state_handler };
static const httpd_uri_t system_stats_uri = { .uri = "/system/stats", .method = HTTP_GET, .handler = get_system_stats_handler };
static const httpd_uri_t start_uri = { .uri = "/start", .method = HTTP_POST, .handler = start_handler };
static const httpd_uri_t join_uri = { .uri = "/join", .method = HTTP_POST, .handler = join_request_handler };
static const httpd_uri_t request_auth_uri = { .uri = "/request_authentication", .method = HTTP_POST, .handler = request_authentication_handler };
static const httpd_uri_t request_auth_from_verifier_uri = { .uri = "/request_auth_from_verifier", .method = HTTP_POST, .handler = request_auth_from_verifier_handler };
static const httpd_uri_t tls_auth_uri = { .uri = "/request_authentication_tls", .method = HTTP_POST, .handler = tls_authentication_handler };
static const httpd_uri_t remove_node_uri = { .uri = "/remove_node", .method = HTTP_POST, .handler = remove_node_handler };
static const httpd_uri_t reboot_uri = { .uri = "/reboot", .method = HTTP_POST, .handler = reboot_handler };
static const httpd_uri_t mqtts_auth_uri = { .uri = "/request_authentication_mqtts", .method = HTTP_POST, .handler = mqtts_authentication_handler };
static const httpd_uri_t cluster_heal_uri = { .uri = "/cluster/heal", .method = HTTP_POST, .handler = cluster_heal_handler };
static const httpd_uri_t start_stats_phase_uri = { .uri = "/system/stats/start_phase", .method = HTTP_POST, .handler = start_stats_phase_handler };
static const httpd_uri_t tamper_secret_uri = { .uri = "/test/tamper_secret", .method = HTTP_POST, .handler = tamper_secret_handler };

/**
 * @brief Registers all standard, non-secure API endpoints.
 * @param server The handle to the HTTP server instance.
 */
static void register_http_handlers(httpd_handle_t server) {
    ESP_LOGI(TAG, "Registering HTTP URI handlers");
    httpd_register_uri_handler(server, &raft_state_uri);
    httpd_register_uri_handler(server, &system_stats_uri);
    httpd_register_uri_handler(server, &start_uri);
    httpd_register_uri_handler(server, &join_uri);
    httpd_register_uri_handler(server, &request_auth_uri);
    httpd_register_uri_handler(server, &request_auth_from_verifier_uri);
    httpd_register_uri_handler(server, &remove_node_uri);
    httpd_register_uri_handler(server, &reboot_uri);
    httpd_register_uri_handler(server, &mqtts_auth_uri);
    httpd_register_uri_handler(server, &tls_auth_uri);
    httpd_register_uri_handler(server, &cluster_heal_uri);
    httpd_register_uri_handler(server, &start_stats_phase_uri);
    httpd_register_uri_handler(server, &tamper_secret_uri);
}

/**
 * @brief Registers the secure API endpoints.
 * @param server The handle to the HTTPS server instance.
 */
static void register_https_handlers(httpd_handle_t server) {
    ESP_LOGI(TAG, "Registering HTTPS URI handlers");
}

/**
 * @brief Starts both the HTTP and HTTPS REST API servers.
 * @details This function initializes the web servers and registers all the API endpoints
 * for interacting with the node.
 * @return void
 */
void rest_api_start(void) {
    stats_sampler_init();

    httpd_config_t http_config = HTTPD_DEFAULT_CONFIG();
    http_config.lru_purge_enable = true;
    http_config.server_port = 80;
    http_config.max_uri_handlers = 14;
    http_config.stack_size = 8192;
    ESP_LOGI(TAG, "Starting HTTP server on port %d", http_config.server_port);
    if (httpd_start(&http_server, &http_config) == ESP_OK) {
        register_http_handlers(http_server);
    } else {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }

    char cert_path[96];
    char key_path[96];
    char ca_path[96];
    snprintf(cert_path, sizeof(cert_path), "/certs/device.crt");
    snprintf(key_path, sizeof(key_path), "/certs/device.key");
    snprintf(ca_path, sizeof(ca_path), "/certs/ca.crt");

    size_t cert_len, key_len, ca_len;
    char* servercert_buf = read_embedded_file(cert_path, &cert_len);
    char* prvtkey_buf = read_embedded_file(key_path, &key_len);
    char* cacert_buf = read_embedded_file(ca_path, &ca_len);

    if (servercert_buf && prvtkey_buf && cacert_buf) {
        httpd_ssl_config_t https_config = HTTPD_SSL_CONFIG_DEFAULT();
        https_config.port_secure = 443;
        https_config.servercert = (const uint8_t*) servercert_buf;
        https_config.servercert_len = cert_len;
        https_config.prvtkey_pem = (const uint8_t*) prvtkey_buf;
        https_config.prvtkey_len = key_len;
        https_config.cacert_pem = (const uint8_t*) cacert_buf;
        https_config.cacert_len = ca_len;

        ESP_LOGI(TAG, "Starting HTTPS server on port %d", https_config.port_secure);
        if (httpd_ssl_start(&https_server, &https_config) == ESP_OK) {
            register_https_handlers(https_server);
        } else {
            ESP_LOGE(TAG, "Failed to start HTTPS server");
        }
    } else {
        ESP_LOGE(TAG, "Failed to load certificates for HTTPS server.");
    }

    if (servercert_buf) free(servercert_buf);
    if (prvtkey_buf) free(prvtkey_buf);
    if (cacert_buf) free(cacert_buf);
}

/**
 * @brief Stops both the HTTP and HTTPS servers.
 * @details This function cleanly shuts down the web servers and frees their resources.
 * @return void
 */
void rest_api_stop(void) {
    if (http_server) {
        ESP_LOGI(TAG, "Stopping HTTP server");
        httpd_stop(http_server);
        http_server = NULL;
    }
    if (https_server) {
        ESP_LOGI(TAG, "Stopping HTTPS server");
        httpd_ssl_stop(https_server);
        https_server = NULL;
    }
}