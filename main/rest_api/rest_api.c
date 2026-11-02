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
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"

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
#include "attestation_test_region.h"
#include "attacker.h"
#include "wifi.h"


static const char *TAG = "REST_API";

typedef struct {
    char mode[16];
    int cluster_size;
} startup_params_t;


extern EventGroupHandle_t auth_event_group;
static bool app_logic_started = false;
// Started in "baseline" mode: only the TLS and MQTTS baselines run, none of the services of SRAFT.
static bool baseline_mode = false;

static httpd_handle_t http_server = NULL;
static httpd_handle_t https_server = NULL;
static void https_server_start(void);
static void https_server_stop(void);

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
    // The SRAM PUF is read only when SRAFT starts, so that a device started for the baselines does not
    // read it nor keep its buffers.
    init_sram_puf();
    ESP_LOGI(TAG, "Running timed discovery phase (10 seconds)...");
    discovery_service_start(NULL);
    xTaskCreate(periodic_discovery_task, "discovery_bcast", 3072, NULL, 5, NULL);
    vTaskDelay(pdMS_TO_TICKS(10000));

    int peer_count = 0;
    char** peer_list = discovery_get_peer_list_copy(&peer_count);

    ESP_LOGI(TAG, "Discovery finished. Found %d peers. Initializing services.", peer_count);
    log_heap("after discovery");
    db_init();
    nonce_manager_init();
    log_heap("after db and nonces");
    auth_join_init();
    log_heap("after join module");
    auth_remove_init();
    log_heap("after remove module");
    auth_puf_init();
    log_heap("after auth module");
    integrity_verification_start_periodic();
    log_heap("after periodic check");

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
            log_heap("after connection pool");
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
 * @brief Rejects a request that needs the protocol services when /start has not been called yet.
 * @return true if the request was rejected.
 */
static bool reject_if_not_started(httpd_req_t *req) {
    if (is_raft_running()) return false;
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Node not started");
    return true;
}

/**
 * @brief Like reject_if_not_started(), but also accepts a device started in "baseline" mode, in which only
 * the TLS and MQTTS baselines run.
 */
static bool reject_if_no_baseline(httpd_req_t *req) {
    if (baseline_mode) return false;
    return reject_if_not_started(req);
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

    // The Raft state does not exist before /start.
    if (!is_raft_running()) {
        cJSON_Delete(resp_root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Raft node not started");
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

    // On the Coordinator: the members in the network state and the smallest number of Verifiers of a
    // member, against the target ceil(rho N), so that a test can tell when redundancy is restored.
    if (strcmp(state_str, "leader") == 0) {
        int followers = db_get_follower_count();
        char **follower_ips = NULL;
        int listed = db_get_all_follower_ips(&follower_ips, followers);
        int members = listed + 1;
        int target = (int)ceil(members * VERIFIER_PERCENTAGE);
        if (target == 0) target = 1;
        int min_verifiers = db_get_verifier_count_for_node(my_ip);
        cJSON *members_array = cJSON_CreateArray();
        cJSON_AddItemToArray(members_array, cJSON_CreateString(my_ip));
        for (int i = 0; i < listed; i++) {
            int count = db_get_verifier_count_for_node(follower_ips[i]);
            if (count < min_verifiers) min_verifiers = count;
            cJSON_AddItemToArray(members_array, cJSON_CreateString(follower_ips[i]));
            free(follower_ips[i]);
        }
        if (follower_ips) free(follower_ips);
        cJSON_AddItemToObject(resp_root, "members", members_array);
        cJSON_AddNumberToObject(resp_root, "min_verifiers", min_verifiers);
        cJSON_AddNumberToObject(resp_root, "target_verifiers", target);
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
            } else if (strcmp(mode_item->valuestring, "baseline") == 0) {
                strncpy(params->mode, "baseline", sizeof(params->mode) - 1);
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
    if (strcmp(params->mode, "baseline") == 0) {
        // Baselines only: none of the services of SRAFT is started (no PUF, discovery, database,
        // join, removal, periodic checks, Raft, connection pool, or HAtt prover), so that TLS and
        // MQTTS are measured on a device that runs nothing else.
        baseline_mode = true;
        free(params);
        ESP_LOGI(TAG, "/start endpoint called in 'baseline' mode: only the TLS and MQTTS baselines are enabled.");
        log_heap("baseline mode");
        const char* resp_str = "{\"status\": \"ok\", \"message\": \"Baseline mode\"}";
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, resp_str, strlen(resp_str));
        return ESP_OK;
    }
    ESP_LOGI(TAG, "/start endpoint called in '%s' mode (cluster size: %d). Starting background services...", params->mode, params->cluster_size);
    // Before the HAtt prover, which answers with the PUF of this device.
    init_sram_puf();
    
    log_heap("before start");
    xTaskCreate(distributed_startup_task, "dist_startup", 4096, (void*)params, 5, NULL);
    hatt_prover_start_task();
    log_heap("after HAtt prover");

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
    if (reject_if_not_started(req)) return ESP_OK;
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
/**
 * @brief State of the authentication requested through the REST interface (SRAFT, TLS, or MQTTS).
 * @details The authentication runs in its own task, so that the HTTP server of this device keeps answering
 * the monitoring server, which samples the devices while the authentication runs. The request returns at
 * once with a sequence number; the outcome is read with {"poll": true} on the same endpoint.
 */
typedef enum { ASYNC_AUTH_SRAFT, ASYNC_AUTH_TLS, ASYNC_AUTH_MQTTS } async_auth_scheme_t;
typedef struct {
    async_auth_scheme_t scheme;
    tls_auth_mode_t tls_mode;  // for TLS: full handshake, prime run, or resumption
    char target_ip[INET_ADDRSTRLEN];
    volatile bool running;
    volatile bool passed;
    volatile uint32_t seq;   // number of the last authentication started, 0 before the first one
} async_auth_t;
static async_auth_t async_auth = {0};

static void async_auth_task(void *arg) {
    async_auth_t *a = (async_auth_t *)arg;
    bool passed = false;
    if (a->scheme == ASYNC_AUTH_SRAFT) {
        xSemaphoreTake(auth_result_sem, 0);
        initiate_authentication_as_prover();
        passed = xSemaphoreTake(auth_result_sem, pdMS_TO_TICKS(30000)) == pdTRUE && auth_result_success;
    } else if (a->scheme == ASYNC_AUTH_TLS) {
        passed = run_tls_authentication(a->target_ip, a->tls_mode);
    } else {
        char broker_uri[64];
        snprintf(broker_uri, sizeof(broker_uri), "mqtts://%s:%d", MQTT_BROKER_IP, MQTT_BROKER_PORT);
        passed = run_mqtts_authentication(broker_uri, a->target_ip);
    }
    a->passed = passed;
    a->running = false;
    vTaskDelete(NULL);
}

/**
 * @brief Reads the request body of an authentication endpoint: target_ip, poll, and for TLS the mode
 * ("full", "prime", or "resumed"; full by default).
 */
static void read_auth_request(httpd_req_t *req, char *target_ip, size_t size, bool *poll, tls_auth_mode_t *tls_mode) {
    char buf[256] = {0};
    *poll = false;
    if (tls_mode) *tls_mode = TLS_AUTH_FULL;
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return;
    cJSON *root = cJSON_Parse(buf);
    if (!root) return;
    const cJSON *item = cJSON_GetObjectItem(root, "target_ip");
    if (cJSON_IsString(item) && item->valuestring) {
        strncpy(target_ip, item->valuestring, size - 1);
        target_ip[size - 1] = '\0';
    }
    *poll = cJSON_IsTrue(cJSON_GetObjectItem(root, "poll"));
    const cJSON *mode = cJSON_GetObjectItem(root, "mode");
    if (tls_mode && cJSON_IsString(mode) && mode->valuestring) {
        if (strcmp(mode->valuestring, "prime") == 0) *tls_mode = TLS_AUTH_PRIME;
        else if (strcmp(mode->valuestring, "resumed") == 0) *tls_mode = TLS_AUTH_RESUMED;
    }
    cJSON_Delete(root);
}

/**
 * @brief Starts an authentication of the given scheme, or returns the state of the last one if poll is set.
 * @details Answers {"status": "started"|"busy"|"running"|"done"|"none", "seq": n, "authentication_passed": b}.
 */
static esp_err_t async_auth_respond(httpd_req_t *req, async_auth_scheme_t scheme, const char *target_ip, bool poll,
                                    tls_auth_mode_t tls_mode) {
    async_auth_t *a = &async_auth;
    char resp[128];
    httpd_resp_set_type(req, "application/json");
    if (poll || a->running) {
        const char *status = a->running ? (poll ? "running" : "busy") : (a->seq ? "done" : "none");
        snprintf(resp, sizeof(resp), "{\"status\": \"%s\", \"seq\": %lu, \"authentication_passed\": %s}",
                 status, (unsigned long)a->seq, (!a->running && a->passed) ? "true" : "false");
        httpd_resp_sendstr(req, resp);
        return ESP_OK;
    }
    a->scheme = scheme;
    a->tls_mode = tls_mode;
    strncpy(a->target_ip, target_ip ? target_ip : "", sizeof(a->target_ip) - 1);
    a->target_ip[sizeof(a->target_ip) - 1] = '\0';
    a->passed = false;
    a->running = true;
    a->seq++;
    if (xTaskCreate(async_auth_task, "async_auth", 10240, a, 5, NULL) != pdPASS) {
        a->running = false;
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not start the authentication");
        return ESP_OK;
    }
    snprintf(resp, sizeof(resp), "{\"status\": \"started\", \"seq\": %lu}", (unsigned long)a->seq);
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}

static esp_err_t request_authentication_handler(httpd_req_t *req) {
    if (reject_if_not_started(req)) return ESP_OK;
    char target_ip[INET_ADDRSTRLEN] = {0};
    bool poll;
    read_auth_request(req, target_ip, sizeof(target_ip), &poll, NULL);
    if (!poll) ESP_LOGI(TAG, "Received /request_authentication. Initiating process.");
    return async_auth_respond(req, ASYNC_AUTH_SRAFT, NULL, poll, TLS_AUTH_FULL);
}

/**
 * @brief HTTP POST handler for /request_auth_from_verifier (SERVER-INITIATED)
 * @details This endpoint is called by the monitoring server to command this node
 * (as a Prover) to authenticate itself against a *specific* Verifier.
 * @param req The HTTP request object.
 * @return ESP_OK on success.
 */
static esp_err_t request_auth_from_verifier_handler(httpd_req_t *req) {
    if (reject_if_not_started(req)) return ESP_OK;
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
    if (reject_if_no_baseline(req)) return ESP_OK;
    char target_ip[INET_ADDRSTRLEN] = {0};
    bool poll;
    tls_auth_mode_t tls_mode;
    read_auth_request(req, target_ip, sizeof(target_ip), &poll, &tls_mode);
    if (!poll && strlen(target_ip) == 0) {
        // In baseline mode there is no network state to pick a peer from: the target must be given.
        if (baseline_mode || !db_get_random_follower_ip(target_ip, sizeof(target_ip))) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No target for TLS auth");
            return ESP_FAIL;
        }
    }
    if (!poll) ESP_LOGI(TAG, "TLS authentication requested against %s", target_ip);
    return async_auth_respond(req, ASYNC_AUTH_TLS, target_ip, poll, tls_mode);
}

/**
 * @brief Handler for the master node to initiate the removal of another node.
 * @param req The HTTP request object.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t remove_node_handler(httpd_req_t *req) {
    if (reject_if_not_started(req)) return ESP_OK;
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

    // The answer is sent as soon as the removal is queued: the removal task runs it, and the HTTP server of the
    // Coordinator stays free to answer the monitoring server, which samples the devices meanwhile. Its end is
    // observed in the state of the Coordinator (members and Verifiers of each member).
    const char* resp_str = "{\"status\": \"ok\", \"message\": \"Node removal started\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp_str, strlen(resp_str));
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
 * @brief Handler that makes this device leave the network (planned decommissioning).
 * @param req The HTTP request object.
 * @return ESP_OK on success.
 */
static esp_err_t leave_handler(httpd_req_t *req) {
    if (reject_if_not_started(req)) return ESP_OK;
    ESP_LOGW(TAG, "Received /leave request. Leaving the network...");
    const char* resp_str = "{\"status\": \"ok\", \"message\": \"Leaving the network...\"}";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    vTaskDelay(pdMS_TO_TICKS(100));
    auth_remove_leave_network();
    return ESP_OK;
}

/**
 * @brief Handler to trigger an MQTTS-based authentication check.
 * @param req The HTTP request object.
 * @return ESP_OK on success, or an ESP_FAIL error code on failure.
 */
static esp_err_t mqtts_authentication_handler(httpd_req_t *req) {
    if (reject_if_no_baseline(req)) return ESP_OK;
    char target_ip[INET_ADDRSTRLEN] = {0};
    bool poll;
    read_auth_request(req, target_ip, sizeof(target_ip), &poll, NULL);
    if (!poll && strlen(target_ip) == 0) {
        // In baseline mode there is no network state to pick a peer from: the target must be given.
        if (baseline_mode || !db_get_random_follower_ip(target_ip, sizeof(target_ip))) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No target for MQTTS auth");
            return ESP_FAIL;
        }
    }
    if (!poll) ESP_LOGI(TAG, "MQTTS authentication requested against %s", target_ip);
    return async_auth_respond(req, ASYNC_AUTH_MQTTS, target_ip, poll, TLS_AUTH_FULL);
}

/**
 * @brief Handler that starts or stops the MQTTS auth responder ({"enable": true|false}).
 * @details The responder keeps a TLS connection to the broker, so it runs only while the MQTTS
 * baseline is measured and does not take memory during the other scenarios.
 */
static esp_err_t mqtts_responder_handler(httpd_req_t *req) {
    char buf[64] = {0};
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    bool enable = true;
    if (len > 0) {
        cJSON *root = cJSON_Parse(buf);
        cJSON *item = root ? cJSON_GetObjectItem(root, "enable") : NULL;
        if (cJSON_IsBool(item)) enable = cJSON_IsTrue(item);
        cJSON_Delete(root);
    }
    // When enabled, the answer is sent only once the responder is subscribed to its request topic (or
    // after a timeout), so that the orchestrator does not send a request that would be lost.
    bool ready = false;
    if (enable) {
        ready = mqtts_auth_start_responder();
    } else {
        mqtts_auth_stop_responder();
    }
    log_heap(enable ? "after MQTTS responder start" : "after MQTTS responder stop");
    const char *resp_str = !enable ? "{\"status\": \"ok\", \"responder\": \"stopped\"}" :
                           ready ? "{\"status\": \"ok\", \"responder\": \"ready\"}" :
                                   "{\"status\": \"error\", \"responder\": \"not_ready\"}";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

/**
 * @brief Handler that starts or stops the HTTPS server of the TLS baseline ({"enable": true|false}).
 */
static esp_err_t https_server_handler(httpd_req_t *req) {
    char buf[64] = {0};
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    bool enable = true;
    if (len > 0) {
        cJSON *root = cJSON_Parse(buf);
        cJSON *item = root ? cJSON_GetObjectItem(root, "enable") : NULL;
        if (cJSON_IsBool(item)) enable = cJSON_IsTrue(item);
        cJSON_Delete(root);
    }
    if (enable) {
        https_server_start();
    } else {
        https_server_stop();
    }
    log_heap(enable ? "after HTTPS server start" : "after HTTPS server stop");
    const char *resp_str = enable ? "{\"status\": \"ok\", \"https\": \"started\"}" : "{\"status\": \"ok\", \"https\": \"stopped\"}";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

/**
 * @brief Handler that erases the list of excluded devices. For tests only.
 */
static esp_err_t clear_blacklist_handler(httpd_req_t *req) {
    raft_state_clear_blacklist();
    const char* resp_str = "{\"status\": \"ok\", \"message\": \"Blacklist cleared\"}";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

/**
 * @brief State of the attestation requested through /request_attestation, run by its own task so that
 * the HTTP server of this device stays free to answer the monitoring server while it runs.
 */
typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    char target_id[MAC_ADDR_STR_LEN];
    char operation_id[64];
    volatile bool running;
    volatile int outcome;  // hatt_result_t of the last attestation, -1 before the first one
} requested_attestation_t;

static requested_attestation_t requested_attestation = { .outcome = -1 };

static void requested_attestation_task(void *arg) {
    requested_attestation_t *a = (requested_attestation_t *)arg;
    char event_msg[160];
    snprintf(event_msg, sizeof(event_msg), "ATTEST_START|%s|%s", a->operation_id, a->target_id);
    send_monitoring_tcp_event(event_msg);

    hatt_result_t outcome = hatt_verifier_attest(a->target_ip, NULL);

    snprintf(event_msg, sizeof(event_msg), "ATTEST_RESULT_EVENT|%d|%s|%s", outcome == HATT_PASSED ? 1 : 0, a->operation_id, a->target_id);
    send_monitoring_tcp_event(event_msg);
    a->outcome = outcome;
    a->running = false;
    vTaskDelete(NULL);
}

/**
 * @brief HTTP POST handler for /request_attestation (cost of a successful attestation, RQ1).
 * @details With {"target_ip": ip} this device, if it is one of the Verifiers of ip, starts the attestation
 * of ip with HAtt bound to one of the CRPs it holds for it, as the periodic check does, and answers at once
 * with the identifier of the run. The attestation reports ATTEST_START and ATTEST_RESULT_EVENT to the
 * monitoring server, which samples CPU, memory, and power of every device between the two events. If this
 * device is not a Verifier of ip, it answers with the Verifiers of ip listed in its network state, so that
 * the orchestrator can send the request to one of them. With {} it returns the state of the last run.
 */
static esp_err_t request_attestation_handler(httpd_req_t *req) {
    if (reject_if_not_started(req)) return ESP_OK;
    char buf[128] = {0};
    char target_ip[INET_ADDRSTRLEN] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret > 0) {
        cJSON *root = cJSON_Parse(buf);
        const cJSON *item = root ? cJSON_GetObjectItem(root, "target_ip") : NULL;
        if (cJSON_IsString(item)) strncpy(target_ip, item->valuestring, sizeof(target_ip) - 1);
        cJSON_Delete(root);
    }
    httpd_resp_set_type(req, "application/json");
    requested_attestation_t *a = &requested_attestation;
    char resp[160];

    if (target_ip[0] == '\0' || a->running) {
        int outcome = a->outcome;
        const char *result_str = a->running ? "running" : outcome == HATT_PASSED ? "passed" :
                                 outcome == HATT_FAILED ? "failed" : outcome == HATT_NO_ANSWER ? "no_answer" : "none";
        snprintf(resp, sizeof(resp), "{\"status\": \"%s\", \"attestation\": \"%s\", \"operation_id\": \"%s\"}",
                 (target_ip[0] != '\0') ? "busy" : "ok", result_str, a->operation_id);
        httpd_resp_send(req, resp, strlen(resp));
        return ESP_OK;
    }

    if (!auth_puf_is_verifier_of(target_ip)) {
        char verifiers[MAX_DISTINCT_VERIFIERS][INET_ADDRSTRLEN];
        int count = db_get_verifiers_for_node(target_ip, verifiers, MAX_DISTINCT_VERIFIERS);
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "status", "not_verifier");
        cJSON *list = cJSON_AddArrayToObject(json, "verifiers");
        for (int i = 0; i < count; i++) cJSON_AddItemToArray(list, cJSON_CreateString(verifiers[i]));
        char *json_str = cJSON_PrintUnformatted(json);
        httpd_resp_send(req, json_str, strlen(json_str));
        free(json_str);
        cJSON_Delete(json);
        return ESP_OK;
    }

    char my_mac[MAC_ADDR_STR_LEN];
    get_my_mac(my_mac, sizeof(my_mac));
    strncpy(a->target_ip, target_ip, sizeof(a->target_ip) - 1);
    a->target_ip[sizeof(a->target_ip) - 1] = '\0';
    if (!discovery_get_mac_for_ip(target_ip, a->target_id, sizeof(a->target_id))) {
        strncpy(a->target_id, target_ip, sizeof(a->target_id) - 1);
        a->target_id[sizeof(a->target_id) - 1] = '\0';
    }
    snprintf(a->operation_id, sizeof(a->operation_id), "attest_%s_%lu", my_mac, (uint32_t)esp_timer_get_time());
    a->running = true;
    if (xTaskCreate(requested_attestation_task, "req_attest", 8192, a, 6, NULL) != pdPASS) {
        a->running = false;
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not start the attestation");
        return ESP_OK;
    }
    snprintf(resp, sizeof(resp), "{\"status\": \"started\", \"operation_id\": \"%s\"}", a->operation_id);
    httpd_resp_send(req, resp, strlen(resp));
    return ESP_OK;
}

/**
 * @brief Handler of the attestation tests, used to measure the detection rate of HAtt. For tests only.
 * @details With {"prover": true} the device starts its HAtt Prover. With {"target_ip": ip, "runs": n} it
 * attests the device ip n times in a row, one attestation at a time, and returns how many proofs were
 * accepted, rejected, or not received. Both forms return the digest of the attested image of the device,
 * so that the test can tell which image each device runs. The protocol does not need to be started.
 */
static esp_err_t hatt_test_handler(httpd_req_t *req) {
    char buf[128] = {0};
    char target_ip[INET_ADDRSTRLEN] = {0};
    bool start_prover = false;
    int runs = 0;
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret > 0) {
        cJSON *root = cJSON_Parse(buf);
        const cJSON *item = root ? cJSON_GetObjectItem(root, "prover") : NULL;
        start_prover = cJSON_IsTrue(item);
        item = root ? cJSON_GetObjectItem(root, "target_ip") : NULL;
        if (cJSON_IsString(item)) strncpy(target_ip, item->valuestring, sizeof(target_ip) - 1);
        item = root ? cJSON_GetObjectItem(root, "runs") : NULL;
        if (cJSON_IsNumber(item)) runs = item->valueint;
        cJSON_Delete(root);
    }
    // The proxy of the test bench waits at most 95 s, i.e., about 25 attestations.
    if (runs < 0) runs = 0;
    if (runs > 25) runs = 25;

    // The attestation reads the size of the network from the database, which is otherwise
    // initialized only when the protocol starts.
    if (!app_logic_started) db_init();
    init_sram_puf();
    hatt_init();
    if (start_prover) hatt_prover_start_task();

    int passed = 0, failed = 0, no_answer = 0;
    if (target_ip[0] != '\0') {
        for (int i = 0; i < runs; i++) {
            hatt_result_t outcome = hatt_verifier_attest(target_ip, NULL);
            if (outcome == HATT_PASSED) passed++;
            else if (outcome == HATT_FAILED) failed++;
            else no_answer++;
        }
    }

    uint8_t digest[HATT_HASH_SIZE_BYTES];
    char digest_hex[2 * 8 + 1] = {0};
    if (hatt_attested_image_digest(digest)) bytes_to_hex(digest, digest_hex, 8);

    char resp[192];
    snprintf(resp, sizeof(resp), "{\"status\": \"ok\", \"image\": \"%s\", \"passed\": %d, \"failed\": %d, \"no_answer\": %d}",
             digest_hex, passed, failed, no_answer);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, strlen(resp));
    return ESP_OK;
}

/**
 * @brief Handler that injects a fault in the device. For tests only.
 * @details {"fault": "crash"} makes the device leave the network without notice, as after a power loss.
 * {"fault": "tamper", "bytes": n} rewrites n bytes of the attestation test region in flash, as a remote
 * alteration of the software of a running device would do.
 */
static esp_err_t fault_test_handler(httpd_req_t *req) {
    char buf[96] = {0};
    char fault[16] = {0};
    int bytes = ATTESTATION_TEST_REGION_SIZE;
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret > 0) {
        cJSON *root = cJSON_Parse(buf);
        const cJSON *item = root ? cJSON_GetObjectItem(root, "fault") : NULL;
        if (cJSON_IsString(item)) strncpy(fault, item->valuestring, sizeof(fault) - 1);
        item = root ? cJSON_GetObjectItem(root, "bytes") : NULL;
        if (cJSON_IsNumber(item)) bytes = item->valueint;
        cJSON_Delete(root);
    }

    if (strcmp(fault, "tamper") == 0) {
        bool ok = bytes > 0 && attestation_test_region_tamper((size_t)bytes);
        const char *resp_str = ok ? "{\"status\": \"ok\", \"fault\": \"tamper\"}" : "{\"status\": \"error\", \"fault\": \"tamper\"}";
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, resp_str, strlen(resp_str));
        return ESP_OK;
    }
    if (strcmp(fault, "crash") == 0) {
        const char *resp_str = "{\"status\": \"ok\", \"fault\": \"crash\"}";
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, resp_str, strlen(resp_str));
        vTaskDelay(pdMS_TO_TICKS(200));
        wifi_simulate_failure();
        return ESP_OK;
    }
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Unknown fault");
    return ESP_OK;
}

#ifdef SRAFT_ATTACK_HOOKS
/**
 * @brief Test-only endpoint that drives the adversary hooks of the attack-resilience campaign.
 * @details Each call performs one adversary action through the real transport and verify paths and
 * returns what the attacker can observe. The ordinary firmware is built without SRAFT_ATTACK_HOOKS
 * and does not register this endpoint. Actions:
 *  - {"action":"force_prover_response"[, "response":hex]} arms the next Prover answer with a response
 *    other than the enrolled one, so that a following /request_authentication fails (impersonation
 *    with a wrong credential, Section 5.3).
 *  - {"action":"oracle","prover_ip":ip,"challenge":c} queries a Prover with an invalid proof and
 *    reports whether it answered (Section 5.2).
 *  - {"action":"send_raw","target_ip":ip,"line":s[,"flip_index":n]} injects a raw line, optionally
 *    with one byte flipped (Section 5.1 and 5.4).
 *  - {"action":"direct_removal","target_ip":ip} as Coordinator, orders a removal without the
 *    confirmation phase (Section 5.4).
 *  - {"action":"forge_hb","target_ip":ip,"term":t} forges a Coordinator heartbeat (Section 5.4).
 */
static esp_err_t attack_test_handler(httpd_req_t *req) {
    char buf[320] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    cJSON *root = ret > 0 ? cJSON_Parse(buf) : NULL;
    if (!root) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); return ESP_OK; }

    const cJSON *a = cJSON_GetObjectItem(root, "action");
    const char *action = cJSON_IsString(a) ? a->valuestring : "";
    const cJSON *ip_item = cJSON_GetObjectItem(root, "target_ip");
    const char *target_ip = cJSON_IsString(ip_item) ? ip_item->valuestring : "";
    char resp[160] = "{\"status\": \"error\"}";

    if (strcmp(action, "force_prover_response") == 0) {
        const cJSON *r = cJSON_GetObjectItem(root, "response");
        // A fixed value that is a valid response string but not the one enrolled for any challenge.
        const char *forced = cJSON_IsString(r) ? r->valuestring : "00000000000000000000000000000000";
        attacker_force_prover_response(forced);
        snprintf(resp, sizeof(resp), "{\"status\": \"ok\", \"armed\": true}");
    } else if (strcmp(action, "build_authreq") == 0) {
        const cJSON *p = cJSON_GetObjectItem(root, "prover_ip");
        char line[PUF_MAX_MSG_SIZE] = {0};
        bool ok = cJSON_IsString(p) && attacker_build_authreq(p->valuestring, line, sizeof(line));
        // Strip the trailing newline for the JSON string.
        size_t ll = strlen(line);
        if (ll && line[ll - 1] == '\n') line[ll - 1] = '\0';
        if (ok) {
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "status", "ok");
            cJSON_AddStringToObject(o, "line", line);
            char *s = cJSON_PrintUnformatted(o);
            cJSON_Delete(o);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_sendstr(req, s);
            free(s);
            cJSON_Delete(root);
            return ESP_OK;
        }
        snprintf(resp, sizeof(resp), "{\"status\": \"error\", \"reason\": \"no_crp\"}");
    } else if (strcmp(action, "watch_arm") == 0) {
        const cJSON *o = cJSON_GetObjectItem(root, "op_id");
        attacker_watch_arm(cJSON_IsString(o) ? o->valuestring : NULL);
        snprintf(resp, sizeof(resp), "{\"status\": \"ok\"}");
    } else if (strcmp(action, "watch_count") == 0) {
        snprintf(resp, sizeof(resp), "{\"status\": \"ok\", \"responses\": %d}", attacker_watch_responses_count());
    } else if (strcmp(action, "oracle") == 0) {
        const cJSON *c = cJSON_GetObjectItem(root, "challenge");
        const char *challenge = cJSON_IsString(c) ? c->valuestring : "1";
        bool sent = attacker_send_oracle_query(target_ip, challenge);
        vTaskDelay(pdMS_TO_TICKS(1500));
        int seen = attacker_watch_responses_count();
        snprintf(resp, sizeof(resp), "{\"status\": \"ok\", \"sent\": %s, \"prover_responded\": %s, \"responses\": %d}",
                 sent ? "true" : "false", seen > 0 ? "true" : "false", seen);
    } else if (strcmp(action, "send_raw") == 0) {
        const cJSON *l = cJSON_GetObjectItem(root, "line");
        const cJSON *f = cJSON_GetObjectItem(root, "flip_index");
        int flip = cJSON_IsNumber(f) ? f->valueint : -1;
        bool sent = cJSON_IsString(l) && attacker_send_raw(target_ip, l->valuestring, flip);
        snprintf(resp, sizeof(resp), "{\"status\": \"ok\", \"sent\": %s}", sent ? "true" : "false");
    } else if (strcmp(action, "direct_removal") == 0) {
        int sent = attacker_force_direct_removal(target_ip);
        snprintf(resp, sizeof(resp), "{\"status\": \"ok\", \"sent_to\": %d}", sent);
    } else if (strcmp(action, "forge_hb") == 0) {
        const cJSON *t = cJSON_GetObjectItem(root, "term");
        unsigned int term = cJSON_IsNumber(t) ? (unsigned int)t->valueint : 0;
        bool sent = attacker_forge_heartbeat(target_ip, term);
        snprintf(resp, sizeof(resp), "{\"status\": \"ok\", \"sent\": %s}", sent ? "true" : "false");
    } else {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Unknown attack action");
        return ESP_OK;
    }
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}
static const httpd_uri_t attack_test_uri = { .uri = "/test/attack", .method = HTTP_POST, .handler = attack_test_handler };
#endif // SRAFT_ATTACK_HOOKS

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
static const httpd_uri_t leave_uri = { .uri = "/leave", .method = HTTP_POST, .handler = leave_handler };
static const httpd_uri_t mqtts_auth_uri = { .uri = "/request_authentication_mqtts", .method = HTTP_POST, .handler = mqtts_authentication_handler };
static const httpd_uri_t cluster_heal_uri = { .uri = "/cluster/heal", .method = HTTP_POST, .handler = cluster_heal_handler };
static const httpd_uri_t start_stats_phase_uri = { .uri = "/system/stats/start_phase", .method = HTTP_POST, .handler = start_stats_phase_handler };
static const httpd_uri_t https_server_uri = { .uri = "/test/https_server", .method = HTTP_POST, .handler = https_server_handler };
static const httpd_uri_t mqtts_responder_uri = { .uri = "/test/mqtts_responder", .method = HTTP_POST, .handler = mqtts_responder_handler };
static const httpd_uri_t clear_blacklist_uri = { .uri = "/test/clear_blacklist", .method = HTTP_POST, .handler = clear_blacklist_handler };
static const httpd_uri_t request_attestation_uri = { .uri = "/request_attestation", .method = HTTP_POST, .handler = request_attestation_handler };
static const httpd_uri_t hatt_test_uri = { .uri = "/test/hatt", .method = HTTP_POST, .handler = hatt_test_handler };
static const httpd_uri_t fault_test_uri = { .uri = "/test/fault", .method = HTTP_POST, .handler = fault_test_handler };

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
    httpd_register_uri_handler(server, &leave_uri);
    httpd_register_uri_handler(server, &mqtts_auth_uri);
    httpd_register_uri_handler(server, &tls_auth_uri);
    httpd_register_uri_handler(server, &cluster_heal_uri);
    httpd_register_uri_handler(server, &start_stats_phase_uri);
    httpd_register_uri_handler(server, &clear_blacklist_uri);
    httpd_register_uri_handler(server, &mqtts_responder_uri);
    httpd_register_uri_handler(server, &https_server_uri);
    httpd_register_uri_handler(server, &request_attestation_uri);
    httpd_register_uri_handler(server, &hatt_test_uri);
    httpd_register_uri_handler(server, &fault_test_uri);
#ifdef SRAFT_ATTACK_HOOKS
    httpd_register_uri_handler(server, &attack_test_uri);
#endif
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
    http_config.max_uri_handlers = 20;
    // The REST handlers of the baselines run a TLS client in this task, which needs a large stack.
    http_config.stack_size = 10240;
    ESP_LOGI(TAG, "Starting HTTP server on port %d", http_config.server_port);
    if (httpd_start(&http_server, &http_config) == ESP_OK) {
        register_http_handlers(http_server);
    } else {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }

    // The HTTPS server is the target of the TLS baseline only, so it is started on demand
    // (see /test/https_server) and does not take memory during the other scenarios.
}

/**
 * @brief Starts the HTTPS server (mutual TLS) used as the target of the TLS baseline.
 */
static void https_server_start(void) {
    if (https_server) return;

    size_t cert_len, key_len, ca_len;
    char* servercert_buf = read_embedded_file("/certs/device.crt", &cert_len);
    char* prvtkey_buf = read_embedded_file("/certs/device.key", &key_len);
    char* cacert_buf = read_embedded_file("/certs/ca.crt", &ca_len);

    if (servercert_buf && prvtkey_buf && cacert_buf) {
        httpd_ssl_config_t https_config = HTTPD_SSL_CONFIG_DEFAULT();
        https_config.port_secure = 443;
        https_config.servercert = (const uint8_t*) servercert_buf;
        https_config.servercert_len = cert_len;
        https_config.prvtkey_pem = (const uint8_t*) prvtkey_buf;
        https_config.prvtkey_len = key_len;
        https_config.cacert_pem = (const uint8_t*) cacert_buf;
        https_config.cacert_len = ca_len;
        // Session tickets (RFC 5077), so that a client can resume a session established by an earlier full
        // handshake (baseline "TLS_RESUMED"). The ticket key lives as long as the server, which is kept
        // running between the full handshake and the resumption.
        https_config.session_tickets = true;

        ESP_LOGI(TAG, "Starting HTTPS server on port %d", https_config.port_secure);
        if (httpd_ssl_start(&https_server, &https_config) == ESP_OK) {
            register_https_handlers(https_server);
        } else {
            https_server = NULL;
            ESP_LOGE(TAG, "Failed to start HTTPS server");
        }
    } else {
        ESP_LOGE(TAG, "Failed to load certificates for HTTPS server.");
    }

    if (servercert_buf) free(servercert_buf);
    if (prvtkey_buf) free(prvtkey_buf);
    if (cacert_buf) free(cacert_buf);
}

static void https_server_stop(void) {
    if (https_server) {
        ESP_LOGI(TAG, "Stopping HTTPS server");
        httpd_ssl_stop(https_server);
        https_server = NULL;
    }
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