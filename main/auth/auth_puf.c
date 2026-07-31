/* =============================
 * File: auth_puf.c
 * Description: Implements the "push" model for PUF-based authentication.
 * ============================= */

#include "auth_puf.h"
#include "utility.h"
#include "auth_db.h"
#include "connection_pool.h"
#include "nonce_manager.h"
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


static const char *TAG = "AUTH_PUF";

SemaphoreHandle_t auth_result_sem = NULL;
bool auth_result_success = false;

static portMUX_TYPE auth_init_spinlock = portMUX_INITIALIZER_UNLOCKED;

static QueueHandle_t auth_message_queue = NULL;

static void auth_worker_task(void *pvParameters);

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
    
    if (auth_message_queue == NULL) {
        auth_message_queue = xQueueCreate(10, sizeof(auth_message_t*));
        if (auth_message_queue) {
            xTaskCreate(auth_worker_task, "auth_worker", 4096, NULL, 6, NULL);
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
 * @brief Initiates an authentication challenge from an authenticator to a target node.
 * @param authenticatorIp The IP address of this node (the authenticator).
 * @param targetIp The IP address of the node to be authenticated.
 * @return void
 */
static void node_authenticator_start(const char* operation_id, const char* targetIp, const char* targetMac) {
    CRPNode *crp = db_get_random_crp_for_node(targetIp);
    if (!crp) {
        ESP_LOGE(TAG, "No CRP available to authenticate node %s. Cannot start authentication.", targetIp);
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
        
        return;
    }

    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));

    uint8_t nonce_bytes[NONCE_SIZE];
    generate_nonce(nonce_bytes, NONCE_SIZE);

    char nonce_hex[NONCE_HEX_SIZE];
    bytes_to_hex(nonce_bytes, nonce_hex, NONCE_SIZE);

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%s|%s|%s|%s\n", MSG_AUTH_REQ, operation_id, crp->challenge, my_ip, nonce_hex);
    
    ESP_LOGI(TAG, "Queueing %s for target %s", MSG_AUTH_REQ, targetIp);
    connection_pool_send(targetIp, msg);
    
    free(crp);
}

/**
 * @brief Responds to an authentication request with a simulated PUF response.
 * @param challenge The challenge string received from the authenticator.
 * @param myIp The IP address of this node (the prover).
 * @param authenticatorIp The IP address of the authenticator to send the response to.
 * @param nonce_hex The nonce received from the authenticator, to be echoed back.
 * @return void
 */
static void node_to_authenticate_respond(const char *operation_id, const char *challenge, const char* myIp, const char* authenticatorIp, const char *nonce_hex) {
    char response[64];
    simulate_puf_response((const uint8_t*)challenge, strlen(challenge), response);

    char my_mac[MAC_ADDR_STR_LEN];
    get_my_mac(my_mac, sizeof(my_mac));

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%s|%s|%s|%s|%s|%s\n", MSG_AUTH_RESPONSE, operation_id, response, challenge, myIp, my_mac, nonce_hex);

    ESP_LOGI(TAG, "Queueing PUF %s to authenticator %s", MSG_AUTH_RESPONSE, authenticatorIp);
    connection_pool_send(authenticatorIp, msg);
}

/**
 * @brief Verifies a received response against the expected CRP and checks the nonce.
 * @param receivedResponse The PUF response string from the prover.AUTH_RESPONSE
 * @param challenge The original challenge string, used to look up the expected response and nonce.
 * @param responseFromIp The IP address of the node that sent the response.
 * @param received_nonce_hex The nonce string echoed back by the prover.
 * @return void
 */
static void node_authenticator_check_response(const char *operation_id, const char *receivedResponse, const char *challenge, const char* responseFromIp, const char* responseFromMac, const char* received_nonce_hex) {
    int result = 0;
    if (!nonce_is_valid_and_store(received_nonce_hex)) {
        ESP_LOGE(TAG, "Authentication failed for %s due to replayed or invalid nonce in response.", responseFromIp);
        result = 0;
    } else {
        CRPNode *expected = db_get_crp_by_challenge(challenge);
        if (!expected) {
            ESP_LOGE(TAG, "No expected CRP found for challenge %s from %s", challenge, responseFromIp);
            result = 0;
        } else {
            if (strcmp(receivedResponse, expected->response) == 0) {
                result = 1;
            }
            free(expected);
        }
    }

    ESP_LOGI(TAG, "[RESULT] Authentication of node %s %s", responseFromIp, result ? "SUCCEEDED" : "FAILED");

    char result_msg[PUF_MAX_MSG_SIZE];
    char nonce_hex[NONCE_HEX_SIZE];
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    bytes_to_hex(nonce, nonce_hex, NONCE_SIZE);
    
    snprintf(result_msg, sizeof(result_msg), "%s|%d|%s\n", MSG_AUTH_FINAL_RESULT, result, nonce_hex);
    connection_pool_send(responseFromIp, result_msg);

    char event_msg[PUF_MAX_MSG_SIZE];
    snprintf(event_msg, sizeof(event_msg), "AUTH_RESULT_EVENT|%d|%s|%s|SRAFT", result, operation_id, responseFromMac);
    send_monitoring_tcp_event(event_msg);
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
        char* nonce_hex = strtok_r(NULL, "", &saveptr);
        if (!challenge || !authenticator_ip || !nonce_hex || !nonce_is_valid_and_store(nonce_hex)) {
            ESP_LOGW(TAG, "Malformed or replayed %s from %s", MSG_AUTH_REQ, from_ip);
            return;
        }

        ESP_LOGI(TAG, "Received %s from authenticator %s", MSG_AUTH_REQ, authenticator_ip);
        node_to_authenticate_respond(operation_id, challenge, my_ip, authenticator_ip, nonce_hex);
    } else if (strcmp(command, MSG_AUTH_RESPONSE) == 0) {
        char* operation_id = strtok_r(NULL, "|", &saveptr);
        char* response = strtok_r(NULL, "|", &saveptr);
        char* challenge = strtok_r(NULL, "|", &saveptr);
        char* prover_ip = strtok_r(NULL, "|", &saveptr);
        char* prover_mac = strtok_r(NULL, "|", &saveptr);
        char* nonce_hex = strtok_r(NULL, "", &saveptr);
        if (!response || !challenge || !prover_ip || !prover_mac || !nonce_hex) {
            ESP_LOGW(TAG, "Malformed %s from %s", MSG_AUTH_RESPONSE, from_ip);
            return;
        }

        ESP_LOGI(TAG, "Received PUF %s from prover %s", MSG_AUTH_RESPONSE, prover_ip);
        node_authenticator_check_response(operation_id, response, challenge, prover_ip, prover_mac, nonce_hex);
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