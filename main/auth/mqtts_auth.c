/* =============================
 * File: mqtts_auth.c
 * Description: Implements authentication via MQTTS connection.
 * ============================= */

#include "mqtts_auth.h"
#include "utility.h"
#include "raft_state.h"
#include "rest_api.h"
#include "esp_log.h"
#include "mqtt_client.h"
#include "freertos/event_groups.h"
#include <string.h>

static const char *TAG = "MQTTS_AUTH";
static esp_mqtt_client_handle_t responder_client = NULL;

/**
 * @brief Handles events from the MQTT client, such as connection and data reception.
 * @details This callback function is registered with the ESP-MQTT client. It uses an
 * event group to signal the main function when specific events (like a successful
 * connection or receiving data) occur.
 * @param handler_args User-defined arguments passed to the handler (event group handle).
 * @param base The event base associated with the event.
 * @param event_id The specific event ID.
 * @param event_data Data associated with the event.
 * @return void
 */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    EventGroupHandle_t mqtt_event_group = (EventGroupHandle_t)handler_args;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        xEventGroupSetBits(mqtt_event_group, CONNECTED_BIT);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        xEventGroupSetBits(mqtt_event_group, MSG_RECEIVED_BIT);
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT_EVENT_ERROR");
        break;
    default:
        break;
    }
}

/**
 * @brief Performs authentication by connecting to an MQTTS broker.
 * @details This function establishes a mutual TLS (mTLS) connection to the specified
 * MQTTS broker using the node's unique certificates. A successful connection is
 * considered a successful authentication. It also performs an optional end-to-end
 * message check for further validation.
 * @param broker_uri The full URI of the MQTTS broker (e.g., "mqtts://192.168.1.100:8883").
 * @param target_ip The IP of the target node for the end-to-end message check.
 * @return true if the connection and message exchange are successful, false otherwise.
 */
bool run_mqtts_authentication(const char *broker_uri, const char *target_ip)
{
    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));

    uint32_t op_id = (uint32_t)esp_random();
    char event_msg[MAX_MESSAGE_SIZE];
    snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_START|auth_%s_%lu|%s|MQTTS",
             my_mac, op_id, my_mac);
    send_monitoring_tcp_event(event_msg);

    bool success = false;
    size_t ca_len, cert_len, key_len;
    char *ca_cert = read_embedded_file("/certs/ca.crt", &ca_len);
    char *device_cert = read_embedded_file("/certs/device.crt", &cert_len);
    char *device_key = read_embedded_file("/certs/device.key", &key_len);

    if (!ca_cert || !device_cert || !device_key)
    {
        ESP_LOGE(TAG, "Failed to load embedded certificates for MQTTS auth.");
        if (ca_cert)
            free(ca_cert);
        if (device_cert)
            free(device_cert);
        if (device_key)
            free(device_key);
        return false;
    }

    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = broker_uri,
        .broker.verification.certificate = (const char *)ca_cert,
        .broker.verification.certificate_len = ca_len,
        .broker.verification.skip_cert_common_name_check = true,
        .credentials.authentication = {
            .certificate = (const char *)device_cert,
            .certificate_len = cert_len,
            .key = (const char *)device_key,
            .key_len = key_len,
        }};

    EventGroupHandle_t mqtt_event_group = xEventGroupCreate();
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, mqtt_event_group);
    esp_mqtt_client_start(client);

    EventBits_t bits = xEventGroupWaitBits(mqtt_event_group, CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(10000));

    if (bits & CONNECTED_BIT)
    {
        char response_topic[64];
        snprintf(response_topic, sizeof(response_topic), "auth/response/%s", my_ip);
        esp_mqtt_client_subscribe(client, response_topic, 0);

        char request_topic[64];
        snprintf(request_topic, sizeof(request_topic), "auth/request/%s", target_ip);
        esp_mqtt_client_publish(client, request_topic, my_ip, 0, 1, 0);

        EventBits_t msg_bits = xEventGroupWaitBits(mqtt_event_group, MSG_RECEIVED_BIT, pdTRUE, pdTRUE, pdMS_TO_TICKS(5000));
        if (msg_bits & MSG_RECEIVED_BIT)
        {
            ESP_LOGI(TAG, "End-to-end message exchange successful.");
            success = true;
        }
        else
        {
            ESP_LOGW(TAG, "Timed out waiting for response message.");
        }
    }
    else
    {
        ESP_LOGE(TAG, "Failed to connect to MQTTS broker.");
    }

    esp_mqtt_client_stop(client);
    esp_mqtt_client_destroy(client);
    vEventGroupDelete(mqtt_event_group);

    free(ca_cert);
    free(device_cert);
    free(device_key);

    snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_RESULT_EVENT|%d|auth_%s_%lu|%s|MQTTS",
             success ? 1 : 0, my_mac, op_id, my_mac);
    send_monitoring_tcp_event(event_msg);
    return success;
}

/**
 * @brief Event handler for the persistent MQTTS auth responder client.
 * @details On connect, (re-)subscribes to this node's own request topic. On
 * receiving a request (the payload is the requester's IP), publishes an
 * acknowledgement back to the requester's response topic, completing the
 * end-to-end challenge/response used by run_mqtts_authentication().
 */
static void mqtts_responder_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
    {
        char my_ip[INET_ADDRSTRLEN];
        get_my_ip(my_ip, sizeof(my_ip));
        char request_topic[64];
        snprintf(request_topic, sizeof(request_topic), "auth/request/%s", my_ip);
        esp_mqtt_client_subscribe(event->client, request_topic, 0);
        ESP_LOGI(TAG, "MQTTS auth responder (re)subscribed to %s", request_topic);
        break;
    }
    case MQTT_EVENT_DATA:
    {
        if (event->data_len <= 0 || event->data_len >= INET_ADDRSTRLEN)
        {
            ESP_LOGW(TAG, "MQTTS auth responder received malformed request payload.");
            break;
        }
        char requester_ip[INET_ADDRSTRLEN];
        memcpy(requester_ip, event->data, event->data_len);
        requester_ip[event->data_len] = '\0';

        char my_ip[INET_ADDRSTRLEN];
        get_my_ip(my_ip, sizeof(my_ip));
        char response_topic[64];
        snprintf(response_topic, sizeof(response_topic), "auth/response/%s", requester_ip);
        esp_mqtt_client_publish(event->client, response_topic, my_ip, 0, 1, 0);
        ESP_LOGI(TAG, "MQTTS auth responder answered request from %s", requester_ip);
        break;
    }
    default:
        break;
    }
}

/**
 * @brief Starts the persistent background MQTTS auth responder for this node.
 * @details Without this responder, run_mqtts_authentication() has no peer to answer
 * its end-to-end challenge and always times out. Safe to call multiple times;
 * subsequent calls are no-ops once the responder is running.
 * @return void
 */
void mqtts_auth_start_responder(void)
{
    if (responder_client != NULL)
    {
        return;
    }

    size_t ca_len, cert_len, key_len;
    char *ca_cert = read_embedded_file("/certs/ca.crt", &ca_len);
    char *device_cert = read_embedded_file("/certs/device.crt", &cert_len);
    char *device_key = read_embedded_file("/certs/device.key", &key_len);
    if (!ca_cert || !device_cert || !device_key)
    {
        ESP_LOGE(TAG, "Failed to load embedded certificates for MQTTS auth responder.");
        if (ca_cert)
            free(ca_cert);
        if (device_cert)
            free(device_cert);
        if (device_key)
            free(device_key);
        return;
    }

    char broker_uri[64];
    snprintf(broker_uri, sizeof(broker_uri), "mqtts://%s:%d", MQTT_BROKER_IP, MQTT_BROKER_PORT);

    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = broker_uri,
        .broker.verification.certificate = (const char *)ca_cert,
        .broker.verification.certificate_len = ca_len,
        .broker.verification.skip_cert_common_name_check = true,
        .credentials.authentication = {
            .certificate = (const char *)device_cert,
            .certificate_len = cert_len,
            .key = (const char *)device_key,
            .key_len = key_len,
        }};

    responder_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(responder_client, ESP_EVENT_ANY_ID, mqtts_responder_event_handler, NULL);
    esp_mqtt_client_start(responder_client);

    ESP_LOGI(TAG, "MQTTS auth responder started.");
}