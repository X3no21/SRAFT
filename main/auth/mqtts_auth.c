/* =============================
 * File: mqtts_auth.c
 * Description: Implements authentication via MQTTS connection.
 * ============================= */

#include "mqtts_auth.h"
#include "utility.h"
#include "raft_state.h"
#include "rest_api.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "mqtt_client.h"
#include "freertos/event_groups.h"
#include <string.h>

static const char *TAG = "MQTTS_AUTH";
static esp_mqtt_client_handle_t responder_client = NULL;
// Certificates of the responder, kept until the responder is stopped.
static char *responder_ca = NULL, *responder_cert = NULL, *responder_key = NULL;
// Set by the responder when it is subscribed to its request topic.
static EventGroupHandle_t responder_events = NULL;

// A failed connection attempt is repeated after this time, so that it is retried within the time a run waits.
#define MQTTS_RECONNECT_MS 1000
#define MQTTS_CONNECT_WAIT_MS 10000
#define MQTTS_RESPONSE_WAIT_MS 5000
#define MQTTS_RESPONDER_READY_WAIT_MS 15000

/**
 * @brief State shared between a run and the event handler of its MQTT client.
 */
typedef struct {
    EventGroupHandle_t events;
    int last_esp_err;       // esp_tls_last_esp_err of the last transport error
    int last_stack_err;     // mbedTLS error of the last transport error
    unsigned verify_flags;  // certificate verification flags of the last transport error
    int errors;             // transport errors seen during the run
} mqtts_run_ctx_t;

/**
 * @brief Handles events from the MQTT client, such as connection and data reception.
 * @details This callback function is registered with the ESP-MQTT client. It uses an
 * event group to signal the main function when specific events (like a successful
 * connection or receiving data) occur, and records the last transport error.
 * @param handler_args The mqtts_run_ctx_t of the run.
 * @param base The event base associated with the event.
 * @param event_id The specific event ID.
 * @param event_data Data associated with the event.
 * @return void
 */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    mqtts_run_ctx_t *ctx = (mqtts_run_ctx_t *)handler_args;
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        xEventGroupSetBits(ctx->events, CONNECTED_BIT);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        xEventGroupSetBits(ctx->events, MSG_RECEIVED_BIT);
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle && event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT)
        {
            ctx->errors++;
            ctx->last_esp_err = event->error_handle->esp_tls_last_esp_err;
            ctx->last_stack_err = event->error_handle->esp_tls_stack_err;
            ctx->verify_flags = (unsigned)event->error_handle->esp_tls_cert_verify_flags;
            ESP_LOGE(TAG, "TLS error: esp_err 0x%x, stack err -0x%x, certificate verify flags 0x%x",
                     ctx->last_esp_err, -ctx->last_stack_err, ctx->verify_flags);
        }
        break;
    default:
        break;
    }
}

/**
 * @brief Fills the client configuration shared by the requester and the responder.
 */
static void fill_config(esp_mqtt_client_config_t *cfg, const char *broker_uri,
                        const char *ca, size_t ca_len, const char *cert, size_t cert_len, const char *key, size_t key_len)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->broker.address.uri = broker_uri;
    cfg->broker.verification.certificate = ca;
    cfg->broker.verification.certificate_len = ca_len;
    cfg->broker.verification.skip_cert_common_name_check = true;
    cfg->credentials.authentication.certificate = cert;
    cfg->credentials.authentication.certificate_len = cert_len;
    cfg->credentials.authentication.key = key;
    cfg->credentials.authentication.key_len = key_len;
    cfg->network.reconnect_timeout_ms = MQTTS_RECONNECT_MS;
}

/**
 * @brief Performs authentication by connecting to an MQTTS broker.
 * @details This function establishes a mutual TLS (mTLS) connection to the specified
 * MQTTS broker using the node's unique certificates. A successful connection is
 * considered a successful authentication. It also performs an optional end-to-end
 * message check for further validation. The free heap before the run and, on a failure, its
 * cause are reported to the monitoring server (AUTH_DIAG).
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

    size_t heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t heap_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    bool success = false;
    const char *cause = "none";
    mqtts_run_ctx_t ctx = {0};
    size_t ca_len, cert_len, key_len;
    char *ca_cert = read_embedded_file("/certs/ca.crt", &ca_len);
    char *device_cert = read_embedded_file("/certs/device.crt", &cert_len);
    char *device_key = read_embedded_file("/certs/device.key", &key_len);
    esp_mqtt_client_handle_t client = NULL;

    if (!ca_cert || !device_cert || !device_key)
    {
        ESP_LOGE(TAG, "Failed to load embedded certificates for MQTTS auth.");
        cause = "certificates";
        goto done;
    }

    esp_mqtt_client_config_t mqtt_cfg;
    fill_config(&mqtt_cfg, broker_uri, ca_cert, ca_len, device_cert, cert_len, device_key, key_len);

    ctx.events = xEventGroupCreate();
    client = ctx.events ? esp_mqtt_client_init(&mqtt_cfg) : NULL;
    if (!client)
    {
        // Out of memory: the run fails instead of using an invalid client.
        ESP_LOGE(TAG, "Could not create the MQTTS client.");
        cause = "client";
        goto done;
    }
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, &ctx);
    esp_mqtt_client_start(client);

    EventBits_t bits = xEventGroupWaitBits(ctx.events, CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(MQTTS_CONNECT_WAIT_MS));

    if (bits & CONNECTED_BIT)
    {
        char response_topic[64];
        snprintf(response_topic, sizeof(response_topic), "auth/response/%s", my_ip);
        esp_mqtt_client_subscribe(client, response_topic, 0);

        char request_topic[64];
        snprintf(request_topic, sizeof(request_topic), "auth/request/%s", target_ip);
        esp_mqtt_client_publish(client, request_topic, my_ip, 0, 1, 0);

        EventBits_t msg_bits = xEventGroupWaitBits(ctx.events, MSG_RECEIVED_BIT, pdTRUE, pdTRUE, pdMS_TO_TICKS(MQTTS_RESPONSE_WAIT_MS));
        if (msg_bits & MSG_RECEIVED_BIT)
        {
            ESP_LOGI(TAG, "End-to-end message exchange successful.");
            success = true;
        }
        else
        {
            ESP_LOGW(TAG, "Timed out waiting for response message.");
            cause = "no_response";
        }
    }
    else
    {
        ESP_LOGE(TAG, "Failed to connect to MQTTS broker.");
        cause = ctx.errors ? "tls" : "connect_timeout";
    }

done:
    if (client)
    {
        esp_mqtt_client_stop(client);
        esp_mqtt_client_destroy(client);
    }
    if (ctx.events)
        vEventGroupDelete(ctx.events);
    free(ca_cert);
    free(device_cert);
    free(device_key);

    // Free heap before the run and cause of a failure, for the diagnosis of failed runs.
    snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_DIAG|auth_%s_%lu|MQTTS|%s|heap_free=%u|heap_largest=%u|tls_errors=%d|esp_err=0x%x|stack_err=-0x%x|verify=0x%x",
             my_mac, op_id, success ? "ok" : cause, (unsigned)heap_free, (unsigned)heap_largest, ctx.errors,
             ctx.last_esp_err, -ctx.last_stack_err, ctx.verify_flags);
    send_monitoring_tcp_event(event_msg);

    snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_RESULT_EVENT|%d|auth_%s_%lu|%s|MQTTS",
             success ? 1 : 0, my_mac, op_id, my_mac);
    send_monitoring_tcp_event(event_msg);
    return success;
}

/**
 * @brief Event handler for the persistent MQTTS auth responder client.
 * @details On connect, (re-)subscribes to this node's own request topic, and signals when the
 * subscription is acknowledged. On receiving a request (the payload is the requester's IP),
 * publishes an acknowledgement back to the requester's response topic, completing the
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
    case MQTT_EVENT_SUBSCRIBED:
        if (responder_events)
            xEventGroupSetBits(responder_events, CONNECTED_BIT);
        break;
    case MQTT_EVENT_DISCONNECTED:
        if (responder_events)
            xEventGroupClearBits(responder_events, CONNECTED_BIT);
        break;
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
 * its end-to-end challenge and always times out. Returns only when the responder is subscribed
 * to its request topic, or after MQTTS_RESPONDER_READY_WAIT_MS, so that a request sent afterwards
 * is not lost. Safe to call multiple times.
 * @return true if the responder is subscribed.
 */
bool mqtts_auth_start_responder(void)
{
    if (responder_client == NULL)
    {
        size_t ca_len, cert_len, key_len;
        char *ca_cert = read_embedded_file("/certs/ca.crt", &ca_len);
        char *device_cert = read_embedded_file("/certs/device.crt", &cert_len);
        char *device_key = read_embedded_file("/certs/device.key", &key_len);
        if (!ca_cert || !device_cert || !device_key)
        {
            ESP_LOGE(TAG, "Failed to load embedded certificates for MQTTS auth responder.");
            free(ca_cert);
            free(device_cert);
            free(device_key);
            return false;
        }
        if (!responder_events)
            responder_events = xEventGroupCreate();
        if (responder_events)
            xEventGroupClearBits(responder_events, CONNECTED_BIT);

        static char broker_uri[64];
        snprintf(broker_uri, sizeof(broker_uri), "mqtts://%s:%d", MQTT_BROKER_IP, MQTT_BROKER_PORT);

        esp_mqtt_client_config_t mqtt_cfg;
        fill_config(&mqtt_cfg, broker_uri, ca_cert, ca_len, device_cert, cert_len, device_key, key_len);

        responder_client = esp_mqtt_client_init(&mqtt_cfg);
        if (!responder_client)
        {
            ESP_LOGE(TAG, "Failed to create the MQTTS auth responder.");
            free(ca_cert);
            free(device_cert);
            free(device_key);
            return false;
        }
        responder_ca = ca_cert;
        responder_cert = device_cert;
        responder_key = device_key;
        esp_mqtt_client_register_event(responder_client, ESP_EVENT_ANY_ID, mqtts_responder_event_handler, NULL);
        esp_mqtt_client_start(responder_client);
        ESP_LOGI(TAG, "MQTTS auth responder started.");
    }

    if (!responder_events)
        return false;
    EventBits_t bits = xEventGroupWaitBits(responder_events, CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(MQTTS_RESPONDER_READY_WAIT_MS));
    bool ready = (bits & CONNECTED_BIT) != 0;
    if (!ready)
        ESP_LOGW(TAG, "MQTTS auth responder not subscribed after %d ms.", MQTTS_RESPONDER_READY_WAIT_MS);
    return ready;
}

void mqtts_auth_stop_responder(void)
{
    if (responder_client == NULL)
    {
        return;
    }
    esp_mqtt_client_stop(responder_client);
    esp_mqtt_client_destroy(responder_client);
    responder_client = NULL;
    if (responder_events)
        xEventGroupClearBits(responder_events, CONNECTED_BIT);
    free(responder_ca);
    free(responder_cert);
    free(responder_key);
    responder_ca = responder_cert = responder_key = NULL;
    ESP_LOGI(TAG, "MQTTS auth responder stopped.");
}
