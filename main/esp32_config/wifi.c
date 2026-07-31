/* =============================
 * File: wifi.c
 * Description: Simple Wi-Fi connection in STA mode.
 * ============================= */

#include "wifi.h"
#include "utility.h"
#include "discovery.h"
#include "esp_wifi.h"
#include "sdkconfig.h"
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/event_groups.h"
#include <string.h>
#include <arpa/inet.h>

static const char *TAG = "WIFI";

static EventGroupHandle_t wifi_event_group;

/**
 * @brief A background task that periodically sends a heartbeat message to the monitoring server.
 * @details This task runs in a continuous loop, sending a "NODE_ALIVE" message to the central
 * monitoring server to indicate that the node is still operational.
 * @param pvParameters Unused task parameters.
 */
static void heartbeat_task(void *pvParameters) {
    ESP_LOGI("HEARTBEAT", "Heartbeat task started.");
    char my_ip_buffer[INET_ADDRSTRLEN];
    char my_mac_buffer[MAC_ADDR_STR_LEN];
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(30 * 1000));
        get_my_ip(my_ip_buffer, sizeof(my_ip_buffer));
        get_my_mac(my_mac_buffer, sizeof(my_mac_buffer));
        if (strcmp(my_ip_buffer, "0.0.0.0") != 0) {
            char heartbeat_msg[64];
            snprintf(heartbeat_msg, sizeof(heartbeat_msg), "NODE_ALIVE:%s:%s", my_ip_buffer, my_mac_buffer);
            send_monitoring_tcp_event(heartbeat_msg);
        }
    }
}

/**
 * @brief Handles Wi-Fi and IP events from the ESP-IDF event loop.
 * @details This function is the central callback for network events. It handles the Wi-Fi
 * station starting, obtaining an IP address, and handling disconnections. Upon
 * first successful connection, it starts a simple heartbeat task.
 * @param arg User-defined arguments (unused).
 * @param event_base The event base that triggered the handler (e.g., WIFI_EVENT, IP_EVENT).
 * @param event_id The specific ID of the event.
 * @param event_data A pointer to the data associated with the event.
 * @return void
 */
static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "Wi-Fi started, attempting to connect");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        initialize_sntp_sync();
        announce_presence();

        static bool services_started = false;
        if (!services_started) {
            xTaskCreate(heartbeat_task, "heartbeat_task", 3072, NULL, 5, NULL);
            services_started = true;
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Disconnected from Wi-Fi. Attempting to reconnect...");
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

/**
 * @brief Initializes the Wi-Fi station, connects to the configured AP, and waits for an IP address.
 * @details This is a blocking function. It initializes the underlying TCP/IP stack and event loop,
 * configures the Wi-Fi with the hardcoded SSID and password, and does not return until
 * a successful connection is established and an IP address is obtained.
 * @return void
 */
void wifi_init_sta(void) {
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi-Fi initialization started, waiting for connection...");

    EventBits_t bits = xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Successfully connected to AP and got IP.");
    } else {
        ESP_LOGE(TAG, "Failed to connect to AP.");
    }
}