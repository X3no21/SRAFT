/* =============================
 * File: main.c
 * Description: Main application entry point. Initializes basic services (NVS, WiFi)
 * and the REST API server, then waits for commands.
 * ============================= */

#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "rest_api.h"
#include "wifi.h"
#include "auth_db.h"
#include "auth_join.h"
#include "auth_join.h"
#include "auth_remove.h"
#include "utility.h"

static const char *TAG = "MAIN";


/**
 * @brief Main entry point. Initializes basic services and the REST API server.
 */
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(psa_crypto_init() == PSA_SUCCESS ? ESP_OK : ESP_FAIL);

    ESP_LOGI(TAG, "Initializing SRAM-PUF...");
    init_sram_puf();
    
    monitoring_init();

    ESP_LOGI(TAG, "App started. Initializing WiFi...");
    wifi_init_sta();

    ESP_LOGI(TAG, "WiFi connected. Starting REST API server.");
    rest_api_start();
    
    ESP_LOGI(TAG, "app_main setup finished. System is idle, waiting for commands via REST API.");
}