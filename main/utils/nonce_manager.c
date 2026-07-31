/* =============================
 * File: nonce_manager.c
 * Description: Implements a thread-safe, fixed-size nonce store using a circular
 * array to detect and prevent replay attacks.
 * ============================= */

#include "nonce_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "NONCE_MANAGER";

static char nonce_store[NONCE_STORE_SIZE][NONCE_HEX_SIZE];
static int next_nonce_idx = 0;

static SemaphoreHandle_t nonce_mutex = NULL;
static portMUX_TYPE nonce_manager_init_spinlock = portMUX_INITIALIZER_UNLOCKED;

/**
 * @brief Initializes the nonce manager module.
 * @details This must be called once at system startup before the module is used.
 */
void nonce_manager_init(void) {
    ESP_LOGI(TAG, "Initializing Node NONCE_MANAGER Module...");
    if (nonce_mutex == NULL) {
        taskENTER_CRITICAL(&nonce_manager_init_spinlock);
        if (nonce_mutex == NULL) {
            nonce_mutex = xSemaphoreCreateMutex();
        }
        taskEXIT_CRITICAL(&nonce_manager_init_spinlock);
    }

    if (nonce_mutex == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create NONCE_MANAGER mutex!");
        return;
    }

    ESP_LOGD(TAG, "Attempting to take NONCE_MANAGER mutex for initialization...");
    if (xSemaphoreTake(nonce_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to take NONCE_MANAGER mutex during init. Aborting.");
        return;
    } else {
        xSemaphoreGive(nonce_mutex);
    }
}

/**
 * @brief Checks if a nonce is valid and, if so, stores it.
 * @details This function is atomic. It checks if the given nonce is already in
 * the store. If not, it adds the nonce to the store and returns true.
 * If the nonce is already present (indicating a replay attack), it returns false.
 * @param nonce The hexadecimal string representation of the nonce to be validated.
 * @return true if the nonce is new and valid, false otherwise.
 */
bool nonce_is_valid_and_store(const char* nonce) {
    if (!nonce_mutex) {
        ESP_LOGE(TAG, "Nonce manager not initialized!");
        return false;
    }

    bool is_valid = true;
    if (xSemaphoreTake(nonce_mutex, portMAX_DELAY) == pdTRUE) {
        for (int i = 0; i < NONCE_STORE_SIZE; i++) {
            if (strcmp(nonce_store[i], nonce) == 0) {
                is_valid = false;
                break;
            }
        }
        if (is_valid) {
            strncpy(nonce_store[next_nonce_idx], nonce, NONCE_HEX_SIZE - 1);
            nonce_store[next_nonce_idx][NONCE_HEX_SIZE - 1] = '\0';
            
            next_nonce_idx = (next_nonce_idx + 1) % NONCE_STORE_SIZE;
        }
        
        xSemaphoreGive(nonce_mutex);
    } else {
        is_valid = false;
    }

    if (!is_valid) {
        ESP_LOGW(TAG, "Replay attack detected or failed to validate nonce: %s", nonce);
    }
    
    return is_valid;
}