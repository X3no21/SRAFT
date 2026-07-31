/* =============================
 * File: utility.c
 * Description: Utility functions.
 * ============================= */

#include "utility.h"
#include "raft_state.h"
#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "psa/crypto.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/rtc.h"
#include <time.h>

static const char *TAG = "UTILITY";

static uint32_t sram_fingerprint[SRAM_PUF_SIZE_WORDS] = {0};
static uint32_t reliability_mask[SRAM_PUF_SIZE_WORDS] = {0};

static bool puf_initialized = false;

/**
 * @brief Callback function executed upon successful SNTP time synchronization.
 * @details This function is registered with the SNTP service and is automatically
 * invoked when the system obtains a valid time from an NTP server. Its sole
 * purpose is to print a confirmation log message.
 * @param tv A pointer to a `timeval` struct provided by the SNTP library. This
 * parameter is not used in the current implementation.
 * @return void
 */
static void on_sntp_sync(struct timeval *tv) {
    ESP_LOGI("SNTP", "Time has been synchronized");
}

/**
 * @brief Initializes the SNTP client and blocks until the system time is synchronized.
 * @details This function configures and starts the SNTP client to obtain the current
 * time from a public NTP server (`pool.ntp.org`). It enters a blocking wait
 * loop with a limited number of retries to ensure time is synchronized before
 * proceeding. If successful, it sets the local timezone environment variable to
 * allow for correct local time conversions.
 * @param None
 * @return void
 */
void initialize_sntp_sync(void) {
    ESP_LOGI("SNTP", "Initializing SNTP");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, MONITORING_SERVER_IP);
    esp_sntp_set_time_sync_notification_cb(on_sntp_sync);
    esp_sntp_init();

    int retry = 0;
    const int retry_count = 15;
    while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET && ++retry < retry_count) {
        ESP_LOGI("SNTP", "Waiting for time synchronization... (%d/%d)", retry, retry_count);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    if (retry == retry_count) {
        ESP_LOGE("SNTP", "Failed to sync time!");
    }
}

/**
 * @brief Logs a byte buffer as a hexadecimal string using the ESP-IDF logging framework.
 * @details This utility function provides a standardized way to print binary data for debugging.
 * It displays a label and then the hexadecimal representation of the buffer content.
 * @param tag The logging tag (e.g., "HATT_PROTOCOL") to use for the ESP_LOG message.
 * @param label A descriptive label for the data being printed (e.g., "Nonce N1").
 * @param data A pointer to the byte buffer to be logged.
 * @param len The number of bytes to log from the buffer.
 */
void print_hex(const char* tag, const char* label, const uint8_t* data, size_t len) {
   if (data == NULL || len == 0) {
        ESP_LOGD(tag, "%s [0 bytes]: (null)", label);
        return;
    }
    ESP_LOGD(tag, "%s [%u bytes]:", label, len);
    ESP_LOG_BUFFER_HEX_LEVEL(tag, data, len, ESP_LOG_DEBUG);
}

/**
 * @brief Announces the node's presence on the network to the central monitoring server.
 * @details This is typically called once after a successful Wi-Fi connection.
 * @return void
 */
void announce_presence(void) {
    char my_ip_buf[INET_ADDRSTRLEN];
    char my_mac_buf[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip_buf, sizeof(my_ip_buf));
    get_my_mac(my_mac_buf, sizeof(my_mac_buf));
    
    char announce_msg[128];
    snprintf(announce_msg, sizeof(announce_msg), "NODE_ONLINE:%s:%s", my_ip_buf, my_mac_buf);

    ESP_LOGI("ANNOUNCE", "Sending presence announcement: %s", announce_msg);
    send_monitoring_tcp_event(announce_msg);
}

extern const uint8_t _binary_ca_crt_start[] asm("_binary_ca_crt_start");
extern const uint8_t _binary_ca_crt_end[]   asm("_binary_ca_crt_end");
extern const uint8_t _binary_device_crt_start[] asm("_binary_device_crt_start");
extern const uint8_t _binary_device_crt_end[]   asm("_binary_device_crt_end");
extern const uint8_t _binary_device_key_start[] asm("_binary_device_key_start");
extern const uint8_t _binary_device_key_end[]   asm("_binary_device_key_end");

/**
 * @brief Reads an embedded file from the firmware binary.
 * @details The caller is responsible for freeing the returned buffer using free().
 * @param path The virtual path to the file (e.g., "/certs/ca.crt").
 * @param[out] file_size A pointer to a size_t variable where the size of the file will be stored.
 * @return A dynamically allocated buffer containing the file's content, or NULL on failure.
 */
char* read_embedded_file(const char* path, size_t* file_size) {
    *file_size = 0;
    const uint8_t *start = NULL;
    const uint8_t *end = NULL;

    if (strstr(path, "ca.crt") != NULL) {
        start = _binary_ca_crt_start;
        end = _binary_ca_crt_end;
    } else if (strstr(path, "device.crt") != NULL) {
        start = _binary_device_crt_start;
        end = _binary_device_crt_end;
    } else if (strstr(path, "device.key") != NULL) {
        start = _binary_device_key_start;
        end = _binary_device_key_end;
    } else {
        ESP_LOGE(TAG, "Unknown embedded file path: %s", path);
        return NULL;
    }

    size_t size = end - start;
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for embedded file: %s", path);
        return NULL;
    }

    memcpy(buffer, start, size);
    buffer[size] = '\0';
    *file_size = size;

    ESP_LOGI(TAG, "Loaded embedded file: %s (%d bytes)", path, (int)size);
    return buffer;
}

/**
 * @brief Sends a monitoring event message to the logging server over a reliable TCP connection.
 * @details This function opens, uses, and closes a new TCP socket for each event.
 * @param event_message The null-terminated string message to send.
 * @return void
 */
static QueueHandle_t monitoring_queue = NULL;

/**
 * @brief Background task that consumes monitoring events from the queue and sends them over TCP.
 * @details This task handles the blocking network I/O, allowing the main application logic
 * (like Raft state transitions) to remain non-blocking.
 */
static void monitoring_task(void *pvParameters) {
    char *msg_to_send;
    while (1) {
        if (xQueueReceive(monitoring_queue, &msg_to_send, portMAX_DELAY) == pdTRUE) {
            if (msg_to_send) {
                struct timeval tv;
                gettimeofday(&tv, NULL);

                char timestamp_buf[32];
                time_t now = tv.tv_sec;
                struct tm timeinfo;
                gmtime_r(&now, &timeinfo);

                strftime(timestamp_buf, sizeof(timestamp_buf), "%Y-%m-%dT%H:%M:%S", &timeinfo);
                int len = strlen(timestamp_buf);
                int millis = tv.tv_usec / 1000;
                snprintf(timestamp_buf + len, sizeof(timestamp_buf) - len, ".%03dZ", millis);

                int new_msg_len = strlen(timestamp_buf) + 1 + strlen(msg_to_send) + 1;
                char *msg_with_ts = malloc(new_msg_len);
                if (msg_with_ts) {
                    snprintf(msg_with_ts, new_msg_len, "%s|%s", timestamp_buf, msg_to_send);

                    int sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock >= 0) {
                        struct sockaddr_in dest_addr;
                        dest_addr.sin_family = AF_INET;
                        dest_addr.sin_port = htons(MONITORING_PORT);
                        inet_pton(AF_INET, MONITORING_SERVER_IP, &dest_addr.sin_addr);

                        struct timeval timeout;
                        timeout.tv_sec = 2;
                        timeout.tv_usec = 0;
                        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

                        if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == 0) {
                            send(sock, msg_with_ts, strlen(msg_with_ts), 0);
                        } else {
                            ESP_LOGW(TAG, "Monitor TCP: Connect failed to %s:%d", MONITORING_SERVER_IP, MONITORING_PORT);
                        }
                        close(sock);
                    } else {
                        ESP_LOGE(TAG, "Monitor TCP: Socket creation failed");
                    }
                    free(msg_with_ts);
                }
                free(msg_to_send);
            }
        }
    }
}

/**
 * @brief Initializes the background monitoring task and queue.
 */
void monitoring_init(void) {
    if (monitoring_queue == NULL) {
        monitoring_queue = xQueueCreate(20, sizeof(char*));
        if (monitoring_queue) {
            xTaskCreate(monitoring_task, "monitor_task", 4096, NULL, 3, NULL);
            ESP_LOGI(TAG, "Async monitoring task initialized.");
        } else {
            ESP_LOGE(TAG, "Failed to create monitoring queue!");
        }
    }
}

/**
 * @brief Queues a monitoring event message to be sent asynchronously.
 * @details This function is non-blocking. It makes a copy of the message and pushes it
 * to the monitoring queue. If the queue is full, the message is dropped to prevent
 * blocking the caller (which might be holding critical mutexes).
 * @param event_message The null-terminated string message to send.
 * @return void
 */
void send_monitoring_tcp_event(const char *event_message) {
    if (monitoring_queue == NULL) {
        return;
    }

    char *msg_copy = strdup(event_message);
    if (!msg_copy) {
        ESP_LOGE(TAG, "Failed to allocate memory for monitoring message copy.");
        return;
    }

    if (xQueueSend(monitoring_queue, &msg_copy, 0) != pdTRUE) {
        ESP_LOGW(TAG, "Monitoring queue full! Dropping message: %s", event_message);
        free(msg_copy);
    }
}

/**
 * @brief Reads and stabilizes SRAM fingerprint using Vatajelu's Stability Test.
 * @details Defines a method to identify unreliable cells based on stability test.
 * We simulate multiple power-ups by toggling the power domain of the RTC Slow Memory
 * at runtime. This forces the SRAM cells to re-initialize, generating fresh entropy
 * for each readout without requiring a full system reboot.
 */
void init_sram_puf(void) {
    if (puf_initialized) {
        return;
    }
    
    ESP_LOGI(TAG, "Initializing SRAM-PUF fingerprint...");
    vTaskSuspendAll();

    uint32_t (*readouts)[SRAM_PUF_SIZE_WORDS] = malloc(SRAM_PUF_READOUTS * sizeof(*readouts));
    if (readouts == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for PUF readouts");
        return;
    }

    volatile uint32_t *rtc_slow_mem = (volatile uint32_t *)0x50000000;
    
    for (int r = 0; r < SRAM_PUF_READOUTS; r++) {
        SET_PERI_REG_MASK(RTC_CNTL_PWC_REG, RTC_CNTL_SLOWMEM_FORCE_PD);
        CLEAR_PERI_REG_MASK(RTC_CNTL_PWC_REG, RTC_CNTL_SLOWMEM_FORCE_PU);
        esp_rom_delay_us(20000);
        
        CLEAR_PERI_REG_MASK(RTC_CNTL_PWC_REG, RTC_CNTL_SLOWMEM_FORCE_PD);
        SET_PERI_REG_MASK(RTC_CNTL_PWC_REG, RTC_CNTL_SLOWMEM_FORCE_PU);
        
        esp_rom_delay_us(5000);
        
        for (int i = 0; i < SRAM_PUF_SIZE_WORDS; i++) {
            readouts[r][i] = rtc_slow_mem[i];
        }
        
        CLEAR_PERI_REG_MASK(RTC_CNTL_PWC_REG, RTC_CNTL_SLOWMEM_FORCE_PU);
    }
    
    xTaskResumeAll();
    
    uint32_t reliable_bits_count = 0;

    for (int i = 0; i < SRAM_PUF_SIZE_WORDS; i++) {
        uint32_t stable_word = 0;
        uint32_t mask_word = 0;

        for (int bit = 0; bit < 32; bit++) {
            int ones = 0;
            for (int r = 0; r < SRAM_PUF_READOUTS; r++) {
                if (readouts[r][i] & (1 << bit)) {
                    ones++;
                }
            }

            if (ones == SRAM_PUF_READOUTS) {
                stable_word |= (1 << bit);
                mask_word |= (1 << bit);
                reliable_bits_count++;
            } else if (ones == 0) {
                stable_word &= ~(1 << bit);
                mask_word |= (1 << bit);
                reliable_bits_count++;
            } else {
                mask_word &= ~(1 << bit);
            }
        }
        sram_fingerprint[i] = stable_word;
        reliability_mask[i] = mask_word;
    }
    
    puf_initialized = true;
    
    free(readouts);
    
    ESP_LOGI(TAG, "SRAM-PUF initialized. Reliable bits: %lu/65536 (%lu%%)", 
             reliable_bits_count, (reliable_bits_count * 100) / 65536);

    const char *test_challenge = "TEST_CHALLENGE";
    char resp1[64], resp2[64];
    simulate_puf_response((uint8_t*)test_challenge, strlen(test_challenge), resp1);
    simulate_puf_response((uint8_t*)test_challenge, strlen(test_challenge), resp2);
    
    if (strcmp(resp1, resp2) == 0) {
        ESP_LOGI(TAG, "PUF Determinism Check: PASS (Resp: %s)", resp1);
    } else {
        ESP_LOGE(TAG, "PUF Determinism Check: FAIL (R1: %s, R2: %s)", resp1, resp2);
    }
}

/**
 * @brief Generates a Strong PUF response by eliminating unreliable bits.
 * @details Implements the response construction described by Vatajelu et al.:
 * "By eliminating these bits [unreliable] from the PUF response, its reliability is greatly improved".
 * The challenge acts as a seed to select bits ONLY from the reliable regions defined by the mask.
 * @param challenge The input challenge bytes.
 * @param challenge_len Length of the challenge.
 * @param response Output buffer (at least 64 bytes) for the response string.
 */
void simulate_puf_response(const uint8_t *challenge, size_t challenge_len, char *response) {
    uint8_t hmac_output[32];
    uint8_t *key = (uint8_t *)sram_fingerprint;

    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&key_attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t hmac_key_id;
    psa_import_key(&key_attr, key, SRAM_PUF_SIZE_WORDS * 4, &hmac_key_id);

    size_t hmac_output_len = 0;
    psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;
    psa_mac_sign_setup(&mac_op, hmac_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_mac_update(&mac_op, challenge, challenge_len);
    psa_mac_sign_finish(&mac_op, hmac_output, sizeof(hmac_output), &hmac_output_len);
    psa_destroy_key(hmac_key_id);

    uint32_t selected_bits = 0;
    uint32_t total_bits = SRAM_PUF_SIZE_WORDS * 32;
    uint32_t iterator_seed = 0;
    memcpy(&iterator_seed, hmac_output, sizeof(uint32_t));
    uint32_t current_bit_idx = iterator_seed % total_bits;
    
    for (int k = 0; k < RESPONSE_BITS; k++) {
        bool bit_found = false;
        
        for (int scan = 0; scan < total_bits; scan++) {
            uint32_t word_idx = current_bit_idx / 32;
            uint32_t bit_offset = current_bit_idx % 32;
            
            if ((reliability_mask[word_idx] >> bit_offset) & 1) {
                uint32_t bit_val = (sram_fingerprint[word_idx] >> bit_offset) & 1;
                selected_bits = (selected_bits << 1) | bit_val;
                
                current_bit_idx = (current_bit_idx + 1) % total_bits;
                bit_found = true;
                break;
            }
            
            current_bit_idx = (current_bit_idx + 1) % total_bits;
        }
        
        if (!bit_found) {
            ESP_LOGE(TAG, "Critical: Not enough reliable bits in PUF!");
            break;
        }
    }
    
    snprintf(response, 64, "R%08" PRIX32, selected_bits);
}

/**
 * @brief Thread-safely retrieves the current node's IPv4 address as a string.
 * @param ip_buf A character buffer to store the retrieved IP address.
 * @param buf_size The size of the provided ip_buf.
 * @return void
 */
void get_my_ip(char* ip_buf, size_t buf_size) {
    esp_netif_ip_info_t ip_info;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif != NULL && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        esp_ip4addr_ntoa(&ip_info.ip, ip_buf, buf_size);
    } else {
        strncpy(ip_buf, "0.0.0.0", buf_size);
    }
}

/**
 * @brief Thread-safely retrieves the current node's unique ID (which is its IP address).
 * @param id_buf A character buffer to store the retrieved node ID.
 * @param buf_size The size of the provided id_buf.
 * @return void
 */
void get_my_node_id(char* id_buf, size_t buf_size) {
    get_my_ip(id_buf, buf_size);
}

/**
 * @brief Thread-safely retrieves the current node's MAC address as a string.
 * @param mac_buf A character buffer to store the retrieved MAC address (e.g., "XX:XX:XX:XX:XX:XX").
 * @param buf_size The size of the provided mac_buf (at least MAC_ADDR_STR_LEN).
 * @return void
 */
void get_my_mac(char* mac_buf, size_t buf_size) {
    if (buf_size < MAC_ADDR_STR_LEN) {
        ESP_LOGE(TAG, "Buffer too small for MAC address in get_my_mac");
        if (buf_size > 0) mac_buf[0] = '\0';
        return;
    }
    uint8_t mac_addr_raw[6];
    esp_read_mac(mac_addr_raw, ESP_MAC_WIFI_STA);
    snprintf(mac_buf, buf_size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_addr_raw[0], mac_addr_raw[1], mac_addr_raw[2],
             mac_addr_raw[3], mac_addr_raw[4], mac_addr_raw[5]);
}

/**
 * @brief Generates a cryptographically secure random nonce.
 * @param nonce_buffer A pointer to the buffer where the random bytes will be stored.
 * @param size The number of random bytes to generate.
 * @return void
 */
void generate_nonce(uint8_t* nonce_buffer, size_t size) {
    esp_fill_random(nonce_buffer, size);
}

/**
 * @brief Converts an array of bytes to its hexadecimal string representation.
 * @param src A pointer to the source byte array.
 * @param dest A character buffer to store the resulting hexadecimal string. Its size
 * must be at least (size * 2 + 1).
 * @param size The number of bytes in the source array.
 * @return void
 */
void bytes_to_hex(const uint8_t* src, char* dest, size_t size) {
    for (size_t i = 0; i < size; i++) {
        sprintf(dest + (i * 2), "%02x", src[i]);
    }
}

/**
 * @brief Converts a hexadecimal string to an array of bytes.
 * @param src The source null-terminated hexadecimal string.
 * @param dest A pointer to the destination byte array. Its size must be at least (strlen(src) / 2).
 * @param size The number of bytes to convert.
 * @return void
 */
void hex_to_bytes(const char* src, uint8_t* dest, size_t size) {
    for (size_t i = 0; i < size; i++) {
        sscanf(src + (i * 2), "%2hhx", &dest[i]);
    }
}

/**
 * @brief Generates a cryptographically secure random number within a specified range.
 * @details Uses rejection sampling to avoid modulo bias.
 * @param max The upper bound of the range (exclusive).
 * @return A securely generated random number as a uint32_t between 0 and max-1.
 */
uint32_t secure_rand_range(uint32_t max) {
    if (max == 0) {
        return 0;
    }
    uint32_t random_val;
    uint32_t rejection_threshold = UINT32_MAX - (UINT32_MAX % max);
    
    do {
        esp_fill_random(&random_val, sizeof(random_val));
    } while (random_val >= rejection_threshold);

    return random_val % max;
}