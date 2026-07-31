/* =============================
 * File: tls_auth.c
 * Description: Implements mutual TLS (mTLS) authentication using dynamically loaded certificates.
 * ============================= */

#include "tls_auth.h"
#include "esp_tls.h"
#include "esp_log.h"
#include "utility.h"
#include "raft_state.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "TLS_AUTH";

/**
 * @brief Performs TLS-based authentication.
 * @details Establishes a mutual TLS connection to verify device certificates.
 * @param target_ip The IP address of the target node for authentication.
 * @return true if authentication succeeds, false otherwise.
 */
bool run_tls_authentication(const char* target_ip) {
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_mac(my_mac, sizeof(my_mac));

    uint32_t op_id = (uint32_t)esp_random();
    char event_msg[MAX_MESSAGE_SIZE];
    snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_START|auth_%s_%lu|%s|TLS", 
             my_mac, op_id, my_mac);
    send_monitoring_tcp_event(event_msg);

    bool success = false;
    char url[128];
    snprintf(url, sizeof(url), "https://%s:443", target_ip);

    size_t ca_len, cert_len, key_len;
    char *ca_cert = read_embedded_file("/certs/ca.crt", &ca_len);
    char *device_cert = read_embedded_file("/certs/device.crt", &cert_len);
    char *device_key = read_embedded_file("/certs/device.key", &key_len);

    if (!ca_cert || !device_cert || !device_key) {
        ESP_LOGE(TAG, "Failed to load embedded certificates for TLS auth.");
        if (ca_cert) free(ca_cert);
        if (device_cert) free(device_cert);
        if (device_key) free(device_key);
        return false;
    }

    esp_tls_cfg_t cfg = {
        .cacert_buf = (const unsigned char *)ca_cert,
        .cacert_bytes = ca_len,
        .clientcert_buf = (const unsigned char *)device_cert,
        .clientcert_bytes = cert_len,
        .clientkey_buf = (const unsigned char *)device_key,
        .clientkey_bytes = key_len,
        .skip_common_name = true,
    };

    esp_tls_t *tls = esp_tls_init();
    if (tls) {
        int ret = esp_tls_conn_http_new_sync(url, &cfg, tls);
        if (ret == 1) {
            ESP_LOGI(TAG, "mTLS connection successful to %s. Authentication passed.", target_ip);
            success = true;
        } else {
            ESP_LOGE(TAG, "mTLS connection failed to %s with code %d. Authentication failed.", target_ip, ret);
        }
        esp_tls_conn_destroy(tls);
    } else {
        ESP_LOGE(TAG, "Failed to initialize TLS context.");
    }

    free(ca_cert);
    free(device_cert);
    free(device_key);

    snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_RESULT_EVENT|%d|auth_%s_%lu|%s|TLS", 
             success ? 1 : 0, my_mac, op_id, my_mac);
    send_monitoring_tcp_event(event_msg);
    return success;
}