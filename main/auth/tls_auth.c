/* =============================
 * File: tls_auth.c
 * Description: Implements mutual TLS (mTLS) authentication using dynamically loaded certificates,
 * with a full handshake or with the resumption of a session (RFC 5077 session tickets).
 * ============================= */

// The start time of a session, used to tell a resumed session from a new one, is a private field.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "tls_auth.h"
#include "esp_tls.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "mbedtls/ssl.h"
#include "utility.h"
#include "raft_state.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "TLS_AUTH";

// Upper bound of the connection and handshake, so that a target that does not answer ends the run.
#define TLS_AUTH_TIMEOUT_MS 15000

// Session established by the last "prime" run, and the target it was established with.
static esp_tls_client_session_t *cached_session = NULL;
static char cached_session_target[INET_ADDRSTRLEN] = {0};

static void drop_cached_session(void) {
    if (cached_session) {
        esp_tls_free_client_session(cached_session);
        cached_session = NULL;
    }
    cached_session_target[0] = '\0';
}

/**
 * @brief Whether the handshake just completed on tls resumed the cached session.
 * @details A resumed TLS 1.2 session keeps the start time of the session it resumes, whereas a full
 * handshake starts a new session; the start times are compared.
 */
static bool session_was_resumed(esp_tls_t *tls) {
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)esp_tls_get_ssl_context(tls);
    if (!ssl || !cached_session) return false;
    mbedtls_ssl_session current;
    mbedtls_ssl_session_init(&current);
    bool resumed = mbedtls_ssl_get_session(ssl, &current) == 0 &&
                   current.start == cached_session->saved_session.start;
    mbedtls_ssl_session_free(&current);
    return resumed;
}

/**
 * @brief Performs TLS-based authentication.
 * @details Establishes a mutual TLS connection to verify device certificates. The free heap before
 * the run and, on a failure, its cause are reported to the monitoring server (AUTH_DIAG).
 * TLS_AUTH_FULL: full handshake, reported as "TLS".
 * TLS_AUTH_PRIME: full handshake whose session is kept for a later resumption with the same target;
 * not reported, since it only prepares the resumption.
 * TLS_AUTH_RESUMED: resumption of the session kept by the last prime run with the same target,
 * reported as "TLS_RESUMED"; it succeeds only if the session was actually resumed.
 * @param target_ip The IP address of the target node for authentication.
 * @param mode Full handshake, prime, or resumption.
 * @return true if authentication succeeds, false otherwise.
 */
bool run_tls_authentication(const char* target_ip, tls_auth_mode_t mode) {
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_mac(my_mac, sizeof(my_mac));
    const bool measured = mode != TLS_AUTH_PRIME;
    const char *scheme = mode == TLS_AUTH_RESUMED ? "TLS_RESUMED" : "TLS";

    uint32_t op_id = (uint32_t)esp_random();
    char event_msg[MAX_MESSAGE_SIZE];
    if (measured) {
        snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_START|auth_%s_%lu|%s|%s",
                 my_mac, op_id, my_mac, scheme);
        send_monitoring_tcp_event(event_msg);
    }

    size_t heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t heap_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    bool success = false;
    bool resumed = false;
    const char *cause = "none";
    int ret = 0, esp_tls_code = 0, esp_tls_flags = 0;
    esp_err_t last_err = ESP_OK;
    char url[128];
    snprintf(url, sizeof(url), "https://%s:443", target_ip);

    size_t ca_len, cert_len, key_len;
    char *ca_cert = read_embedded_file("/certs/ca.crt", &ca_len);
    char *device_cert = read_embedded_file("/certs/device.crt", &cert_len);
    char *device_key = read_embedded_file("/certs/device.key", &key_len);

    if (mode == TLS_AUTH_RESUMED && (!cached_session || strcmp(cached_session_target, target_ip) != 0)) {
        ESP_LOGE(TAG, "No session with %s to resume.", target_ip);
        cause = "no_session";
    } else if (!ca_cert || !device_cert || !device_key) {
        ESP_LOGE(TAG, "Failed to load embedded certificates for TLS auth.");
        cause = "certificates";
    } else {
        esp_tls_cfg_t cfg = {
            .cacert_buf = (const unsigned char *)ca_cert,
            .cacert_bytes = ca_len,
            .clientcert_buf = (const unsigned char *)device_cert,
            .clientcert_bytes = cert_len,
            .clientkey_buf = (const unsigned char *)device_key,
            .clientkey_bytes = key_len,
            .skip_common_name = true,
            .timeout_ms = TLS_AUTH_TIMEOUT_MS,
            .client_session = mode == TLS_AUTH_RESUMED ? cached_session : NULL,
        };

        esp_tls_t *tls = esp_tls_init();
        if (tls) {
            ret = esp_tls_conn_http_new_sync(url, &cfg, tls);
            if (ret == 1) {
                if (mode == TLS_AUTH_RESUMED) {
                    resumed = session_was_resumed(tls);
                    success = resumed;
                    if (!resumed) {
                        cause = "not_resumed";
                        ESP_LOGW(TAG, "Connection to %s completed with a full handshake instead of a resumption.", target_ip);
                    }
                } else {
                    success = true;
                }
                if (mode == TLS_AUTH_PRIME) {
                    drop_cached_session();
                    cached_session = esp_tls_get_client_session(tls);
                    if (cached_session) {
                        strncpy(cached_session_target, target_ip, sizeof(cached_session_target) - 1);
                    } else {
                        success = false;
                        cause = "no_ticket";
                    }
                }
                if (success) ESP_LOGI(TAG, "mTLS connection successful to %s. Authentication passed.", target_ip);
            } else {
                esp_tls_error_handle_t err = NULL;
                if (esp_tls_get_error_handle(tls, &err) == ESP_OK && err) {
                    last_err = esp_tls_get_and_clear_last_error(err, &esp_tls_code, &esp_tls_flags);
                }
                cause = "handshake";
                ESP_LOGE(TAG, "mTLS connection failed to %s with code %d (esp_err 0x%x, stack err -0x%x, flags 0x%x).",
                         target_ip, ret, last_err, -esp_tls_code, esp_tls_flags);
            }
            esp_tls_conn_destroy(tls);
        } else {
            ESP_LOGE(TAG, "Failed to initialize TLS context.");
            cause = "context";
        }
    }
    // A session is resumed once: the next resumption needs a new prime run.
    if (mode == TLS_AUTH_RESUMED) drop_cached_session();

    free(ca_cert);
    free(device_cert);
    free(device_key);

    if (measured) {
        // Free heap before the run and cause of a failure, for the diagnosis of failed runs.
        snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_DIAG|auth_%s_%lu|%s|%s|heap_free=%u|heap_largest=%u|ret=%d|resumed=%d|esp_err=0x%x|stack_err=-0x%x|flags=0x%x",
                 my_mac, op_id, scheme, success ? "ok" : cause, (unsigned)heap_free, (unsigned)heap_largest, ret,
                 resumed ? 1 : 0, last_err, -esp_tls_code, esp_tls_flags);
        send_monitoring_tcp_event(event_msg);

        snprintf(event_msg, MAX_MESSAGE_SIZE, "AUTH_RESULT_EVENT|%d|auth_%s_%lu|%s|%s",
                 success ? 1 : 0, my_mac, op_id, my_mac, scheme);
        send_monitoring_tcp_event(event_msg);
    }
    return success;
}
