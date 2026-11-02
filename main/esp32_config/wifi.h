/* =============================
 * File: wifi.h
 * Description: Public interface for Wi-Fi station mode connection.
 * ============================= */

#ifndef WIFI_H
#define WIFI_H

#include "freertos/FreeRTOS.h"

/* Credentials of the WiFi network shared by the ESP32 nodes and the Raspberry Pi.
 * Put the real ones in wifi_credentials.h (gitignored), next to this file:
 *     #define WIFI_SSID "..."
 *     #define WIFI_PASS "..."
 * They are compiled into the firmware binary, so the firmware must be rebuilt
 * and reflashed after any change. */
#if __has_include("wifi_credentials.h")
#include "wifi_credentials.h"
#endif
#ifndef WIFI_SSID
#define WIFI_SSID           "YOUR_WIFI_SSID"
#endif
#ifndef WIFI_PASS
#define WIFI_PASS           "YOUR_WIFI_PASSWORD"
#endif
#define WIFI_CONNECTED_BIT  BIT0

/**
 * @brief Initializes the Wi-Fi station, connects to the configured AP, and waits for an IP address.
 * @details This is a blocking function. It initializes the underlying TCP/IP stack and event loop,
 * configures the Wi-Fi with the hardcoded SSID and password, and does not return until
 * a successful connection is established and an IP address is obtained. Upon connection,
 * it starts background services like discovery and monitoring heartbeats.
 * @return void
 */
void wifi_init_sta(void);

/**
 * @brief Disconnects the device from the network and keeps it disconnected. For tests only: it simulates
 * an abrupt failure, since the device stops answering without notifying anyone.
 */
void wifi_simulate_failure(void);

#endif // WIFI_H