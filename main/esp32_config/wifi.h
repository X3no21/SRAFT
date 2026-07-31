/* =============================
 * File: wifi.h
 * Description: Public interface for Wi-Fi station mode connection.
 * ============================= */

#ifndef WIFI_H
#define WIFI_H

#include "freertos/FreeRTOS.h"

/* Set these to the credentials of the WiFi network shared by the ESP32 nodes
 * and the Raspberry Pi. They are compiled into the firmware binary, so the
 * firmware must be rebuilt and reflashed after any change. */
#define WIFI_SSID           "YOUR_WIFI_SSID"
#define WIFI_PASS           "YOUR_WIFI_PASSWORD"
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

#endif // WIFI_H