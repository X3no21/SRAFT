/* =============================
 * File: rest_api.h
 * Description: Public interface for starting and stopping the REST API servers.
 * ============================= */

#ifndef REST_API_H
#define REST_API_H

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define DISCOVERY_PHASE_DURATION_MS 30000
#define MQTT_BROKER_IP "192.168.1.125"
#define MQTT_BROKER_PORT 8883

/**
 * @brief Starts both the HTTP and HTTPS REST API servers.
 * @details This function initializes the web servers and registers all the API endpoints
 * for interacting with the node.
 * @return void
 */
void rest_api_start(void);

/**
 * @brief Stops both the HTTP and HTTPS servers.
 * @details This function cleanly shuts down the web servers and frees their resources.
 * @return void
 */
void rest_api_stop(void);

#endif // REST_API_H