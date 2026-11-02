/* =============================
 * File: mqtts_auth.h
 * Description: Public interface for authentication via MQTTS connection.
 * ============================= */

#ifndef MQTTS_AUTH_H
#define MQTTS_AUTH_H

#include "freertos/FreeRTOS.h"
#include <stdbool.h>

static const int CONNECTED_BIT = BIT0;
static const int MSG_RECEIVED_BIT = BIT1;

/**
 * @brief Performs authentication by connecting to an MQTTS broker.
 * @details This function establishes a mutual TLS (mTLS) connection to the specified
 * MQTTS broker using the node's unique certificates. A successful connection is
 * considered a successful authentication. It also performs an optional end-to-end
 * message check for further validation.
 * @param broker_uri The full URI of the MQTTS broker (e.g., "mqtts://192.168.1.100:8883").
 * @param target_ip The IP of the target node for the end-to-end message check.
 * @return true if the connection and message exchange are successful, false otherwise.
 */
bool run_mqtts_authentication(const char* broker_uri, const char* target_ip);

/**
 * @brief Starts the persistent background MQTTS auth responder for this node.
 * @details Without this responder running on the target node, run_mqtts_authentication()
 * has no peer to answer its end-to-end challenge and always times out. Returns when the
 * responder is subscribed to its request topic, or after a timeout. Safe to call multiple times.
 * @return true if the responder is subscribed.
 */
bool mqtts_auth_start_responder(void);

/**
 * @brief Stops the MQTTS auth responder and releases its connection and memory.
 * @details The responder serves only the MQTTS baseline, so it runs only while that baseline is measured.
 */
void mqtts_auth_stop_responder(void);

#endif // MQTTS_AUTH_H