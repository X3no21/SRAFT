/* =============================
 * File: tls_auth.h
 * Description: Public interface for mutual TLS (mTLS) authentication.
 * ============================= */

#ifndef TLS_AUTH_H
#define TLS_AUTH_H

#include <stdbool.h>

/**
 * @brief Performs mutual TLS authentication with a target node.
 * @details This function acts as a client, attempting to establish a secure mTLS
 * connection to the target node's HTTPS server (on port 443). It uses the
 * node's unique, dynamically loaded certificates for authentication.
 * @param target_ip The IP address of the node to authenticate with.
 * @return true if the TLS handshake and connection are successful, false otherwise.
 */
bool run_tls_authentication(const char* target_ip);

#endif // TLS_AUTH_H