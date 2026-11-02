/* =============================
 * File: tls_auth.h
 * Description: Public interface for mutual TLS (mTLS) authentication.
 * ============================= */

#ifndef TLS_AUTH_H
#define TLS_AUTH_H

#include <stdbool.h>

/**
 * @brief Kind of TLS authentication.
 */
typedef enum {
    TLS_AUTH_FULL,     // full handshake (baseline "TLS")
    TLS_AUTH_PRIME,    // full handshake that keeps the session for a resumption; not measured
    TLS_AUTH_RESUMED,  // resumption of the kept session (baseline "TLS_RESUMED")
} tls_auth_mode_t;

/**
 * @brief Performs mutual TLS authentication with a target node.
 * @details This function acts as a client, attempting to establish a secure mTLS
 * connection to the target node's HTTPS server (on port 443). It uses the
 * node's unique, dynamically loaded certificates for authentication.
 * @param target_ip The IP address of the node to authenticate with.
 * @param mode Full handshake, prime run that keeps the session, or resumption of that session.
 * @return true if the TLS handshake and connection are successful (and, for a resumption, the
 * session was resumed), false otherwise.
 */
bool run_tls_authentication(const char* target_ip, tls_auth_mode_t mode);

#endif // TLS_AUTH_H
