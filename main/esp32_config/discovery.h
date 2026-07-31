/* =============================
 * File: discovery.h
 * Description: Public interface for the peer discovery service.
 * ============================= */

#ifndef DISCOVERY_H
#define DISCOVERY_H

#include <stddef.h>
#include "raft_state.h"

#define DISCOVERY_BROADCAST_PORT 41234
#define MAX_DISCOVERED_PEERS 32

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[MAC_ADDR_STR_LEN];
} discovered_peer_info_t;

/**
 * @brief Defines the callback function type for new peer notifications.
 */
typedef void (*new_peer_discovered_callback_t)(const char* peer_ip);

/**
 * @brief Registers a callback for new peer notifications after the service has started.
 */
void discovery_register_new_peer_callback(new_peer_discovered_callback_t on_new_peer);

/**
 * @brief Starts the background discovery service.
 * @details This function initializes the peer list and creates a task to listen for UDP
 * broadcast announcements. It registers a callback that will be invoked for each new, unique peer.
 * @param on_new_peer The callback function to call when a new peer is discovered.
 * @return void
 */
void discovery_service_start(new_peer_discovered_callback_t on_new_peer);

/**
 * @brief Sends a UDP broadcast message to announce this node's presence.
 * @return void
 */
void discovery_send_broadcast(void);

/**
 * @brief Retrieves a memory-managed copy of the currently discovered peer list.
 * @param[out] peer_count A pointer to an integer where the number of discovered peers will be stored.
 * @return A dynamically allocated array of C-strings. The caller is responsible for freeing it.
 */
char** discovery_get_peer_list_copy(int* peer_count);

/**
 * @brief Retrieves the MAC address associated with a given IP address from the discovery list.
 * @param ip The IP address to search for.
 * @param mac_buf Buffer to store the found MAC address (must be at least MAC_ADDR_STR_LEN).
 * @param buf_size Size of the mac_buf.
 * @return true if the IP was found and the MAC was copied, false otherwise.
 */
bool discovery_get_mac_for_ip(const char* ip, char* mac_buf, size_t buf_size);

#endif // DISCOVERY_H