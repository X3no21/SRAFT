/* =============================
 * File: connection_pool.h
 * Description: Public interface for a unified, dynamic, bidirectional TCP connection pool.
 * ============================= */

#ifndef CONNECTION_POOL_H
#define CONNECTION_POOL_H

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <stdbool.h>
#include <arpa/inet.h>

#define MAX_PEERS 32
#define RECONNECT_BASE_INTERVAL_MS 5000
#define MESSAGE_QUEUE_LENGTH 128
#define MAX_MESSAGE_SIZE 2048

typedef void (*message_handler_callback_t)(const char* from_ip, const char* message);

/**
 * @brief Initializes and starts the unified connection pool service.
 * @details This function sets up the entire connection pool module based on a provided
 * peer list. It allocates memory for all peers, determines their roles (initiator
 * or acceptor), and starts the background tasks for listening, connecting, and I/O.
 * @param peers An array of C-strings containing the IP addresses of all nodes in the cluster.
 * @param num_peers The total number of peers in the array.
 * @param handler A function pointer to the callback that will be invoked when a complete
 * message is received from a peer.
 * @return void
 */
void connection_pool_start(char **peers, int num_peers, message_handler_callback_t handler);

/**
 * @brief Dynamically adds a new peer to the connection pool.
 * @details This function is thread-safe and should be called by the discovery service.
 * @param peer_ip The IP address of the new peer to add.
 * @return void
 */
void connection_pool_add_peer(const char* peer_ip);

/**
 * @brief Dynamically removes a peer from the connection pool.
 * @param ip_to_remove The IP address of the peer to remove.
 */
void connection_pool_remove_peer(const char* ip_to_remove);

/**
 * @brief Queues a message to be sent to a target peer.
 * @param target_ip The IP address of the destination node.
 * @param message The null-terminated string message to send.
 * @return true if the message was successfully queued, false otherwise.
 */
bool connection_pool_send(const char* target_ip, const char* message);

/**
 * @brief Deinitializes the connection pool, stopping all tasks and closing sockets.
 * @return void
 */
void connection_pool_deinit(void);

#endif // CONNECTION_POOL_H