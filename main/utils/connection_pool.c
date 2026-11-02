/* =============================
 * File: connection_pool.c
 * Description: Manages a pool of unified, dynamic, bidirectional TCP connections to peer nodes.
 * ============================= */

#include "esp_heap_caps.h"
#include "connection_pool.h"
#include "raft_state.h"
#include "utility.h"
#include "esp_log.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>
#include <stdlib.h>
#include <lwip/sockets.h>
#include <sys/select.h>
#include <fcntl.h>

static const char *TAG = "CONN_POOL";

typedef enum {
    CONN_STATE_DISCONNECTED,
    CONN_STATE_CONNECTING,
    CONN_STATE_CONNECTED
} connection_state_e;

typedef struct {
    char peer_ip[INET_ADDRSTRLEN];
    int sock_fd;
    connection_state_e state;
    bool is_initiator;
    TickType_t last_reconnect_attempt;
    uint32_t next_reconnect_delay_ms;
    // Allocated only while part of a message is waiting for the rest, so that idle peers take no buffer.
    char *rx_buffer;
    int rx_len;
} peer_connection_t;

#define PEER_RX_BUFFER_SIZE (MAX_MESSAGE_SIZE * 2)
// How long a message may wait for room in the send buffer of a peer before the connection is reset.
#define PEER_SEND_TIMEOUT_MS 3000
// A silent peer is probed after 5 s and declared dead after 3 probes 2 s apart.
#define PEER_KEEPALIVE_IDLE_S 5
#define PEER_KEEPALIVE_INTERVAL_S 2
#define PEER_KEEPALIVE_COUNT 3

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    // Sized to the message: a fixed buffer of MAX_MESSAGE_SIZE for every queued message wastes the heap.
    char message[];
} outgoing_message_t;

static peer_connection_t* connection_pool = NULL;
static int pool_size = 0;
static char my_ip[INET_ADDRSTRLEN];

static SemaphoreHandle_t pool_mutex = NULL;
static QueueHandle_t outgoing_message_queue = NULL;
static QueueHandle_t self_message_queue = NULL;
static message_handler_callback_t message_handler = NULL;

static TaskHandle_t listener_task_handle = NULL;
static TaskHandle_t manager_task_handle = NULL;
static TaskHandle_t io_task_handle = NULL;
static TaskHandle_t self_handler_task_handle = NULL;

#define TAKE_POOL_MUTEX(func_name) do { \
    /** ESP_LOGD("CONN_POOL_MUTEX", "Attempting to take lock in %s", func_name); **/ \
    xSemaphoreTake(pool_mutex, portMAX_DELAY); \
    /** ESP_LOGD("CONN_POOL_MUTEX", ">> Lock TAKEN in %s", func_name); **/ \
} while(0)

#define GIVE_POOL_MUTEX(func_name) do { \
    /** ESP_LOGD("CONN_POOL_MUTEX", "<< Lock GIVEN in %s", func_name); **/ \
    xSemaphoreGive(pool_mutex); \
} while(0)

/**
 * @brief Safely closes a peer's connection and resets its state.
 * @details This helper function ensures that a peer's connection is cleanly terminated.
 * It closes the socket file descriptor if valid, sets it to -1, resets the connection
 * state to CONN_STATE_DISCONNECTED, and clears the receive buffer length.
 * @param p A pointer to the peer_connection_t object to reset.
 * @return void
 */
static void close_peer_connection(peer_connection_t* p) {
    if (p->sock_fd >= 0) {
        // Abortive close: the data still queued for a peer that has failed is dropped at once, instead of
        // being kept for retransmission while the connection is closed.
        struct linger lg = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(p->sock_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        close(p->sock_fd);
        ESP_LOGI(TAG, "Closed connection with %s (socket %d)", p->peer_ip, p->sock_fd);
    }
    p->sock_fd = -1;
    p->state = CONN_STATE_DISCONNECTED;
    p->rx_len = 0;
    free(p->rx_buffer);
    p->rx_buffer = NULL;
}

/**
 * @brief Options of a connection with a peer: no Nagle delay, and TCP keepalive, so that a peer that fails
 * without closing the connection (power loss, crash) is detected within seconds and the data queued for it
 * does not accumulate in memory.
 */
static void configure_peer_socket(int sock) {
    int optval = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
    int idle = PEER_KEEPALIVE_IDLE_S, interval = PEER_KEEPALIVE_INTERVAL_S, count = PEER_KEEPALIVE_COUNT;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
}

/**
 * @brief Sets a socket to non-blocking mode.
 * @param sock The socket file descriptor.
 */
static void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        ESP_LOGE(TAG, "Failed to get socket flags");
        return;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        ESP_LOGE(TAG, "Failed to set socket to non-blocking");
    }
}

/**
 * @brief Finds a peer in the connection pool by its IP address.
 * @details This is a non-thread-safe helper function that iterates through the global
 * connection pool array. It must be called only when the pool_mutex is held.
 * @param ip The null-terminated IP address string of the peer to find.
 * @return A pointer to the peer_connection_t object if found, NULL otherwise.
 */
static peer_connection_t* find_peer_by_ip(const char* ip) {
    for (int i = 0; i < pool_size; i++) {
        if (strcmp(connection_pool[i].peer_ip, ip) == 0) {
            return &connection_pool[i];
        }
    }
    return NULL;
}

/**
 * @brief Task to handle internal messages sent to the node itself.
 * @details This task reads from a dedicated queue for self-messages, bypassing
 * the network stack entirely. It calls the main message handler asynchronously,
 * ensuring that self-communication is efficient and free of network race conditions.
 * @param pvParameters Unused task parameters.
 */
static void self_message_handler_task(void *pvParameters) {
    outgoing_message_t* msg;
    ESP_LOGI(TAG, "Self-message handler task started.");
    while (1) {
        if (xQueueReceive(self_message_queue, &msg, portMAX_DELAY) == pdTRUE) {
            if (message_handler) {
                message_handler(msg->target_ip, msg->message);
            }
            free(msg);
        }
    }
}

/**
 * @brief A background task that manages OUTGOING connection attempts.
 * @details This task periodically iterates through the connection pool. For each peer that
 * this node is responsible for initiating a connection with (is_initiator == true),
 * it checks if the connection is down. If so, it attempts to connect using an
 * exponential backoff strategy to avoid overwhelming the network or the remote peer
 * on repeated failures.
 * @param pvParameters Unused task parameters.
 * @return void
 */
static void connection_manager_task(void *pvParameters) {
    ESP_LOGI(TAG, "Connection manager task started.");
    char ips_to_connect[MAX_PEERS][INET_ADDRSTRLEN];
    int connect_count = 0;
 
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000)); 

        connect_count = 0;
        TAKE_POOL_MUTEX(__FUNCTION__);
        for (int i = 0; i < pool_size && connect_count < MAX_PEERS; i++) {
            peer_connection_t* p = &connection_pool[i];
            if (p->is_initiator && p->state == CONN_STATE_DISCONNECTED) {
                if (xTaskGetTickCount() - p->last_reconnect_attempt > pdMS_TO_TICKS(p->next_reconnect_delay_ms)) {
                    strncpy(ips_to_connect[connect_count], p->peer_ip, INET_ADDRSTRLEN - 1);
                    ips_to_connect[connect_count][INET_ADDRSTRLEN - 1] = '\0';
                    connect_count++;

                    p->state = CONN_STATE_CONNECTING;
                    p->last_reconnect_attempt = xTaskGetTickCount();
                }
            }
        }
        GIVE_POOL_MUTEX(__FUNCTION__);

        if (connect_count > 0) {
            ESP_LOGI(TAG, "Found %d peer(s) to connect to in this cycle.", connect_count);
        }

        for (int i = 0; i < connect_count; i++) {
            const char* peer_ip = ips_to_connect[i];
            ESP_LOGI(TAG, "Attempting to connect to peer %s...", peer_ip);

            struct sockaddr_in dest_addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
            inet_pton(AF_INET, peer_ip, &dest_addr.sin_addr);

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                ESP_LOGE(TAG, "Failed to create socket for %s", peer_ip);
                TAKE_POOL_MUTEX(__FUNCTION__);
                peer_connection_t* p = find_peer_by_ip(peer_ip);
                if (p) p->state = CONN_STATE_DISCONNECTED;
                GIVE_POOL_MUTEX(__FUNCTION__);
                continue; 
            }

            if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == 0) {
                ESP_LOGI(TAG, "Successfully connected to peer %s on socket %d.", peer_ip, sock);
                configure_peer_socket(sock);
                set_nonblocking(sock);

                TAKE_POOL_MUTEX(__FUNCTION__);
                peer_connection_t* p = find_peer_by_ip(peer_ip);
                if (p) {
                    if (p->sock_fd >= 0 && p->sock_fd != sock) close(p->sock_fd);
                    p->rx_len = 0;
                    free(p->rx_buffer);
                    p->rx_buffer = NULL;
                    p->sock_fd = sock;
                    p->state = CONN_STATE_CONNECTED;
                    p->next_reconnect_delay_ms = RECONNECT_BASE_INTERVAL_MS;
                } else {
                    close(sock);
                }
                GIVE_POOL_MUTEX(__FUNCTION__);
            } else {
                close(sock);
                TAKE_POOL_MUTEX(__FUNCTION__);
                peer_connection_t* p = find_peer_by_ip(peer_ip);
                if (p) {
                    p->state = CONN_STATE_DISCONNECTED;
                    p->next_reconnect_delay_ms *= 2;
                    if (p->next_reconnect_delay_ms > (RECONNECT_BASE_INTERVAL_MS * 10)) {
                        p->next_reconnect_delay_ms = (RECONNECT_BASE_INTERVAL_MS * 10);
                    }
                    ESP_LOGW(TAG, "Failed to connect to %s. Retrying in %lu ms.", p->peer_ip, p->next_reconnect_delay_ms);
                }
                GIVE_POOL_MUTEX(__FUNCTION__);
            }
        }
    }
}

/**
 * @brief Task that handles INCOMING connections.
 * @details This task creates a single listening socket for the entire node. It enters an
 * infinite loop to accept incoming connections from peers that, according to the
 * deterministic rule (lower IP connects to higher IP), are responsible for initiating
 * communication. When a valid connection is accepted, the new socket is integrated
 * into the connection pool.
 * @param pvParameters Task parameters (unused).
 * @return void
 */
static void connection_listener_task(void *pvParameters) {
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY), .sin_port = htons(PORT) };
    
    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Listener failed to bind. Deleting task.");
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }
    
    if (listen_sock < 0 || listen(listen_sock, RAFT_LISTEN_BACKLOG) != 0) {
        ESP_LOGE(TAG, "Listener failed to listen on port %d (errno %d). Deleting task.", PORT, errno);
        if (listen_sock >= 0) close(listen_sock);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "Connection listener started on port %d.", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            ESP_LOGE(TAG, "Failed to accept connection: %s", strerror(errno));
            // Do not spin on a persistent error (e.g., no memory): it would starve the other tasks.
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        configure_peer_socket(client_sock);
        set_nonblocking(client_sock);

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        
        ESP_LOGI(TAG, "Accepted connection from %s on socket %d", client_ip, client_sock);

        TAKE_POOL_MUTEX(__FUNCTION__);
        peer_connection_t* p = find_peer_by_ip(client_ip);
        if (p) {
            bool is_from_self = (strcmp(client_ip, my_ip) == 0);
             if (is_from_self) {
                if (p->sock_fd >= 0 && p->sock_fd != client_sock) {
                    close(p->sock_fd);
                }
                p->sock_fd = client_sock;
                p->rx_len = 0;
                free(p->rx_buffer);
                p->rx_buffer = NULL;
                p->state = CONN_STATE_CONNECTED;
                ESP_LOGI(TAG, "Loopback connection for self registered on socket %d", client_sock);
            } else if (!p->is_initiator) {
                if (p->sock_fd >= 0) close(p->sock_fd);
                p->sock_fd = client_sock;
                p->rx_len = 0;
                free(p->rx_buffer);
                p->rx_buffer = NULL;
                p->state = CONN_STATE_CONNECTED;
                p->next_reconnect_delay_ms = RECONNECT_BASE_INTERVAL_MS;
                ESP_LOGI(TAG, "Accepted and registered connection from %s on socket %d", client_ip, client_sock);
            } else {
                ESP_LOGW(TAG, "Rejected connection from %s, they are not supposed to initiate.", client_ip);
                close(client_sock);
            }
        } else {
            ESP_LOGW(TAG, "Accepted connection from unknown peer %s. Adding to pool.", client_ip);
            
            GIVE_POOL_MUTEX(__FUNCTION__);
            connection_pool_add_peer(client_ip);
            TAKE_POOL_MUTEX(__FUNCTION__);

            p = find_peer_by_ip(client_ip);
            if (p && !p->is_initiator) {
                p->sock_fd = client_sock;
                p->state = CONN_STATE_CONNECTED;
                p->next_reconnect_delay_ms = RECONNECT_BASE_INTERVAL_MS;
            } else {
                close(client_sock);
            }
        }
        GIVE_POOL_MUTEX(__FUNCTION__);
    }
}

/**
 * @brief Sends a whole message on a non-blocking socket, waiting while its send buffer is full.
 * @return true if every byte was sent within the timeout.
 */
static bool send_all(int sock, const char *buf, size_t len, uint32_t timeout_ms) {
    size_t sent = 0;
    TickType_t start = xTaskGetTickCount();
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if ((xTaskGetTickCount() - start) * portTICK_PERIOD_MS >= timeout_ms) return false;
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);
            struct timeval tv = { .tv_sec = 0, .tv_usec = 20000 };
            select(sock + 1, NULL, &write_fds, NULL, &tv);
            continue;
        }
        return false;
    }
    return true;
}

/**
 * @brief Unified task to handle all I/O using select().
 * @details This task is the I/O core of the connection pool. It uses select() to efficiently
 * monitor all active sockets for incoming data. It handles partial messages, reassembles
 * them, and passes complete messages to the upper layer via a callback. It also manages
 * a queue for sending outgoing messages. This single-task design is highly scalable and
 * avoids the high memory overhead of a task-per-connection model.
 * @param pvParameters Unused task parameters.
 */
static void message_io_task(void *pvParameters) {
    fd_set read_fds;
    struct timeval tv;
    
    while(1) {
        FD_ZERO(&read_fds);
        int max_fd = 0;

        TAKE_POOL_MUTEX(__FUNCTION__);
        for (int i = 0; i < pool_size; i++) {
            if (connection_pool[i].state == CONN_STATE_CONNECTED) {
                FD_SET(connection_pool[i].sock_fd, &read_fds);
                if (connection_pool[i].sock_fd > max_fd) {
                    max_fd = connection_pool[i].sock_fd;
                }
            }
        }
        GIVE_POOL_MUTEX(__FUNCTION__);
        
        // A complete message already in a buffer is delivered without waiting for new data.
        bool buffered_message = false;
        TAKE_POOL_MUTEX(__FUNCTION__);
        for (int i = 0; i < pool_size && !buffered_message; i++) {
            buffered_message = connection_pool[i].state == CONN_STATE_CONNECTED &&
                               connection_pool[i].rx_buffer && strchr(connection_pool[i].rx_buffer, '\n');
        }
        GIVE_POOL_MUTEX(__FUNCTION__);

        tv.tv_sec = 0;
        tv.tv_usec = buffered_message ? 0 : 1000;
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (activity < 0 && errno == EBADF) {
            ESP_LOGE(TAG, "Gracefully recovering from select() error: Bad file number.");
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        if (activity < 0) {
            ESP_LOGE(TAG, "select() error: %s", strerror(errno));
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (activity > 0 || buffered_message) {
            // Only this task uses the buffer, so it is allocated once instead of at every message.
            static char received_message[MAX_MESSAGE_SIZE];
            char sender_ip[INET_ADDRSTRLEN];
            bool message_ready = false;

            TAKE_POOL_MUTEX(__FUNCTION__);
            for (int i = 0; i < pool_size && !message_ready; i++) {
                peer_connection_t* p = &connection_pool[i];
                if (p->state != CONN_STATE_CONNECTED) continue;

                bool has_complete = p->rx_buffer && strchr(p->rx_buffer, '\n');
                if (!has_complete && activity > 0 && FD_ISSET(p->sock_fd, &read_fds)) {
                    if (!p->rx_buffer) {
                        p->rx_buffer = malloc(PEER_RX_BUFFER_SIZE);
                        if (!p->rx_buffer) continue;
                        p->rx_len = 0;
                        p->rx_buffer[0] = '\0';
                    }
                    int len = recv(p->sock_fd, p->rx_buffer + p->rx_len, PEER_RX_BUFFER_SIZE - p->rx_len - 1, 0);

                    if (len <= 0) {
                        ESP_LOGW(TAG, "Peer %s disconnected (recv returned %d).", p->peer_ip, len);
                        close_peer_connection(p);
                        continue;
                    }

                    p->rx_len += len;
                    p->rx_buffer[p->rx_len] = '\0';
                }

                char *msg_end = p->rx_buffer ? strchr(p->rx_buffer, '\n') : NULL;
                if (msg_end) {
                    *msg_end = '\0';

                    strncpy(received_message, p->rx_buffer, MAX_MESSAGE_SIZE - 1);
                    received_message[MAX_MESSAGE_SIZE - 1] = '\0';

                    strncpy(sender_ip, p->peer_ip, sizeof(sender_ip) - 1);
                    sender_ip[sizeof(sender_ip) - 1] = '\0';

                    message_ready = true;

                    p->rx_len -= (msg_end - p->rx_buffer + 1);
                    memmove(p->rx_buffer, msg_end + 1, p->rx_len);
                    p->rx_buffer[p->rx_len] = '\0';
                }
                if (p->rx_buffer && p->rx_len == 0) {
                    free(p->rx_buffer);
                    p->rx_buffer = NULL;
                }
            }
            GIVE_POOL_MUTEX(__FUNCTION__);

            if (message_ready && message_handler) {
                message_handler(sender_ip, received_message);
            }
        }

        outgoing_message_t *msg_to_send;
        while (xQueueReceive(outgoing_message_queue, &msg_to_send, 0) == pdTRUE) {
            int sock = -1;
            char peer_ip[INET_ADDRSTRLEN] = {0};
            TAKE_POOL_MUTEX(__FUNCTION__);
            peer_connection_t* p = find_peer_by_ip(msg_to_send->target_ip);
            if (p && p->state == CONN_STATE_CONNECTED) {
                sock = p->sock_fd;
                strncpy(peer_ip, p->peer_ip, sizeof(peer_ip) - 1);
            }
            GIVE_POOL_MUTEX(__FUNCTION__);

            if (sock < 0) {
                ESP_LOGW(TAG, "Could not send to %s, connection not ready. Message dropped.", msg_to_send->target_ip);
            } else {
                const char *text = msg_to_send->message;
                const char *newline = strchr(text, '\n');
                int shown = newline ? (int)(newline - text) : (int)strlen(text);
                if (send_all(sock, text, strlen(text), PEER_SEND_TIMEOUT_MS)) {
                    ESP_LOGI(TAG, "-> RPC SENT from %s to %s: %.*s", my_ip, peer_ip, shown, text);
                } else {
                    // A message sent in part would corrupt the stream, so the connection is closed and opened again.
                    ESP_LOGE(TAG, "Send to %s failed or timed out (errno %d), closing connection.", peer_ip, errno);
                    TAKE_POOL_MUTEX(__FUNCTION__);
                    peer_connection_t* q = find_peer_by_ip(peer_ip);
                    if (q && q->sock_fd == sock) close_peer_connection(q);
                    GIVE_POOL_MUTEX(__FUNCTION__);
                }
            }

            free(msg_to_send);
        }
    }
}

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
void connection_pool_start(char **peers, int num_peers, message_handler_callback_t handler) {
    if (pool_mutex != NULL) return; 

    pool_mutex = xSemaphoreCreateMutex();
    outgoing_message_queue = xQueueCreate(MESSAGE_QUEUE_LENGTH, sizeof(outgoing_message_t*));
    self_message_queue = xQueueCreate(MESSAGE_QUEUE_LENGTH, sizeof(outgoing_message_t*));
    message_handler = handler;
    get_my_ip(my_ip, sizeof(my_ip));

    connection_pool = malloc(sizeof(peer_connection_t) * num_peers);
    if (!connection_pool) {
        ESP_LOGE(TAG, "Failed to allocate memory for connection pool!");
        return;
    }

    pool_size = 0;
    for (int i = 0; i < num_peers; i++) {
        if (strcmp(peers[i], my_ip) == 0) continue;
        if (strcmp(peers[i], MONITORING_SERVER_IP) == 0) continue;
        
        peer_connection_t* p = &connection_pool[pool_size];
        memset(p, 0, sizeof(peer_connection_t));
        strncpy(p->peer_ip, peers[i], INET_ADDRSTRLEN - 1);
        p->sock_fd = -1;
        p->state = CONN_STATE_DISCONNECTED;
        p->next_reconnect_delay_ms = RECONNECT_BASE_INTERVAL_MS;
        p->is_initiator = (strcmp(my_ip, p->peer_ip) < 0);
        
        pool_size++;
    }
    
    if (xTaskCreate(connection_listener_task, "conn_listener", 4096, NULL, 5, &listener_task_handle) != pdPASS ||
        xTaskCreate(connection_manager_task, "conn_manager", 4096, NULL, 5, &manager_task_handle) != pdPASS ||
        xTaskCreate(message_io_task, "msg_io", 4608, NULL, 6, &io_task_handle) != pdPASS ||
        xTaskCreate(self_message_handler_task, "self_handler", 4096, NULL, 6, &self_handler_task_handle) != pdPASS) {
        ESP_LOGE(TAG, "Could not create the connection pool tasks (free heap %u, largest block %u).",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    }
    ESP_LOGI(TAG, "Unified connection pool service started for %d peers.", pool_size);
}

/**
 * @brief Dynamically adds a new peer to the connection pool.
 * @details This function is thread-safe and should be called by the discovery service.
 * @param peer_ip The IP address of the new peer to add.
 * @return void
 */
void connection_pool_add_peer(const char* peer_ip) {
    if (strcmp(peer_ip, my_ip) == 0) {
        return;
    }

    TAKE_POOL_MUTEX(__FUNCTION__);
    if (find_peer_by_ip(peer_ip) != NULL) {
        GIVE_POOL_MUTEX(__FUNCTION__);
        return;
    }

    peer_connection_t* new_pool = realloc(connection_pool, sizeof(peer_connection_t) * (pool_size + 1));
    if (!new_pool) {
        ESP_LOGE(TAG, "Failed to reallocate memory for new peer!");
        GIVE_POOL_MUTEX(__FUNCTION__);
        return;
    }
    connection_pool = new_pool;
    
    peer_connection_t* p = &connection_pool[pool_size];
    memset(p, 0, sizeof(peer_connection_t));
    strncpy(p->peer_ip, peer_ip, INET_ADDRSTRLEN - 1);
    p->sock_fd = -1;
    p->state = CONN_STATE_DISCONNECTED;
    p->next_reconnect_delay_ms = RECONNECT_BASE_INTERVAL_MS;
    p->is_initiator = (strcmp(my_ip, peer_ip) < 0);
    
    pool_size++;
    ESP_LOGI(TAG, "Dynamically added new peer %s. Pool size is now %d.", peer_ip, pool_size);
    GIVE_POOL_MUTEX(__FUNCTION__);
}

/**
 * @brief Dynamically removes a peer from the connection pool.
 * @param ip_to_remove The IP address of the peer to remove.
 */
void connection_pool_remove_peer(const char* ip_to_remove) {
    TAKE_POOL_MUTEX(__FUNCTION__);
    int found_index = -1;
    for (int i = 0; i < pool_size; i++) {
        if (strcmp(connection_pool[i].peer_ip, ip_to_remove) == 0) {
            found_index = i;
            break;
        }
    }

    if (found_index != -1) {
        ESP_LOGW(TAG, "Removing peer %s from connection pool.", ip_to_remove);
        close_peer_connection(&connection_pool[found_index]);

        for (int i = found_index; i < pool_size - 1; i++) {
            connection_pool[i] = connection_pool[i + 1];
        }
        pool_size--;
        
        if (pool_size > 0) {
            peer_connection_t* new_pool = realloc(connection_pool, sizeof(peer_connection_t) * pool_size);
            if (new_pool) {
                connection_pool = new_pool;
            }
        } else {
            free(connection_pool);
            connection_pool = NULL;
        }
    }
    GIVE_POOL_MUTEX(__FUNCTION__);
}

/**
 * @brief Queues a message to be sent to a target peer.
 * @param target_ip The IP address of the destination node.
 * @param message The null-terminated string message to send.
 * @return true if the message was successfully queued, false otherwise.
 */
bool connection_pool_send(const char* target_ip, const char* message) {
    if (!outgoing_message_queue || !self_message_queue) return false;
    
    size_t msg_len = strnlen(message, MAX_MESSAGE_SIZE - 1);
    outgoing_message_t *msg = malloc(sizeof(outgoing_message_t) + msg_len + 1);
    if (!msg) {
        ESP_LOGE(TAG, "Failed to allocate memory for outgoing message.");
        return false;
    }

    if (strcmp(target_ip, my_ip) == 0) {
        ESP_LOGI(TAG, "-> SELF RPC ROUTED from %s to %s: %s", my_ip, target_ip, message);

        strncpy(msg->target_ip, target_ip, INET_ADDRSTRLEN - 1);
        msg->target_ip[INET_ADDRSTRLEN - 1] = '\0';
        memcpy(msg->message, message, msg_len);
        msg->message[msg_len] = '\0';

        if (xQueueSend(self_message_queue, &msg, pdMS_TO_TICKS(100)) != pdPASS) {
            ESP_LOGE(TAG, "Failed to queue self-message. Queue is full.");
            free(msg);
            return false;
        }
        return true;
    }

    strncpy(msg->target_ip, target_ip, INET_ADDRSTRLEN - 1);
    msg->target_ip[INET_ADDRSTRLEN - 1] = '\0';
    memcpy(msg->message, message, msg_len);
    msg->message[msg_len] = '\0';
    
    if (xQueueSend(outgoing_message_queue, &msg, pdMS_TO_TICKS(100)) != pdPASS) {
        ESP_LOGE(TAG, "Failed to queue message for %s. Queue is full.", target_ip);
        free(msg);
        return false;
    }
 
    return true;
}

/**
 * @brief Deinitializes the connection pool, stopping all tasks and closing sockets.
 * @return void
 */
void connection_pool_deinit(void) {
    if (listener_task_handle) vTaskDelete(listener_task_handle);
    if (manager_task_handle) vTaskDelete(manager_task_handle);
    if (io_task_handle) vTaskDelete(io_task_handle);
    if (self_handler_task_handle) vTaskDelete(self_handler_task_handle);
    
    if (pool_mutex) {
        TAKE_POOL_MUTEX(__FUNCTION__);
        for (int i = 0; i < pool_size; i++) {
            close_peer_connection(&connection_pool[i]);
        }
        free(connection_pool);
        connection_pool = NULL;
        pool_size = 0;
        GIVE_POOL_MUTEX(__FUNCTION__);
        vSemaphoreDelete(pool_mutex);
        pool_mutex = NULL;
    }
    
    if (outgoing_message_queue) vQueueDelete(outgoing_message_queue);
    if (self_message_queue) vQueueDelete(self_message_queue);
    
    ESP_LOGI(TAG, "Connection pool deinitialized.");
}