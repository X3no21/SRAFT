/* =============================
 * File: discovery.c
 * Description: Implements a passive peer discovery service using UDP broadcasts.
 * ============================= */

#include "discovery.h"
#include "utility.h"
#include "raft_state.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <lwip/sockets.h>


static const char *TAG = "DISCOVERY_SERVICE";

static discovered_peer_info_t discovered_peer_list[MAX_DISCOVERED_PEERS];
static int discovered_peer_count = 0;
static SemaphoreHandle_t peer_list_mutex = NULL;
static new_peer_discovered_callback_t on_new_peer_callback = NULL;

/**
 * @brief Thread-safely adds a unique peer IP to the internal discovery list.
 * @param ip The IP address string of the peer to add.
 * @param mac The MAC address string of the peer.
 * @return void
 */
static void add_discovered_peer(const char* ip, const char* mac) {
    if (xSemaphoreTake(peer_list_mutex, portMAX_DELAY) == pdTRUE) {
        bool already_exists = false;
        for (int i = 0; i < discovered_peer_count; i++) {
            if (strcmp(discovered_peer_list[i].ip, ip) == 0 ||
                strcmp(discovered_peer_list[i].mac, mac) == 0) {
                already_exists = true;
                break;
            }
        }
        
        if (!already_exists && discovered_peer_count < MAX_DISCOVERED_PEERS) {
            strncpy(discovered_peer_list[discovered_peer_count].ip, ip, INET_ADDRSTRLEN - 1);
            discovered_peer_list[discovered_peer_count].ip[INET_ADDRSTRLEN - 1] = '\0';
            strncpy(discovered_peer_list[discovered_peer_count].mac, mac, MAC_ADDR_STR_LEN - 1);
            discovered_peer_list[discovered_peer_count].mac[MAC_ADDR_STR_LEN - 1] = '\0';

            discovered_peer_count++;
            ESP_LOGI(TAG, "Peer added: IP=%s, MAC=%s (Total: %d)", ip, mac, discovered_peer_count);

            if (on_new_peer_callback) {
                on_new_peer_callback(ip);
            }
        }
        xSemaphoreGive(peer_list_mutex);
    }
}

void discovery_register_new_peer_callback(new_peer_discovered_callback_t on_new_peer) {
    if (xSemaphoreTake(peer_list_mutex, portMAX_DELAY) == pdTRUE) {
        on_new_peer_callback = on_new_peer;
        xSemaphoreGive(peer_list_mutex);
    }
}

/**
 * @brief A background task that listens for UDP broadcast announcements from other peers.
 * @param pvParameters Unused task parameters.
 */
static void discovery_listener_task(void *pvParameters) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Listener task failed to create socket. Deleting task.");
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DISCOVERY_BROADCAST_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Listener task failed to bind socket. Deleting task.");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "UDP listener task started. Listening for peer announcements.");
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));

    while(1) {
        char buffer[128];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&from_addr, &from_len);
        if (len > 0) {
            buffer[len] = '\0';
            
            char* saveptr;
            char* command = strtok_r(buffer, ":", &saveptr);
            if (command && strcmp(command, "RAFT_HELLO") == 0) {
                char* received_ip = strtok_r(NULL, ":", &saveptr);
                char* received_mac = strtok_r(NULL, "", &saveptr);
                if (received_ip && received_mac && (strcmp(received_ip, my_ip) != 0)) {
                    add_discovered_peer(received_ip, received_mac);
                }
            }
        }
    }
}

/**
 * @brief Starts the background discovery service.
 * @details This function initializes the peer list and creates a task to listen for UDP
 * broadcast announcements from other nodes on the network. It should be called once
 * after the node has a valid IP address.
 * @return void
 */
void discovery_service_start(new_peer_discovered_callback_t on_new_peer) {
    if (peer_list_mutex == NULL) {
        peer_list_mutex = xSemaphoreCreateMutex();
    }
    
    on_new_peer_callback = on_new_peer;
    
    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));
    add_discovered_peer(my_ip, my_mac);

    xTaskCreate(discovery_listener_task, "discovery_listen", 3072, NULL, 6, NULL);
}

/**
 * @brief Sends a UDP broadcast message to announce this node's presence.
 * @details The message format is "RAFT_HELLO:<IP>" and is sent to the well-known
 * discovery port, allowing other nodes to learn about this node's existence.
 * @return void
 */
void discovery_send_broadcast(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Broadcast failed: could not create socket");
        return;
    }

    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DISCOVERY_BROADCAST_PORT),
        .sin_addr.s_addr = inet_addr("255.255.255.255")
    };

    char my_ip[INET_ADDRSTRLEN];
    char my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));
    char msg[128];
    snprintf(msg, sizeof(msg), "RAFT_HELLO:%s:%s", my_ip, my_mac);

    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    close(sock);
}

/**
 * @brief Retrieves a memory-managed copy of the currently discovered peer list.
 * @details This function provides a thread-safe way to get the list of all peers
 * (including this node) that have been discovered so far.
 * @param[out] peer_count A pointer to an integer where the number of discovered peers will be stored.
 * @return A dynamically allocated array of C-strings, where each string is an IP address.
 * The caller is responsible for freeing this array and each individual string within it using free().
 * Returns NULL if no peers have been discovered or on memory allocation failure.
 */
char** discovery_get_peer_list_copy(int* peer_count) {
    char** peer_list_copy = NULL;
    *peer_count = 0;

    if (xSemaphoreTake(peer_list_mutex, portMAX_DELAY) == pdTRUE) {
        if (discovered_peer_count > 0) {
            peer_list_copy = malloc(sizeof(char*) * discovered_peer_count);
            if (peer_list_copy) {
                int valid_peers = 0;
                for (int i = 0; i < discovered_peer_count; i++) {
                    peer_list_copy[i] = strdup(discovered_peer_list[i].ip);
                    if (peer_list_copy[i] == NULL) {
                        for (int j = 0; j < i; j++) {
                            free(peer_list_copy[j]);
                        }
                        free(peer_list_copy);
                        peer_list_copy = NULL;
                        valid_peers = 0;
                        break;
                    }
                    valid_peers++;
                }
                 *peer_count = valid_peers;
            }
        }
        xSemaphoreGive(peer_list_mutex);
    }
    return peer_list_copy;
}

/**
 * @brief Retrieves the MAC address associated with a given IP address from the discovery list.
 * @param ip The IP address to search for.
 * @param mac_buf Buffer to store the found MAC address (must be at least MAC_ADDR_STR_LEN).
 * @param buf_size Size of the mac_buf.
 * @return true if the IP was found and the MAC was copied, false otherwise.
 */
bool discovery_get_mac_for_ip(const char* ip, char* mac_buf, size_t buf_size) {
    if (!ip || !mac_buf || buf_size < MAC_ADDR_STR_LEN) {
        return false;
    }

    bool found = false;
    if (xSemaphoreTake(peer_list_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (int i = 0; i < discovered_peer_count; i++) {
            if (strcmp(discovered_peer_list[i].ip, ip) == 0) {
                strncpy(mac_buf, discovered_peer_list[i].mac, buf_size - 1);
                mac_buf[buf_size - 1] = '\0';
                found = true;
                break;
            }
        }
        xSemaphoreGive(peer_list_mutex);
    } else {
        ESP_LOGE(TAG, "Failed to take mutex in discovery_get_mac_for_ip");
    }
    return found;
}