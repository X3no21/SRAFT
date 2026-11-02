/* =============================
 * File: utility.h
 * Description: Public interface for common utility functions.
 * ============================= */

#ifndef UTILITY_H
#define UTILITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define MONITORING_SERVER_IP "192.168.1.125"
#define MONITORING_PORT 9001

// The SRAM PUF uses the first 4 KB of the RTC slow memory, i.e., 32768 cells.
#define SRAM_PUF_SIZE_WORDS 1024
// Readings taken once, at provisioning, to build the stability mask. The cells that still differ
// between power-ups after this filter are corrected by the fuzzy extractor.
#define SRAM_PUF_READOUTS 5
#define RESPONSE_BITS 128
// Number of response indexes that the Coordinator may assign to a device. It is a lower bound on
// what the retained cells of a device provide (see PUF_BLOCKS_PER_RESPONSE).
#define PUF_RESPONSE_CAPACITY 40
// Prefix of a challenge: "<prefix><response index>@<device identifier>".
#define PUF_CHALLENGE_PREFIX "P"

/**
 * @brief Initializes the SNTP client and blocks until the system time is synchronized.
 * @details This function configures and starts the SNTP client to obtain the current
 * time from a public NTP server (`pool.ntp.org`). It enters a blocking wait
 * loop with a limited number of retries to ensure time is synchronized before
 * proceeding. If successful, it sets the local timezone environment variable to
 * allow for correct local time conversions.
 * @param None
 * @return void
 */
void initialize_sntp_sync(void);

/**
 * @brief Initializes the background monitoring task and queue.
 * @details This must be called once at startup to enable asynchronous monitoring events.
 */
void monitoring_init(void);

/**
 * @brief Logs a byte buffer as a hexadecimal string using the ESP-IDF logging framework.
 * @details This utility function provides a standardized way to print binary data for debugging.
 * It displays a label and then the hexadecimal representation of the buffer content.
 * @param tag The logging tag (e.g., "HATT_PROTOCOL") to use for the ESP_LOG message.
 * @param label A descriptive label for the data being printed (e.g., "Nonce N1").
 * @param data A pointer to the byte buffer to be logged.
 * @param len The number of bytes to log from the buffer.
 */
void print_hex(const char* tag, const char* label, const uint8_t* data, size_t len);

/**
 * @brief Announces the node's presence on the network to the central monitoring server.
 * @details This is typically called once after a successful Wi-Fi connection.
 * @return void
 */
void announce_presence(void);

/**
 * @brief Reads an embedded file from the virtual filesystem (VFS).
 * @details The caller is responsible for freeing the returned buffer using free().
 * @param path The full path to the file in the VFS (e.g., "/certs/ca.crt").
 * @param[out] file_size A pointer to a size_t variable where the size of the file will be stored.
 * @return A dynamically allocated buffer containing the file's content, or NULL on failure.
 */
char* read_embedded_file(const char* path, size_t* file_size);

/**
 * @brief Queues a monitoring event message to be sent asynchronously.
 * @details This function is non-blocking. It makes a copy of the message and pushes it
 * to the monitoring queue. If the queue is full, the message is dropped to prevent
 * blocking the caller (which might be holding critical mutexes).
 * @param event_message The null-terminated string message to send.
 * @return void
 */
void send_monitoring_tcp_event(const char *event_message);

/**
 * @brief Initializes the SRAM-PUF fingerprint implementing Vatajelu's Stability Test.
 * @details Performs multiple readouts to identify and mask unreliable (symmetrical) cells.
 * @return void
 */
void init_sram_puf(void);

/**
 * @brief Simulates a Strong PUF response using Vatajelu's Reliable Bit Selection.
 * @details Uses the challenge to select bits ONLY from the reliable (masked) SRAM regions.
 * @param challenge The input challenge C-string.
 * @param challenge_len Length of the challenge.
 * @param response A character buffer of at least 64 bytes to store the resulting response.
 * @return void
 */
void simulate_puf_response(const uint8_t *challenge, size_t challenge_len, char *response);

/**
 * @brief Builds the challenge string that addresses a response index of a device.
 * @param response_index The index of the group of cells, in [0, PUF_RESPONSE_CAPACITY).
 * @param device_id The identifier of the device the challenge is for.
 * @param challenge Output buffer.
 * @param challenge_size The size of the output buffer.
 */
void puf_format_challenge(int response_index, const char *device_id, char *challenge, size_t challenge_size);

/**
 * @brief Thread-safely retrieves the current node's IPv4 address as a string.
 * @param ip_buf A character buffer to store the retrieved IP address.
 * @param buf_size The size of the provided ip_buf.
 * @return void
 */
void get_my_ip(char* ip_buf, size_t buf_size);

/**
 * @brief Thread-safely retrieves the current node's MAC address as a string.
 * @param mac_buf A character buffer to store the retrieved MAC address (e.g., "XX:XX:XX:XX:XX:XX").
 * @param buf_size The size of the provided mac_buf (at least MAC_ADDR_STR_LEN).
 * @return void
 */
void get_my_mac(char* mac_buf, size_t buf_size);

/**
 * @brief Thread-safely retrieves the current node's unique ID (which is its IP address).
 * @param id_buf A character buffer to store the retrieved node ID.
 * @param buf_size The size of the provided id_buf.
 * @return void
 */
void get_my_node_id(char* id_buf, size_t buf_size);

/**
 * @brief Generates a cryptographically secure random nonce.
 * @param nonce_buffer A pointer to the buffer where the random bytes will be stored.
 * @param size The number of random bytes to generate.
 * @return void
 */
void generate_nonce(uint8_t* nonce_buffer, size_t size);

/**
 * @brief Converts an array of bytes to its hexadecimal string representation.
 * @param src A pointer to the source byte array.
 * @param dest A character buffer to store the resulting hexadecimal string. Its size
 * must be at least (size * 2 + 1).
 * @param size The number of bytes in the source array.
 * @return void
 */
void bytes_to_hex(const uint8_t* src, char* dest, size_t size);

/**
 * @brief Converts a hexadecimal string to an array of bytes.
 * @param src The source null-terminated hexadecimal string.
 * @param dest A pointer to the destination byte array. Its size must be at least (strlen(src) / 2).
 * @param size The number of bytes to convert.
 * @return void
 */
void hex_to_bytes(const char* src, uint8_t* dest, size_t size);

/**
 * @brief Generates a cryptographically secure random number within a specified range.
 * @details Uses rejection sampling to avoid modulo bias.
 * @param max The upper bound of the range (exclusive).
 * @return A securely generated random number as a uint32_t between 0 and max-1.
 */
uint32_t secure_rand_range(uint32_t max);

/**
 * @brief Logs the free internal heap and its largest free block, with a label (for diagnostics).
 */
void log_heap(const char *where);

/**
 * @brief Logs, for every task, the smallest amount of stack it has left so far (for diagnostics).
 */
void log_task_stacks(void);

#endif // UTILITY_H