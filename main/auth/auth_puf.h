/* =============================
 * File: auth_puf.h
 * Description: Public interface for the PUF-based authentication protocol.
 * ============================= */

#ifndef AUTH_PUF_H
#define AUTH_PUF_H

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define PUF_MAX_MSG_SIZE 256

#define MSG_AUTH_REQ "AUTH_REQ"
#define MSG_AUTH_RESPONSE "AUTH_RES"
#define MSG_INITIATE_AUTH_REQ "INITIATE_AUTH_REQ"
#define MSG_AUTH_FINAL_RESULT "AFR"

extern SemaphoreHandle_t auth_result_sem;
extern bool auth_result_success;

typedef struct {
    char *message;
    char from_ip[INET_ADDRSTRLEN];
} auth_message_t;

/**
 * @brief Initializes the PUF authentication module.
 * @details This function performs lazy, thread-safe initialization of the synchronization
 * primitives required for the PUF authentication process. Specifically, it creates the
 * `auth_result_sem` binary semaphore. This semaphore is essential for making the
 * `/request_authentication` API endpoint synchronous, allowing the HTTP handler to block
 * until the P2P authentication process completes and a definitive result is available.
 * @param None.
 * @return void
 */
void auth_puf_init(void);

/**
 * @brief Queues an incoming authentication message for processing by the worker task.
 * @details This function is thread-safe and non-blocking. It copies the message pointer
 * and sender IP into the queue. The worker task is responsible for freeing the message memory.
 * @param message The dynamically allocated message string. Ownership is transferred to the queue.
 * @param from_ip The IP address of the sender.
 * @return void
 */
void auth_puf_queue_message(char *message, const char *from_ip);

/**
 * @brief A node (Prover) initiates its own authentication process against a random verifier.
 * @details This function looks up a random verifier from the database and queues an
 * authentication request to it via the connection pool.
 * @return void
 */
void initiate_authentication_as_prover(void);

/**
 * @brief A node (Prover) initiates its own authentication process against a *specific* verifier.
 * @details This function is called by an API handler when commanded by the monitoring server.
 * It sends an authentication request to the specified verifier.
 * @param verifier_ip The IP address of the verifier to use.
 * @return void
 */
void initiate_authentication_as_prover_specific(const char* verifier_ip);

#endif // AUTH_PUF_H