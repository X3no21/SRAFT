/* =============================
 * File: integrity_verification.c
 * Description: Implements distributed and single-node integrity verification protocols.
 * ============================= */

#include "integrity_verification.h"
#include "connection_pool.h"
#include "hatt_protocol.h"
#include "utility.h"
#include "auth_remove.h"
#include "raft.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "INTEGRITY_VERIFY";

static void run_single_check_task(void *pvParameters);
static void run_distributed_check_task(void *pvParameters);

/**
 * @brief (Internal) Central handler for all integrity verification failures.
 * @details This is a critical security response function. When an integrity check
 * fails, this function is called to orchestrate a coordinated response. It
 * blacklists the compromised node's MAC to prevent it from receiving votes
 * in the future, and immediately forces a new election to depose it if it is
 * the leader. Furthermore, if the current node is the leader, it will also
 * trigger the formal `remove` protocol to expel the compromised node from
 * the cluster entirely.
 * @param failed_node_ip The IP address of the node that failed the integrity check.
 * @param failed_node_mac The MAC address of the failed node, used for blacklisting.
 */
static void handle_verification_failure(const char *failed_node_ip, const char *failed_node_mac) {
    ESP_LOGE(TAG, "Integrity check FAILED for %s (MAC: %s). Blacklisting and forcing re-election.", failed_node_ip, failed_node_mac);
    raft_state_blacklist_mac(failed_node_mac);
    raft_force_new_election();

    char my_ip[INET_ADDRSTRLEN], leader_ip[INET_ADDRSTRLEN];
    raft_state_get_self_info(my_ip, sizeof(my_ip), NULL, 0);
    if (raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0) && strcmp(my_ip, leader_ip) == 0) {
        ESP_LOGI(TAG, "As leader, initiating formal removal of compromised node %s.", failed_node_ip);
        if (xQueueSend(remove_request_queue, failed_node_ip, pdMS_TO_TICKS(100)) != pdPASS) {
            ESP_LOGE(TAG, "Could not queue removal request for %s. Queue may be full.", failed_node_ip);
        }
    }
}

/**
 * @brief (Internal) Task that runs a single HAtt verification in parallel.
 * @details This task is created on-demand by integrity_verification_run_single.
 * It executes the check, handles failure, signals the result to
 * its job-specific semaphore, and then deletes itself.
 */
static void run_single_check_task(void *pvParameters) {
    single_check_job_t *job = (single_check_job_t *)pvParameters;

    ESP_LOGI(TAG, "Parallel task: Starting check for %s", job->request.target_ip);
    job->is_honest = hatt_verifier_run_attestation(job->request.target_ip);

    if (!job->is_honest) {
        handle_verification_failure(job->request.target_ip, job->request.target_mac);
    } else {
        ESP_LOGI(TAG, "Parallel task: Check PASSED for %s.", job->request.target_ip);
    }

    xSemaphoreGive(job->result_semaphore);
    vTaskDelete(NULL);
}

/**
 * @brief (Internal) Task that handles a distributed verification request in parallel.
 * @details This task is created on-demand by integrity_verification_handle_message
 * for each follower that sends an MSG_REQUEST_INTEGRITY_CHECK.
 */
static void run_distributed_check_task(void *pvParameters) {
    char *requester_ip = (char *)pvParameters;

    ESP_LOGI(TAG, "Parallel task: Starting to handle request from %s.", requester_ip);

    char leader_ip[INET_ADDRSTRLEN];
    raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0);

    char msg[128];
    snprintf(msg, sizeof(msg), "%s:%s\n", MSG_PROCEED_WITH_INTEGRITY_CHECK, leader_ip);
    connection_pool_send(requester_ip, msg);

    vTaskDelay(pdMS_TO_TICKS(500));

    free(requester_ip);
    vTaskDelete(NULL);
}

/**
 * @brief Runs a single, blocking point-to-point integrity check.
 * @details This function performs a direct HAtt attestation on the target and waits for
 * the result. If the attestation fails, it will automatically blacklist the target's
 * MAC address and trigger a new RAFT election.
 * @param target_ip The IP address of the node to be verified.
 * @param target_mac The MAC address of the node to be verified.
 * @return true if the attestation is successful, false otherwise.
 */
bool integrity_verification_run_single(const char *target_ip, const char *target_mac) {
    ESP_LOGI(TAG, "Running single-node integrity check for %s (MAC: %s)", target_ip, target_mac);
    single_check_job_t *job = malloc(sizeof(single_check_job_t));
    if (!job) {
        ESP_LOGE(TAG, "Failed to allocate memory for check job!");
        return false;
    }

    job->result_semaphore = xSemaphoreCreateBinary();
    if (!job->result_semaphore) {
        ESP_LOGE(TAG, "Failed to create result semaphore!");
        free(job);
        return false;
    }
    
    strncpy(job->request.target_ip, target_ip, INET_ADDRSTRLEN);
    job->request.target_ip[INET_ADDRSTRLEN - 1] = '\0';
    strncpy(job->request.target_mac, target_mac, MAC_ADDR_STR_LEN);
    job->request.target_mac[MAC_ADDR_STR_LEN - 1] = '\0';
    job->is_honest = false;

    if (xTaskCreate(run_single_check_task, "single_check_task", 8192, job, 6, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create parallel task for integrity check!");
        vSemaphoreDelete(job->result_semaphore);
        free(job);
        return false;
    }

    bool result = false;
    if (xSemaphoreTake(job->result_semaphore, pdMS_TO_TICKS(HATT_PROTOCOL_TIMEOUT_MS)) == pdTRUE) {
        result = job->is_honest;
    } else {
        ESP_LOGE(TAG, "Timed out waiting for single integrity check result for %s.", target_ip);
        handle_verification_failure(target_ip, target_mac);
        result = false;
    }

    vSemaphoreDelete(job->result_semaphore);
    free(job);
    
    return result;
}

/**
 * @brief Unified message handler for the centralized integrity verification protocol.
 * @details This function acts as the main router for the leader-coordinated integrity check.
 * It handles two primary messages: `MSG_REQUEST_INTEGRITY_CHECK` from a follower, which
 * it queues for the leader's manager task; and `MSG_PROCEED_WITH_INTEGRITY_CHECK`
 * from the leader, which triggers the follower to begin the attestation process.
 * This orchestrates a sequential, leader-managed verification of the cluster.
 * @param message The raw, null-terminated message string. This buffer will be
 * modified by `strtok_r`.
 * @param from_ip The IP address of the node that sent the message. Used to identify
 * the requester.
 */
void integrity_verification_handle_message(char *message, const char *from_ip) {
    char *saveptr;
    char *command = strtok_r(message, ":", &saveptr);
    if (!command)
        return;

    if (strcmp(command, MSG_REQUEST_INTEGRITY_CHECK) == 0) {
        ESP_LOGI(TAG, "Received integrity check request from %s, spawning parallel task.", from_ip);
        char *ip_copy = strdup(from_ip);
        if (ip_copy == NULL) {
            ESP_LOGE(TAG, "Failed to allocate memory for distributed check task!");
            return;
        }
        if (xTaskCreate(run_distributed_check_task, "dist_check_task", 3072, ip_copy, 6, NULL) != pdPASS) {
            ESP_LOGE(TAG, "Failed to create parallel task for distributed check!");
            free(ip_copy);
        }
    } else if (strcmp(command, MSG_PROCEED_WITH_INTEGRITY_CHECK) == 0) {
        char *leader_ip_from_msg = strtok_r(NULL, ":", &saveptr);
        if (leader_ip_from_msg) {
            char leader_ip_buf[INET_ADDRSTRLEN];
            strncpy(leader_ip_buf, leader_ip_from_msg, sizeof(leader_ip_buf) - 1);
            leader_ip_buf[sizeof(leader_ip_buf) - 1] = '\0';

            char leader_mac_buf[MAC_ADDR_STR_LEN];
            if (raft_state_get_leader_info(leader_ip_buf, sizeof(leader_ip_buf), leader_mac_buf, sizeof(leader_mac_buf))) {
                integrity_verification_run_single(leader_ip_buf, leader_mac_buf);
            }
        }
    }
}