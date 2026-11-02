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
#include "auth_db.h"
#include "auth_puf.h"
#include "auth_join.h"
#include "esp_random.h"
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
        raft_broadcast_blacklist_entry(failed_node_mac);
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
    hatt_result_t outcome = hatt_verifier_attest(job->request.target_ip, NULL);
    job->is_honest = (outcome == HATT_PASSED);

    if (outcome == HATT_FAILED) {
        // The device returned an authentic proof that does not match the reference: it is excluded.
        handle_verification_failure(job->request.target_ip, job->request.target_mac);
    } else if (outcome == HATT_NO_ANSWER) {
        // The check is not passed, but a device that did not answer is not excluded.
        ESP_LOGW(TAG, "Parallel task: no verdict for %s. Check not passed.", job->request.target_ip);
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
    if (xSemaphoreTake(job->result_semaphore, pdMS_TO_TICKS(HATT_PROTOCOL_TIMEOUT_MS + hatt_measurement_timeout_ms())) == pdTRUE) {
        result = job->is_honest;
        vSemaphoreDelete(job->result_semaphore);
        free(job);
    } else {
        // The check task is still running and owns the job, which is therefore not released here.
        ESP_LOGE(TAG, "Timed out waiting for single integrity check result for %s. Check not passed.", target_ip);
        result = false;
    }
    
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

/**
 * @brief (Internal) Picks at random one of the devices this node holds CRPs for.
 * @return true if a device was found and its IP copied to ip_buf.
 */
static bool pick_random_prover(char *ip_buf, size_t ip_buf_size) {
    int max_nodes = db_get_node_count();
    if (max_nodes <= 0) return false;

    char **ips = NULL;
    int count = db_get_all_follower_ips(&ips, max_nodes);
    bool found = false;
    if (count > 0) {
        int start = esp_random() % count;
        for (int i = 0; i < count && !found; i++) {
            const char *candidate = ips[(start + i) % count];
            if (auth_puf_is_verifier_of(candidate)) {
                strncpy(ip_buf, candidate, ip_buf_size - 1);
                ip_buf[ip_buf_size - 1] = '\0';
                found = true;
            }
        }
    }
    for (int i = 0; i < count; i++) free(ips[i]);
    if (ips) free(ips);
    return found;
}

int integrity_verification_check_prover(const char *target_ip, uint32_t auth_timeout_ms) {
    CRPNode crps[CRPS_PER_VERIFIER];
    int count = db_get_crps_for_node(target_ip, crps, CRPS_PER_VERIFIER);
    for (int i = 0; i < count; i++) {
        if (auth_puf_challenge_prover_with_crp(target_ip, &crps[i], auth_timeout_ms)) {
            return hatt_verifier_attest(target_ip, &crps[i]);
        }
        if (i + 1 < count) {
            ESP_LOGW(TAG, "Authentication of %s with %s failed, repeating it with another CRP.", target_ip, crps[i].challenge);
        }
    }
    return HATT_NO_ANSWER;
}

/**
 * @brief (Internal) Task that periodically re-checks the devices this node is a Verifier of.
 */
// Failures counted for each Prover, so that two failing Provers checked alternately are both reported.
#define PERIODIC_TRACKED_PROVERS 8
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int failures;
    bool wrong_proof;
} prover_failures_t;

static prover_failures_t *failures_of(prover_failures_t *table, const char *ip, bool create) {
    prover_failures_t *free_slot = NULL;
    for (int i = 0; i < PERIODIC_TRACKED_PROVERS; i++) {
        if (table[i].ip[0] != '\0' && strcmp(table[i].ip, ip) == 0) return &table[i];
        if (table[i].ip[0] == '\0' && !free_slot) free_slot = &table[i];
    }
    if (!create) return NULL;
    if (!free_slot) free_slot = &table[esp_random() % PERIODIC_TRACKED_PROVERS];
    memset(free_slot, 0, sizeof(*free_slot));
    strncpy(free_slot->ip, ip, INET_ADDRSTRLEN - 1);
    return free_slot;
}

static void periodic_reattestation_task(void *pvParameters) {
    prover_failures_t failures[PERIODIC_TRACKED_PROVERS];
    memset(failures, 0, sizeof(failures));

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(PERIODIC_REATTEST_INTERVAL_MS + (esp_random() % (PERIODIC_REATTEST_INTERVAL_MS / 4 + 1))));
        if (!is_raft_running()) continue;
        // The periodic check runs only while the network is idle, so that it never overlaps an election,
        // a join, a heal, or a removal on this device.
        char current_leader[INET_ADDRSTRLEN];
        if (raft_state_get_state() == CANDIDATE || !raft_state_get_leader_info(current_leader, sizeof(current_leader), NULL, 0) ||
            auth_join_operation_in_progress() || auth_remove_in_progress()) {
            continue;
        }

        char target_ip[INET_ADDRSTRLEN];
        // A Prover that failed the last check is checked again in the next period, so that a failure is
        // confirmed in consecutive periods; otherwise one of the Provers is drawn at random.
        bool retry = false;
        for (int i = 0; i < PERIODIC_TRACKED_PROVERS && !retry; i++) {
            if (failures[i].ip[0] != '\0' && failures[i].failures > 0) {
                if (auth_puf_is_verifier_of(failures[i].ip)) {
                    strncpy(target_ip, failures[i].ip, sizeof(target_ip) - 1);
                    target_ip[sizeof(target_ip) - 1] = '\0';
                    retry = true;
                } else {
                    // No longer one of its Provers, e.g., removed in the meantime.
                    memset(&failures[i], 0, sizeof(failures[i]));
                }
            }
        }
        if (!retry && !pick_random_prover(target_ip, sizeof(target_ip))) continue;

        hatt_result_t outcome = (hatt_result_t)integrity_verification_check_prover(target_ip, PERIODIC_REATTEST_AUTH_TIMEOUT_MS);
        if (outcome == HATT_PASSED) {
            prover_failures_t *entry = failures_of(failures, target_ip, false);
            if (entry) memset(entry, 0, sizeof(*entry));
            continue;
        }

        prover_failures_t *entry = failures_of(failures, target_ip, true);
        entry->failures++;
        if (outcome == HATT_FAILED) entry->wrong_proof = true;
        ESP_LOGW(TAG, "Periodic check FAILED for %s (%d/%d).", target_ip, entry->failures, PERIODIC_REATTEST_FAILURES_TO_REPORT);
        if (entry->failures < PERIODIC_REATTEST_FAILURES_TO_REPORT) continue;

        const bool exclude = entry->wrong_proof;
        memset(entry, 0, sizeof(*entry));

        char leader_ip[INET_ADDRSTRLEN], leader_mac[MAC_ADDR_STR_LEN];
        if (raft_state_get_leader_info(leader_ip, sizeof(leader_ip), leader_mac, sizeof(leader_mac)) && strcmp(leader_ip, target_ip) == 0) {
            if (exclude) {
                handle_verification_failure(leader_ip, leader_mac);
            } else {
                // A Coordinator that does not answer is replaced, and the candidates are attested by the voters.
                raft_force_new_election();
            }
        } else {
            remove_report_suspect(target_ip);
        }
    }
}

void integrity_verification_start_periodic(void) {
    static bool started = false;
    if (started || PERIODIC_REATTEST_INTERVAL_MS == 0) return;
    started = true;
    xTaskCreate(periodic_reattestation_task, "periodic_reattest", 6144, NULL, 4, NULL);
}
