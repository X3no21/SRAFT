/* =============================
 * File: raft.h
 * Description: Public interface for the RAFT logic controller.
 * ============================= */

#ifndef RAFT_H
#define RAFT_H

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h" 
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Retrieves the handle of the heartbeat sender timer.
 * @return The FreeRTOS TimerHandle_t for the heartbeat sender.
 */
TimerHandle_t raft_get_heartbeat_sender_timer(void);

/**
 * @brief Forcefully stops all active Raft timers and the orchestrator task.
 * @details This function acts as a hard stop for the Raft protocol logic on a node. 
 * It is called when a node is being decommissioned (e.g., removed from the cluster) 
 * to ensure it becomes inert. It deletes the main orchestrator task to prevent new 
 * elections and explicitly stops the leader's heartbeat sender, the follower's 
 * heartbeat timeout, and the candidate's election timers.
 * @return void
 */
void raft_shutdown_timers_and_tasks(void);

/**
 * @brief Callback passed to the connection pool to handle all incoming RPC messages.
 * @details This function is the single entry point for all data received from the network.
 * It parses the message and dispatches it to the appropriate handler in the RAFT state machine.
 * @param from_ip The IP address of the node that sent the message.
 * @param message The null-terminated message string.
 */
void raft_message_handler(const char* from_ip, const char* message);

/**
 * @brief Initializes the RAFT logic controller and its background tasks.
 * @details This function sets up the server to listen for incoming messages and the orchestrator
 * task to manage time-based events like elections and heartbeats. It should be
 * called after the connection pool has been started.
 * @param peers An array of C-strings containing the IP addresses of all nodes in the cluster.
 * @param num_peers The total number of peers in the array.
 * @return void
 */
void raft_init_with_peers(char **peers, int num_peers);

/**
 * @brief Public function to externally trigger a new election.
 * @details This function safely notifies the internal RAFT orchestrator task to
 * abandon its current state and start a new election process. It is intended
 * for use by other modules that detect a critical failure, such as a compromised leader.
 * @return void
 */
void raft_force_new_election(void);

/**
 * @brief Checks if the Raft protocol task and timers have been initialized.
 * @return true if Raft is already running, false otherwise.
 */
bool is_raft_running(void);

/**
 * @brief (Coordinator) Tells all the other devices that a device is excluded.
 * @param mac The MAC address of the excluded device.
 */
void raft_broadcast_blacklist_entry(const char *mac);

/**
 * @brief (Coordinator) Sends the whole list of excluded devices to one device, e.g., a new member.
 * @param target_ip The IP address of the device that receives the list.
 */
void raft_send_blacklist_to(const char *target_ip);

#endif // RAFT_H