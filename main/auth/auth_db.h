/* =============================
 * File: auth_db.h
 * Description: Header for NVS-based database operations for authentication.
 * ============================= */

#ifndef AUTH_DB_H_
#define AUTH_DB_H_

// Response of a CRP staged during an enrollment, before the response of the Prover arrives.
#define DB_PENDING_RESPONSE "PENDING"

#include "cJSON.h"
#include <stdbool.h>
#include <arpa/inet.h>

#define DB_TMP_NAMESPACE "auth_db_tmp"

#define MAX_NODES 64
#define MAX_CRP 50
#define MAX_DISTINCT_VERIFIERS 32
// Holder of a challenge whose Verifier was removed: the entry is kept so that the cells behind the
// challenge are never assigned again.
#define DB_REVOKED_HOLDER "0.0.0.0"
// Entries of the network state: at most MAX_NODES devices with PUF_RESPONSE_CAPACITY challenges each.
#define MAX_CNODE (MAX_NODES * 40)
#define DB_NAMESPACE "auth_db"

typedef struct {
    char id[64];
    char ip[INET_ADDRSTRLEN];
} NodeEntry;

typedef struct {
    char challenge[64];
    char target_ip[INET_ADDRSTRLEN];
    char holder_ip[INET_ADDRSTRLEN];
} CNodeEntry;

/**
 * @brief Structure to represent a CRP (Challenge-Response Pair).
 */
typedef struct {
    char challenge[64];
    char response[64];
    char target_ip[INET_ADDRSTRLEN];
} CRPNode;

typedef struct {
    uint32_t transaction_id;
    CNodeEntry cnode;
} TmpCNodeEntry;

/**
 * @brief Internal structure for the temporary DB.
 * Contains a transaction_id to allow parallel operations.
 */
typedef struct {
    uint32_t transaction_id;
    CRPNode crp;
} TmpCRPNode;

/**
 * @brief Initializes the NVS-based database.
 * This function sets up the non-volatile storage, creates the necessary mutex for
 * thread-safe access, and reads the persisted node and entry counts.
 * @return void
 */
void db_init(void);

/**
 * @brief Retrieves the current number of followers (excluding the leader) in the database.
 * @return The number of followers.
 */
int db_get_follower_count(void);

/**
 * @brief Retrieves the total number of nodes (including the leader) in the database.
 * @return The total number of nodes.
 */
int db_get_node_count(void);

/**
 * @brief Gets the IP of the follower at a given index.
 * @param index The 0-based index of the follower to retrieve.
 * @param ip_buffer A character buffer to store the retrieved IP address.
 * @param buffer_size The size of the provided ip_buffer.
 * @return true if a follower at the specified index was found and copied, false otherwise.
 */
bool db_get_follower_ip(int index, char* ip_buffer, size_t buffer_size);

/**
 * @brief Checks if a node with the given IP exists in the database.
 * @param ip The IP address string of the node to check.
 * @return true if the node exists, false otherwise.
 */
bool db_node_exists(const char* ip);

/**
 * @brief Inserts a new node into the database if it doesn't already exist.
 * @param node_id The ID of the new node (can be the same as the IP).
 * @param ip The IP address of the new node.
 * @return void
 */
void db_insert_node(const char* node_id, const char *ip);

/**
 * @brief Retrieves the node ID for a given IP address.
 * @param ip The IP address of the node to look up.
 * @param id_buffer A character buffer to store the retrieved ID.
 * @param buffer_size The size of the provided id_buffer.
 * @return true if the node was found and its ID was copied, false otherwise.
 */
bool get_id_for_node(const char* ip, char* id_buffer, size_t buffer_size);

/**
 * @brief Retrieves the IP of a random follower node using a thread-safe random number generator.
 * @param ip_buffer A buffer provided by the caller to store the resulting IP address.
 * @param buffer_size The size of the provided buffer.
 * @return true if a follower was found and the IP was copied, false otherwise.
 */
bool db_get_random_follower_ip(char* ip_buffer, size_t buffer_size);

/**
 * @brief Finds a random verifier (holder) for the current node.
 * @param my_ip The IP address of the current node seeking a verifier.
 * @return A dynamically allocated string containing the verifier's IP. The caller must free this. Returns NULL if none found.
 */
char* db_get_random_verifier_for_me(const char* my_ip);

/**
 * @brief Check if a CNode entry exists.
 * @param challenge Challenge string.
 * @param target_ip Target node IP.
 * @param holder_ip Holder node IP.
 * @return true if the entry exists, false otherwise.
 */
bool db_cnode_exists(const char *challenge, const char* target_ip, const char* holder_ip);

/**
 * @brief Insert a new CNode entry.
 * @param challenge Challenge string.
 * @param target_ip Target node IP.
 * @param holder_ip Holder node IP.
 */
void db_insert_cnode(const char *challenge, const char* target_ip, const char* holder_ip);

/**
 * @brief Retrieves a random Challenge-Response Pair (CRP) for a specific target node.
 * @param target_ip The IP address of the node for which to find a CRP.
 * @return A pointer to a dynamically allocated CRPNode struct. The caller must free this memory. Returns NULL if no CRP is found.
 */
CRPNode* db_get_random_crp_for_node(const char* target_ip);

/**
 * @brief Copies the CRPs held for a node, starting from a random one.
 * @param target_ip The IP address of the node.
 * @param out Array that receives the CRPs.
 * @param max Size of the array.
 * @return The number of CRPs copied.
 */
int db_get_crps_for_node(const char *target_ip, CRPNode *out, int max);

/**
 * @brief (Debug profile) Logs the storage used by the network state and the shards.
 */
void db_log_storage(void);

/**
 * @brief Retrieves a CRPNode by its challenge.
 * @param challenge The challenge string to search for.
 * @return Pointer to a dynamically allocated CRPNode. Caller must free this. Returns NULL if not found.
 */
CRPNode* db_get_crp_by_challenge(const char* challenge);

/**
 * @brief Inserts a new Challenge-Response Pair into the database.
 * @param crp A pointer to the CRPNode struct containing the new data.
 */
void db_insert_crp(const CRPNode* crp);

/**
 * @brief Exports the entire node table as a JSON string.
 * @return A dynamically allocated string containing the JSON array of nodes. Must be freed by the caller.
 */
char* db_export_nodes_json();

/**
 * @brief Exports the CNode table as a JSON string.
 * @return A dynamically allocated string containing the JSON array. Must be freed by the caller.
 */
char *db_export_cnode_json();

/**
 * @brief Imports a node table from a JSON string.
 * @param json_string The JSON string containing the array of nodes.
 */
void db_import_nodes_json(const char* json_string);

/**
 * @brief Imports and overwrites the CNode table from a JSON string.
 * @param json A constant character pointer to the JSON string.
 */
void db_import_cnode_json(const char *json);

/**
 * @brief Exports the whole network state for a joining device in a compact text form, with the entries
 * of delta_json (a JSON array of {c, t, h}) appended. The caller frees the string.
 */
char *db_export_state_compact(const char *delta_json);

/**
 * @brief Replaces the network state with the one exported by db_export_state_compact.
 */
bool db_import_state_compact(const char *state);

/**
 * @brief Removes all CRP entries associated with a given node IP.
 * @param target_ip The IP of the node whose CRPs should be removed.
 */
void db_remove_crp_for_node(const char* target_ip);

/**
 * @brief Removes all CNode entries where the given node is either the target or the holder.
 * @param node_ip The IP of the node to remove from the CNode table.
 */
void db_remove_cnode_for_node(const char* node_ip);

/**
 * @brief Moves to new_holder the entries in which self_ip is both Prover and Verifier, and returns their
 * challenges (at most max). Used once, when the first Coordinator hands its credentials to the first device.
 */
int db_reassign_self_cnodes(const char *self_ip, const char *new_holder, char challenges[][64], int max);

/**
 * @brief Removes a single node entry from the database by its IP.
 * @param ip The IP of the node to remove.
 */
void db_remove_node(const char* ip);

/**
 * @brief Counts the number of verifiers (holders) for a given target node.
 * @param target_ip The IP address of the node to check.
 * @return The number of verifiers found for the target node.
 */
int db_get_verifier_count_for_node(const char* target_ip);

/**
 * @brief Retrieves a list of all follower IPs from the database.
 * @param[out] follower_ips A pointer to an array of strings that will be allocated
 * and filled with the IP addresses of the followers.
 * @param[in] max_followers The maximum number of followers that can be stored in the array.
 * @return The number of followers found and copied to the array.
 */
int db_get_all_follower_ips(char ***follower_ips, int max_followers);

/**
 * @brief Clears all temporary data related to an active join transaction.
 * @details This function erases the entire temporary NVS namespace ('auth_db_tmp'). 
 * It should be called at the beginning of a new join process to ensure a clean 
 * state, and after a transaction is finished (either committed or aborted) to 
 * clean up. The operation is thread-safe.
 * @return void
 */
void db_join_tmp_clear(void);

void db_join_tmp_clear_by_tid(uint32_t transaction_id);

/**
 * @brief (For Verifiers) Inserts a new Challenge-Response Pair into temporary storage.
 * @details During the verification phase of a join protocol, a verifier calls this
 * function to persist a generated CRP to the temporary NVS namespace. This data is
 * held in staging until the leader confirms the final outcome of the join process.
 * The operation is thread-safe.
 * @param crp A pointer to the CRPNode struct to be temporarily saved.
 * @return void
 */
void db_join_tmp_insert_crp(uint32_t transaction_id, const CRPNode *crp);

/**
 * @brief (For the Leader) Inserts a new CNode entry into temporary storage.
 * @details When a verifier notifies the leader that it has generated a new challenge,
 * the leader calls this function to save the CNode (Challenge, Target, Holder)
 * relationship to its temporary NVS namespace. This builds up the transactional
 * state that will be committed or aborted later. The operation is thread-safe.
 * @param challenge The challenge string generated by the verifier.
 * @param target_ip The IP address of the node being verified (the prover).
 * @param holder_ip The IP address of the verifier that generated the challenge.
 * @return void
 */
void db_join_tmp_insert_cnode(uint32_t transaction_id, const char *challenge, const char *target_ip, const char *holder_ip);

/**
 * @brief (For the Leader) Exports all CNode entries from temporary storage as a JSON string.
 * @details The leader calls this function after a join is deemed successful to create the
 * JSON "delta" of new CNodes. This JSON payload is then broadcast to existing
 * followers so they can update their own databases. The operation is thread-safe.
 * @return A dynamically allocated string containing the JSON array of temporary
 * CNodes. The caller is responsible for freeing this string. Returns NULL on failure.
 */
char* db_join_tmp_export_cnodes_json(uint32_t transaction_id);

/**
 * @brief (For Verifiers) Retrieves a CRP from temporary storage by its challenge.
 * @param challenge The challenge string to search for in the temporary database.
 * @return A pointer to a dynamically allocated CRPNode. Caller must free this. Returns NULL if not found.
 */
CRPNode* db_join_tmp_get_crp_by_challenge(uint32_t transaction_id, const char *challenge);

/**
 * @brief (For Verifiers) Sets the response of a CRP staged in temporary storage.
 * @param transaction_id The transaction ID.
 * @param challenge The challenge of the staged CRP.
 * @param new_response The response received from the Prover.
 */
void db_join_tmp_update_crp_response(uint32_t transaction_id, const char *challenge, const char *new_response);

/**
 * @brief Retrieves a list of all current verifiers (holders) for a given target node.
 * @param target_ip The IP address of the node whose verifiers are to be found.
 * @param verifier_ips A 2D char array to store the resulting IP addresses of the verifiers.
 * @param max_verifiers The maximum number of IPs the verifier_ips array can hold.
 * @return The number of verifiers found and copied into the array.
 */
int db_get_verifiers_for_node(const char* target_ip, char verifier_ips[][INET_ADDRSTRLEN], int max_verifiers);

/**
 * @brief (For the Leader) Updates the holder_ip of a specific CNode in temporary storage.
 * @details This function finds a CNode in the temporary NVS namespace by its challenge
 * and target IP, and then overwrites its holder_ip field with the new value.
 * This is used during the genesis delegation process.
 * @param challenge The challenge string of the CNode to update.
 * @param target_ip The target IP of the CNode to update.
 * @param new_holder_ip The new IP address to set as the holder.
 * @return void
 */
void db_join_tmp_update_cnode_holder(uint32_t transaction_id, const char* challenge, const char* target_ip, const char* new_holder_ip);

/**
 * @brief Commits all data from the temporary storage to the main database.
 * @details This function is called by the leader and verifiers after receiving confirmation
 * that the join was successful cluster-wide. It transactionally reads all CRPs
 * and CNodes from the temporary namespace and merges them into the main, permanent
 * database namespace. After the merge, it clears the temporary storage. The
 * operation is thread-safe.
 * @return void
 */
void db_join_commit(uint32_t transaction_id);

/**
 * @brief Performs a complete wipe of the main authentication database.
 * @details This function erases the entire NVS namespace used for authentication ('auth_db'),
 * including the node list, CNode table, and CRP table. It is called during the node
 * decommissioning process to ensure a removed node has no residual cluster state.
 * @return void
 */
void db_wipe_all_auth_data(void);

/**
 * @brief Commits only the CRPs from temporary storage to the main database.
 * @details This is a helper function used during the commit phase.
 * @param transaction_id The transaction ID to commit.
 * @return void
 */
void db_join_tmp_commit_crps(uint32_t transaction_id);

/**
 * @brief Commits any pending healing data to the main database.
 * @return void
 */
void db_join_commit_all_pending_heal(void);

/**
 * @brief Checks if a challenge string exists anywhere in the CNode table (globally).
 * @param challenge The challenge string to check.
 * @return true if the challenge exists, false otherwise.
 */
bool db_challenge_exists_globally(const char *challenge);

/**
 * @brief Retrieves the challenge associated with a specific verifier for the current node.
 * @param verifier_id The ID (IP) of the verifier.
 * @param challenge_buffer Buffer to store the retrieved challenge.
 * @param max_len Maximum number of bytes to write to the buffer.
 * @return true if a challenge was found, false otherwise.
 */
bool db_get_challenge_for_verifier(const char* verifier_id, char* challenge_buffer, size_t max_len);

#endif // AUTH_DB_H_