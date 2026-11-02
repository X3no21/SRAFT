/* =============================
 * File: attacker.c
 * Description: Implementation of the test-only adversary hooks (see attacker.h). Compiled only when
 * SRAFT_ATTACK_HOOKS is defined. Every primitive reuses the real transport (connection_pool_send) and
 * the ordinary message formats, so the honest nodes answer through their unmodified handlers.
 * ============================= */

#ifdef SRAFT_ATTACK_HOOKS

#include "attacker.h"
#include "auth_puf.h"
#include "auth_remove.h"
#include "connection_pool.h"
#include "raft_state.h"
#include "utility.h"
#include "nonce_manager.h"
#include "esp_log.h"
#include "esp_random.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "ATTACKER";

static volatile int response_watch_count = -1;   // -1 while the watcher is off.
static char response_watch_op[64] = {0};          // Empty: count any AUTH_RES.

void attacker_watch_arm(const char *op_id) {
    response_watch_count = 0;
    if (op_id) {
        strncpy(response_watch_op, op_id, sizeof(response_watch_op) - 1);
        response_watch_op[sizeof(response_watch_op) - 1] = '\0';
    } else {
        response_watch_op[0] = '\0';
    }
}
int attacker_watch_responses_count(void) { return response_watch_count; }
void attacker_on_auth_response_seen(const char *op_id) {
    if (response_watch_count < 0) return;
    if (response_watch_op[0] && (!op_id || strcmp(op_id, response_watch_op) != 0)) return;
    response_watch_count++;
}

bool attacker_send_oracle_query(const char *prover_ip, const char *challenge) {
    char my_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));

    // A fresh nonce, so the receiver does not drop the message as a replay, and a random tag that
    // cannot prove knowledge of the response: the Prover must refuse to answer.
    uint8_t nonce[16], tag[32];
    char nonce_hex[33], tag_hex[65];
    generate_nonce(nonce, sizeof(nonce));
    generate_nonce(tag, sizeof(tag));
    bytes_to_hex(nonce, nonce_hex, sizeof(nonce));
    bytes_to_hex(tag, tag_hex, sizeof(tag));

    char op_id[48];
    snprintf(op_id, sizeof(op_id), "attack_oracle_%lu", (unsigned long)esp_random());

    // Count only the Prover's answer to this exact query, not a late answer from an earlier one.
    attacker_watch_arm(op_id);

    char msg[PUF_MAX_MSG_SIZE];
    snprintf(msg, sizeof(msg), "%s|%s|%s|%s|%s|%s\n", MSG_AUTH_REQ, op_id, challenge, my_ip, nonce_hex, tag_hex);
    ESP_LOGW(TAG, "Oracle query to %s for challenge %s with an invalid proof.", prover_ip, challenge);
    return connection_pool_send(prover_ip, msg);
}

bool attacker_send_raw(const char *target_ip, const char *line, int flip_index) {
    size_t len = strlen(line);
    char *buf = malloc(len + 2);
    if (!buf) return false;
    memcpy(buf, line, len + 1);
    if (flip_index >= 0 && (size_t)flip_index < len) {
        buf[flip_index] ^= 0x01;   // One-bit change of a single field.
    }
    if (len == 0 || buf[len - 1] != '\n') { buf[len] = '\n'; buf[len + 1] = '\0'; }
    bool ok = connection_pool_send(target_ip, buf);
    free(buf);
    return ok;
}

int attacker_force_direct_removal(const char *target_ip) {
    char my_ip[INET_ADDRSTRLEN], leader_ip[INET_ADDRSTRLEN];
    get_my_ip(my_ip, sizeof(my_ip));
    // The order is applied by the receivers only if it comes from the Coordinator; this node must be it.
    if (!raft_state_get_leader_info(leader_ip, sizeof(leader_ip), NULL, 0) || strcmp(my_ip, leader_ip) != 0) {
        ESP_LOGW(TAG, "Direct removal needs this node to be the Coordinator. Aborted.");
        return 0;
    }

    int peer_count = 0;
    char **peers = raft_state_get_peers_copy(&peer_count);
    if (!peers) return 0;

    uint32_t tid = esp_random();
    int sent = 0;
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i], my_ip) == 0 || strcmp(peers[i], target_ip) == 0) { free(peers[i]); continue; }
        uint8_t nonce[16];
        char nonce_hex[33];
        generate_nonce(nonce, sizeof(nonce));
        bytes_to_hex(nonce, nonce_hex, sizeof(nonce));
        char msg[256];
        // The direct order skips the MSG_REMOVE_CHECK_REQ confirmation phase of the ordinary removal.
        snprintf(msg, sizeof(msg), "%s:%lu:%s:%s\n", MSG_NODE_REMOVED, (unsigned long)tid, target_ip, nonce_hex);
        if (connection_pool_send(peers[i], msg)) sent++;
        free(peers[i]);
    }
    free(peers);
    ESP_LOGW(TAG, "Direct removal order for %s sent to %d peers (no confirmation phase).", target_ip, sent);
    return sent;
}

bool attacker_forge_heartbeat(const char *target_ip, unsigned int term) {
    char my_ip[INET_ADDRSTRLEN], my_mac[MAC_ADDR_STR_LEN];
    get_my_ip(my_ip, sizeof(my_ip));
    get_my_mac(my_mac, sizeof(my_mac));
    char msg[128];
    snprintf(msg, sizeof(msg), "%s %u %s %s\n", MSG_HEARTBEAT, term, my_ip, my_mac);
    ESP_LOGW(TAG, "Forging a heartbeat for term %u claiming the Coordinator role, to %s.", term, target_ip);
    return connection_pool_send(target_ip, msg);
}

#endif // SRAFT_ATTACK_HOOKS
