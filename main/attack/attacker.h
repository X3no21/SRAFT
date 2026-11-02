/* =============================
 * File: attacker.h
 * Description: Test-only adversary hooks used by the attack-resilience campaign (Section 5 of the
 * paper). The whole module is compiled only when SRAFT_ATTACK_HOOKS is defined, so the ordinary
 * firmware contains none of it. The hooks let one member emulate a captured/compromised device:
 * they reuse the real send, receive, and verify paths and never read the secrets of an honest node
 * to build an attack. They are armed at runtime by the /test/attack endpoint and are dormant
 * otherwise, so an unarmed node behaves exactly like the ordinary firmware.
 * ============================= */

#ifndef ATTACKER_H
#define ATTACKER_H

#ifdef SRAFT_ATTACK_HOOKS

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Arms, for the next authentication in which this node answers as Prover, the substitution of
 * the PUF response with the given one (hex of up to 64 chars), emulating a captured credential used
 * for a challenge whose genuine response the adversary does not hold. NULL disarms it.
 */
void attacker_force_prover_response(const char *response_or_null);

/**
 * @brief Arms the watcher to count only the AUTH_RES messages whose operation id equals op_id, so a
 * late answer from an earlier probe is not miscounted. NULL counts any AUTH_RES.
 */
void attacker_watch_arm(const char *op_id);

/** @brief Number of matching AUTH_RES messages seen since the watcher was armed. */
int attacker_watch_responses_count(void);

/** @brief Hook called by the receive path on an incoming AUTH_RES, with its operation id. */
void attacker_on_auth_response_seen(const char *op_id);

/**
 * @brief Builds a genuine AUTH_REQ for a Prover this node verifies, using one of its own stored CRPs,
 * with a valid proof and a fresh operation id and nonce. Used as the positive control of the oracle
 * test and as the genuine message that the replay/modification test resends.
 * @return true if a CRP for the Prover was available and the line was built into out.
 */
bool attacker_build_authreq(const char *prover_ip, char *out, size_t out_size);

/**
 * @brief Sends an AUTH_REQ to a Prover with a chosen challenge and a deliberately invalid proof,
 * emulating an attempt to use the Prover as an oracle for a challenge whose response is unknown.
 * @return true if the message was sent.
 */
bool attacker_send_oracle_query(const char *prover_ip, const char *challenge);

/**
 * @brief Sends a raw line to a target through the real transport, with at most one byte flipped.
 * @param flip_index Index of the byte to flip, or a negative value to send the line unchanged.
 */
bool attacker_send_raw(const char *target_ip, const char *line, int flip_index);

/**
 * @brief (As Coordinator) Sends a removal order for a healthy target directly to every peer, skipping
 * the confirmation phase, to measure the membership divergence of Section 5.4.
 * @return The number of peers the order was sent to.
 */
int attacker_force_direct_removal(const char *target_ip);

/**
 * @brief Forges a heartbeat that claims the Coordinator role for the given term from this node,
 * sent to a target, to test that an unvoted claim is checked before it is accepted (Section 5.4).
 * @return true if the message was sent.
 */
bool attacker_forge_heartbeat(const char *target_ip, unsigned int term);

#endif // SRAFT_ATTACK_HOOKS
#endif // ATTACKER_H
