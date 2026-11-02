#!/usr/bin/env python3
"""
Attack-resilience campaign (Section 5 of the paper).

Runs, on a bootstrapped SRAFT network, the adversary scenarios that correspond to the claims of the
security analysis: message replay and modification (5.1), chosen-challenge/oracle queries (5.2),
capture and collusion of Verifiers (5.3), a captured Coordinator that forces a removal and forged
coordination messages (5.4).

The adversary is one member running the attack image (build_attack): a production build plus the
test-only hooks of main/attack/, which are dormant until armed over REST and never read an honest
node's secrets. Every attack reaches the real receive, verify, and apply paths of the honest nodes,
whose behaviour is produced by their unmodified handlers. For each variant the runner records a
numerator/denominator over independent runs and an observable security property; the results are
written as JSON, a CSV for plotting, and a short Markdown summary, into a separate
output directory. No existing results are touched and no substitute numbers are generated: a variant
that cannot be exercised on the available hardware is marked as such with the reason.

Usage (on the server, services up):
    SRAFT_BUILD_DIR=build_attack python3 attack_campaign.py -n 7 --runs 10 --out <dir>
    python3 attack_campaign.py --validate-only        # print the plan, touch nothing
"""
import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

from loguru import logger

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import experimental_campaign as ec

RAFT_TCP_PORT = 9000


def ts():
    return datetime.now(timezone.utc).isoformat()


def raft_state(ip):
    return ec.send_command_via_proxy(ip, "/raft/state", "GET", ec.ESP32_API_PORT) or {}


def attack(ip, payload):
    """Sends one /test/attack action to the attacker node and returns its JSON observation."""
    return ec.send_command_via_proxy(ip, "/test/attack", "POST", ec.ESP32_API_PORT, payload)


def members_of(ip):
    """The members a node sees: its Raft peers plus itself."""
    st = raft_state(ip)
    peers = set(st.get("peer_ips", []) or [])
    me = st.get("esp_ip")
    if me:
        peers.add(me)
    return peers


def pick_coordinator(ips):
    leader, _ = ec.coordinator_view(ips)
    return leader


# --------------------------------------------------------------------------------------------------
# Scenarios. Each returns a dict with the per-run observations and a computed property.
# --------------------------------------------------------------------------------------------------

def scenario_B(attacker_ip, prover_ip, runs):
    """5.2 oracle, measured with the responses watcher for both the negative and the positive case."""
    refused = 0
    for _ in range(runs):
        r = attack(attacker_ip, {"action": "oracle", "target_ip": prover_ip, "challenge": "1"})
        if r and r.get("prover_responded") is False:
            refused += 1
        time.sleep(0.3)
    answered_genuine = 0
    for _ in range(runs):
        built = attack(attacker_ip, {"action": "build_authreq", "prover_ip": prover_ip})
        if not built or built.get("status") != "ok":
            continue
        # Reuse the watcher: send the genuine request as a raw line and count the Prover's answer.
        r = _send_and_watch(attacker_ip, prover_ip, built["line"], flip_index=-1)
        if r:
            answered_genuine += 1
        time.sleep(0.3)
    return {
        "section": "5.2",
        "property": "A Prover answers only a request that proves knowledge of the response",
        "violation": "the Prover answered a request with an invalid proof",
        "invalid_refused": refused, "invalid_total": runs,
        "genuine_answered": answered_genuine, "genuine_total": runs,
    }


def _send_and_watch(attacker_ip, prover_ip, line, flip_index):
    """Sends a raw line and reports whether the Prover answered it. The watcher is armed with the
    operation id carried by the line, so it counts only the answer to this exact request and never a
    late answer from an earlier probe. A flip in the tag does not change the operation id (field 2)."""
    parts = line.split("|")
    op_id = parts[1] if len(parts) > 1 else None
    attack(attacker_ip, {"action": "watch_arm", "op_id": op_id})
    attack(attacker_ip, {"action": "send_raw", "target_ip": prover_ip, "line": line, "flip_index": flip_index})
    time.sleep(1.5)
    w = attack(attacker_ip, {"action": "watch_count"})
    return bool(w and w.get("responses", 0) > 0)


def _build_line(attacker_ip, prover_ip):
    built = attack(attacker_ip, {"action": "build_authreq", "prover_ip": prover_ip})
    return built["line"] if built and built.get("status") == "ok" else None


def scenario_A(attacker_ip, prover_ip, runs):
    """5.1: a single-field modification is refused, and a request already seen (same nonce) is dropped as
    a replay. Each sub-test uses a freshly built genuine request so the two do not interfere."""
    modified_refused = 0
    replay_dropped = 0
    for _ in range(runs):
        # Modification: flip one byte inside the HMAC tag of a fresh genuine request. The Prover must
        # not answer, because the proof no longer matches.
        line_mod = _build_line(attacker_ip, prover_ip)
        if line_mod:
            flip = max(0, len(line_mod) - 10)
            if not _send_and_watch(attacker_ip, prover_ip, line_mod, flip_index=flip):
                modified_refused += 1
        # Replay protection: a fresh genuine request is answered once; resending the very same line
        # (same nonce) is dropped, so a recorded message cannot be replayed into a new answer.
        line = _build_line(attacker_ip, prover_ip)
        if line:
            first = _send_and_watch(attacker_ip, prover_ip, line, flip_index=-1)
            second = _send_and_watch(attacker_ip, prover_ip, line, flip_index=-1)
            if first and not second:
                replay_dropped += 1
        time.sleep(0.3)
    return {
        "section": "5.1",
        "property": "A modified request is refused and a replayed request (seen nonce) is dropped",
        "violation": "the Prover answered a modified request, or answered a replayed one twice",
        "modified_refused": modified_refused, "modified_total": runs,
        "replay_dropped": replay_dropped, "replay_total": runs,
    }


def scenario_C(attacker_ip, runs):
    """5.3: a credential other than the enrolled one does not authenticate; the genuine one does."""
    impersonation_rejected = 0
    genuine_accepted = 0
    for _ in range(runs):
        # Impersonation: answer the next authentication with a response other than the enrolled one.
        attack(attacker_ip, {"action": "force_prover_response"})
        res = ec.run_async_auth(attacker_ip, "/request_authentication", {}, timeout_s=40)
        if res is False:
            impersonation_rejected += 1
        time.sleep(0.5)
    for _ in range(runs):
        # Positive control: the genuine response (the node's own PUF) authenticates.
        res = ec.run_async_auth(attacker_ip, "/request_authentication", {}, timeout_s=40)
        if res is True:
            genuine_accepted += 1
        time.sleep(0.5)
    return {
        "section": "5.3",
        "property": "Authentication succeeds only with the enrolled response, not with another credential",
        "violation": "an authentication succeeded with a response other than the enrolled one",
        "impersonation_rejected": impersonation_rejected, "impersonation_total": runs,
        "genuine_accepted": genuine_accepted, "genuine_total": runs,
    }


def exposure_arithmetic(ips):
    """5.3 structural: with q Verifiers per Prover, compromising k exposes k shards and leaves q-k
    honest verification paths; the Prover stays verifiable while q-k >= 1."""
    _, st = ec.coordinator_view(ips)
    q = st.get("min_verifiers") if st else None
    rows = []
    if q:
        for k in range(0, q + 1):
            rows.append({"compromised_verifiers": k, "exposed_shards": k,
                         "honest_paths_left": q - k, "prover_still_verifiable": (q - k) >= 1})
    return {"verifiers_per_prover": q, "rows": rows}


def scenario_D(ips, runs):
    """5.4: a captured Coordinator forces a removal without the confirmation phase; honest Verifiers of
    the target keep their shard while non-Verifiers apply the order, so membership can diverge."""
    observations = []
    for _ in range(runs):
        coord = pick_coordinator(ips)
        if not coord:
            observations.append({"error": "no coordinator"})
            continue
        # Target: a healthy member that is neither the Coordinator.
        target = next((ip for ip in ips if ip != coord), None)
        before = {ip: (target in members_of(ip)) for ip in ips}
        attack(coord, {"action": "direct_removal", "target_ip": target})
        time.sleep(8)
        after = {ip: (target in members_of(ip)) for ip in ips}
        recipients = [ip for ip in ips if ip not in (coord, target)]
        kept = sum(1 for ip in recipients if after.get(ip))
        removed = sum(1 for ip in recipients if not after.get(ip))
        # Does an honest path still authenticate the target? Ask the target to authenticate.
        still_auth = ec.run_async_auth(target, "/request_authentication", {}, timeout_s=40)
        observations.append({
            "coordinator": coord, "target": target,
            "recipients": len(recipients), "kept_target": kept, "removed_target": removed,
            "membership_diverged": kept > 0 and removed > 0,
            "target_still_authenticates": still_auth,
        })
        # Restore the network before the next run.
        ec.bootstrap_and_wait_redundancy(len(ips), "attack_D_restore", ec.MONITOR_WAIT_TIMEOUT_S)
        ips = ec.wait_for_ips(len(ips), 180) or ips
    return {
        "section": "5.4",
        "property": "An unconfirmed removal order leaves honest Verifiers' shards in place",
        "violation": "an honest Verifier of the target discarded its shard on an unconfirmed order",
        "runs": observations,
    }


def scenario_E(ips, attacker_ip, runs):
    """5.4: forged coordination messages. A software-altered member cannot usurp the Coordinator role
    through a forged heartbeat (an unvoted claim is checked); an outsider's injection is dropped by
    the membership gate; a stale heartbeat is ignored by the term check."""
    results = {"section": "5.4",
               "property": "Forged coordination messages do not install an unauthorized Coordinator",
               "violation": "a forged heartbeat installed the attacker as Coordinator"}

    # E1 regression: a tampered member forges a heartbeat claiming the role; the target must refuse it.
    tampered_refused = 0
    target = next((ip for ip in ips if ip != attacker_ip), None)
    for _ in range(runs):
        coord = pick_coordinator(ips)
        term = (raft_state(coord).get("current_term", 0) if coord else 0) + 5
        leader_before = raft_state(target).get("leader_ip")
        # Alter the attacker's attested software, then forge the claim.
        ec.send_command_via_proxy(attacker_ip, "/test/fault", "POST", ec.ESP32_API_PORT,
                                  {"fault": "tamper", "bytes": 4096})
        time.sleep(1)
        attack(attacker_ip, {"action": "forge_hb", "target_ip": target, "term": term})
        time.sleep(6)
        leader_after = raft_state(target).get("leader_ip")
        if leader_after != attacker_ip:
            tampered_refused += 1
        # Restore the attacker's image and the network for the next run.
        ec.bootstrap_and_wait_redundancy(len(ips), "attack_E_restore", ec.MONITOR_WAIT_TIMEOUT_S)
        ips = ec.wait_for_ips(len(ips), 180) or ips
    results["tampered_claim_refused"] = tampered_refused
    results["tampered_claim_total"] = runs

    # E2 outsider injection: a non-member forges a RequestVote from the server; the target drops it.
    coord = pick_coordinator(ips)
    tgt = next((ip for ip in ips if ip != coord), None)
    term_before = raft_state(tgt).get("current_term", 0)
    dropped = 0
    for _ in range(runs):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((tgt, RAFT_TCP_PORT))
                s.sendall(f"RV {term_before + 9} 10.0.0.254 AA:BB:CC:DD:EE:FF 0 0\n".encode())
        except OSError:
            pass
        time.sleep(1)
        if raft_state(tgt).get("current_term", 0) <= term_before + 1 and raft_state(tgt).get("leader_ip") != "10.0.0.254":
            dropped += 1
    results["outsider_injection_dropped"] = dropped
    results["outsider_injection_total"] = runs
    return results


PLAN = """
Attack-resilience campaign plan (Section 5):
  A (5.1)  replay and single-field modification of the authentication request
  B (5.2)  chosen-challenge / oracle query, with a genuine request as positive control
  C (5.3)  impersonation with a credential other than the enrolled one, genuine as positive control
           + structural exposure arithmetic (q Verifiers, k compromised)
  D (5.4)  captured Coordinator forces a removal without confirmation -> membership divergence
  E (5.4)  forged coordination messages: tampered-member usurpation refused (unvoted claim check),
           outsider injection dropped by the membership gate
Not exercised here (reason):
  firmware tampering detection      -> already measured in RQ1 Table 7 and RQ4 Table 10
  network partitions                -> availability, not an attack; needs real link cutting
  PUF environmental characterization -> needs controlled temperature/voltage hardware (A2 in the paper)
"""


def scenario_legit_removal(ips, runs):
    """Functional check that a legitimate removal still works with the Verifier-backed apply rule: a
    crashed node is detected, confirmed by its Verifiers, removed network-wide, and the network heals
    to N-1 members with the target redundancy."""
    observations = []
    for _ in range(runs):
        coord = pick_coordinator(ips)
        victim = next((ip for ip in ips if ip != coord), None)
        # Crash the victim (leaves the network without notice, as after a power loss).
        ec.send_command_via_proxy(victim, "/test/fault", "POST", ec.ESP32_API_PORT, {"fault": "crash"})
        survivors = [ip for ip in ips if ip != victim]
        healed = ec.wait_for_redundancy(survivors, len(ips) - 1, "attack_legit_removal", ec.MONITOR_WAIT_TIMEOUT_S)
        _, st = ec.coordinator_view(survivors)
        removed = st is not None and victim not in st.get("members", [])
        views_removed = sum(1 for ip in survivors if victim not in members_of(ip))
        observations.append({
            "victim": victim, "healed_to_n_minus_1": healed,
            "victim_removed_from_coordinator_view": removed,
            "members_that_removed_victim": views_removed, "survivors": len(survivors),
        })
        # Restore the full network for the next run / next scenario.
        ec.bootstrap_and_wait_redundancy(len(ips), "attack_legit_restore", ec.MONITOR_WAIT_TIMEOUT_S)
        ips = ec.wait_for_ips(len(ips), 180) or ips
    return {
        "section": "removal (functional)",
        "property": "A legitimately crashed node is removed network-wide and the network heals",
        "runs": observations,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--nodes", type=int, default=7)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--out", default="attack_results")
    ap.add_argument("--validate-only", action="store_true")
    ap.add_argument("--only", default="", help="comma-separated subset: legit,A,B,C,D,E")
    args = ap.parse_args()

    if args.validate_only:
        print(PLAN)
        return

    only = [x.strip() for x in args.only.split(",") if x.strip()]
    if only:
        return run_subset(args, only)

    os.makedirs(args.out, exist_ok=True)
    logger.add(os.path.join(args.out, "attack_campaign.log"), level="INFO")
    logger.info(f"Attack campaign: {args.nodes} nodes, {args.runs} runs/variant")

    campaign_id = f"attack_{args.nodes}_nodes"
    ips = ec.bootstrap_and_wait_redundancy(args.nodes, campaign_id, ec.MONITOR_WAIT_TIMEOUT_S)
    if not ips:
        logger.error("Bootstrap failed; aborting.")
        sys.exit(1)

    coord = pick_coordinator(ips)
    attacker_ip = next((ip for ip in ips if ip != coord), ips[0])
    prover_ip = next((ip for ip in ips if ip not in (attacker_ip, coord)), ips[-1])
    logger.info(f"Coordinator {coord}, attacker {attacker_ip}, prover {prover_ip}")

    report = {"timestamp": ts(), "nodes": args.nodes, "runs_per_variant": args.runs,
              "image": os.environ.get("SRAFT_BUILD_DIR", "build_attack"),
              "coordinator": coord, "attacker": attacker_ip, "prover": prover_ip, "scenarios": {}}

    logger.info("Scenario A (replay/modification)")
    report["scenarios"]["A_replay_modification"] = scenario_A(attacker_ip, prover_ip, args.runs)
    logger.info("Scenario B (oracle)")
    report["scenarios"]["B_chosen_challenge"] = scenario_B(attacker_ip, prover_ip, args.runs)
    logger.info("Scenario C (capture/collusion)")
    report["scenarios"]["C_capture_collusion"] = scenario_C(attacker_ip, args.runs)
    report["scenarios"]["C_exposure"] = exposure_arithmetic(ips)
    logger.info("Scenario D (captured Coordinator forces removal)")
    report["scenarios"]["D_coordinator_removal"] = scenario_D(list(ips), min(args.runs, 5))
    # D and E restore the network; re-read the live set.
    ips = ec.wait_for_ips(args.nodes, 180) or ips
    coord = pick_coordinator(ips)
    attacker_ip = next((ip for ip in ips if ip != coord), ips[0])
    logger.info("Scenario E (forged coordination messages)")
    report["scenarios"]["E_forged_messages"] = scenario_E(list(ips), attacker_ip, min(args.runs, 5))

    out_json = os.path.join(args.out, "attack_results.json")
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)
    write_outputs(report, args.out)
    logger.info(f"Done. Results in {args.out}")


def run_subset(args, only):
    """Runs only the requested scenarios (for re-testing a fix), re-bootstrapping before each as needed.
    Writes a self-contained JSON; does not overwrite the full-campaign outputs unless --out points there."""
    os.makedirs(args.out, exist_ok=True)
    logger.add(os.path.join(args.out, "attack_subset.log"), level="INFO")
    logger.info(f"Attack subset {only}: {args.nodes} nodes")
    report = {"timestamp": ts(), "nodes": args.nodes, "subset": only,
              "image": os.environ.get("SRAFT_BUILD_DIR", "build_attack"), "scenarios": {}}

    def fresh():
        ips = ec.bootstrap_and_wait_redundancy(args.nodes, "attack_subset", ec.MONITOR_WAIT_TIMEOUT_S)
        if not ips:
            logger.error("Bootstrap failed; aborting.")
            sys.exit(1)
        return ips

    if "legit" in only:
        logger.info("Functional: legitimate crash removal + heal")
        ips = fresh()
        report["scenarios"]["legit_removal"] = scenario_legit_removal(list(ips), min(args.runs, 3))
    if "D" in only:
        logger.info("Scenario D (captured Coordinator forces removal)")
        ips = fresh()
        report["scenarios"]["D_coordinator_removal"] = scenario_D(list(ips), min(args.runs, 5))
    if "A" in only or "B" in only or "C" in only or "E" in only:
        ips = fresh()
        coord = pick_coordinator(ips)
        atk = next((ip for ip in ips if ip != coord), ips[0])
        prov = next((ip for ip in ips if ip not in (atk, coord)), ips[-1])
        if "A" in only:
            report["scenarios"]["A_replay_modification"] = scenario_A(atk, prov, args.runs)
        if "B" in only:
            report["scenarios"]["B_chosen_challenge"] = scenario_B(atk, prov, args.runs)
        if "C" in only:
            report["scenarios"]["C_capture_collusion"] = scenario_C(atk, args.runs)
            report["scenarios"]["C_exposure"] = exposure_arithmetic(ips)
        if "E" in only:
            report["scenarios"]["E_forged_messages"] = scenario_E(list(ips), atk, min(args.runs, 5))

    with open(os.path.join(args.out, "attack_subset_results.json"), "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Subset done. Results in {args.out}")


def write_outputs(report, out_dir):
    """Writes the plottable CSV and the Markdown summary."""
    rows = []  # (scenario, property, numerator, denominator, kind)
    s = report["scenarios"]

    def frac(d, num, den):
        return d.get(num, 0), d.get(den, 0)

    a = s["A_replay_modification"]
    rows.append(("A", "modified request refused", *frac(a, "modified_refused", "modified_total")))
    rows.append(("A", "replayed request dropped", *frac(a, "replay_dropped", "replay_total")))
    b = s["B_chosen_challenge"]
    rows.append(("B", "invalid-proof query refused", *frac(b, "invalid_refused", "invalid_total")))
    rows.append(("B", "genuine request answered (control)", *frac(b, "genuine_answered", "genuine_total")))
    c = s["C_capture_collusion"]
    rows.append(("C", "impersonation rejected", *frac(c, "impersonation_rejected", "impersonation_total")))
    rows.append(("C", "genuine authentication accepted (control)", *frac(c, "genuine_accepted", "genuine_total")))
    d = s["D_coordinator_removal"]
    kept_ok = sum(1 for r in d.get("runs", []) if isinstance(r, dict) and r.get("kept_target", 0) > 0)
    rows.append(("D", "honest Verifier kept shard on unconfirmed order", kept_ok, len(d.get("runs", []))))
    e = s["E_forged_messages"]
    rows.append(("E", "tampered-member usurpation refused", *frac(e, "tampered_claim_refused", "tampered_claim_total")))
    rows.append(("E", "outsider injection dropped", *frac(e, "outsider_injection_dropped", "outsider_injection_total")))

    with open(os.path.join(out_dir, "attack_summary.csv"), "w") as f:
        f.write("scenario,property,successes,trials,rate\n")
        for sc, prop, num, den in rows:
            rate = (num / den) if den else 0.0
            f.write(f"{sc},{prop},{num},{den},{rate:.4f}\n")

    md = [f"# Attack-resilience results ({report['nodes']} nodes, {report['runs_per_variant']} runs/variant)",
          f"\nImage: `{report['image']}` (production build + dormant, runtime-armed adversary hooks). "
          f"Attacker {report['attacker']}, Coordinator {report['coordinator']}, Prover {report['prover']}.",
          "\n| Scenario | Property | Successes/Trials |",
          "|---|---|---|"]
    for sc, prop, num, den in rows:
        md.append(f"| {sc} | {prop} | {num}/{den} |")
    exp = s.get("C_exposure", {})
    if exp.get("verifiers_per_prover"):
        md.append(f"\n**Credential exposure (5.3).** With {exp['verifiers_per_prover']} Verifiers per Prover, "
                  "compromising *k* of them exposes *k* shards and leaves the rest able to authenticate the "
                  "Prover; the Prover stays verifiable while at least one honest Verifier remains.")
    md.append("\nExecuted on real boards (emulated adversary capabilities on real boards for C/D/E). "
              "Firmware tampering detection is in RQ1/RQ4; partitions and PUF environmental "
              "characterization are out of scope as stated in the paper.")
    with open(os.path.join(out_dir, "attack_summary.md"), "w") as f:
        f.write("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
