import requests
import threading
from loguru import logger
import sys
import os
import socket
import time
import csv
from datetime import datetime
import os
import argparse
import zipfile
import io
import json
import random

scripts_path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
if scripts_path not in sys.path:
    sys.path.insert(0, scripts_path)
    
from utils.utils import copy_firmware_to_raspberry, TAMPERED_BUILD_DIR

RASPBERRY_PI_IP = "raspberrypi.local"
DEPLOY_SERVER_URL = f"http://{RASPBERRY_PI_IP}:8000"
MONITOR_API_URL = f"http://{RASPBERRY_PI_IP}:9002"
MONITOR_SERVER_IP = RASPBERRY_PI_IP
MONITOR_SERVER_PORT = 9001
ESP32_API_PORT = 80

DEFAULT_ITERATIONS = 10
MIN_CLUSTER_SIZE_FOR_LOOP = 3
MAX_CLUSTER_SIZE_FOR_LOOP = 32
RAFT_MINIMUM_SIZE = 3
DEFAULT_SINGLE_RUN_NODES = 5
# Upper bound for a wait on the monitoring server (bootstrap, removal), so that a run that gets stuck
# goes on with the next scenario instead of blocking forever.
MONITOR_WAIT_TIMEOUT_S = 900
# Optional suffix of the campaign identifiers, so that repeated runs do not mix their data.
RUN_TAG = ""
# When set, only the SRAFT authentication is measured (the TLS and MQTTS baselines are skipped).
SRAFT_ONLY = False


def send_tcp_command(message: str, wait_for_reply: bool = False):
    """
    Helper to send a command to the TCP monitoring server.
    If wait_for_reply is True, it will block until a response is received.
    """
    reply = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if wait_for_reply:
                s.settimeout(MONITOR_WAIT_TIMEOUT_S)
            s.connect((MONITOR_SERVER_IP, MONITOR_SERVER_PORT))
            s.sendall(message.encode('utf-8'))
            
            if wait_for_reply:
                s.shutdown(socket.SHUT_WR)
                
                all_data = []
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    all_data.append(chunk)
                reply = b"".join(all_data).decode('utf-8')

    except Exception as e:
        logger.info(f"Error sending TCP command '{message}': {e}")
    return reply

# Suffix of the campaign identifiers sent to the monitoring server, unique to this execution: the server keeps
# every campaign in its database, and two executions with the same identifier (same size, iteration, and tag)
# would be merged, each phase going from a START of the first execution to an end of the second. The output
# folders keep the identifiers without the suffix.
RUN_STAMP = datetime.now().strftime("%Y%m%d%H%M%S")


def monitor_campaign_id(campaign_id: str) -> str:
    """Identifier of a campaign on the monitoring server for this execution."""
    return f"{campaign_id}_{RUN_STAMP}"


def export_report(campaign_id: str, output_dir: str):
    """Exports the reports of a campaign of this execution from the monitoring server into output_dir."""
    request_and_save_report(f"{MONITOR_API_URL}/campaign/export_one/{monitor_campaign_id(campaign_id)}", output_dir)


def set_monitoring_campaign(campaign_id: str):
    """Sets the test context on the monitoring server (identifier unique to this execution)."""
    logger.info(f"\nSetting monitoring campaign context to: '{monitor_campaign_id(campaign_id)}'")
    send_tcp_command(f"SET_CAMPAIGN:{monitor_campaign_id(campaign_id)}")

def trigger_deployment(offset: int, count: int, build_dir: str = None):
    """Makes a POST request to deploy firmware (build_dir defaults to the configured build)."""
    copy_firmware_to_raspberry(build_dir)
    url = f"{DEPLOY_SERVER_URL}/deploy"
    payload = {"offset": offset, "count": count}
    logger.info(f"Triggering deployment with offset={offset}, count={count}...")
    try:
        response = requests.post(url, json=payload)
        logger.info("Deployment triggered.")
    except requests.exceptions.RequestException as e:
        logger.info(f"Error triggering deployment: {e}")

def trigger_reset(offset: int, count: int):
    """Erases the flash of the devices (esptool erase-flash): the firmware must be deployed again afterwards."""
    url = f"{DEPLOY_SERVER_URL}/reset"
    payload = {"offset": offset, "count": count}
    logger.info(f"Triggering reset with offset={offset}, count={count}...")
    try:
        response = requests.post(url, json=payload)
        logger.info("Reset triggered.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error triggering reset: {e}")

def get_latest_leader_ip(known_ips: list):
    """Queries the new monitoring API to find the leader's IP from the known list."""
    url = f"{MONITOR_API_URL}/query/latest_leader"
    try:
        response = requests.get(url)
        response.raise_for_status()
        leader_ip = response.json().get("leader_ip")
        if leader_ip in known_ips:
            return leader_ip
        else:
            logger.warning(f"Monitor reported leader {leader_ip}, but it's not in our known list.")
            for ip in known_ips:
                try:
                    res = send_command_via_proxy(ip, "/status", "GET", ESP32_API_PORT)
                    if res and str(res.get("state", "")).lower() == "leader":
                        logger.success(f"Fallback successful: Found leader at {ip}")
                        return ip
                except:
                    pass
    except requests.exceptions.RequestException as e:
        logger.info(f"API Error getting leader IP: {e}")
    return None

def wait_for_ips(expected_count: int, timeout_seconds: int = 180) -> list:
    """Waits for nodes to come online by polling the monitoring server's API."""
    logger.info(f"Waiting for {expected_count} nodes to come online (timeout: {timeout_seconds}s)...")
    url = f"{MONITOR_API_URL}/query/online_nodes"
    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                ips = response.json().get("nodes", [])
                logger.info(f"   -> Discovered {len(ips)}/{expected_count} nodes...")
                if len(ips) >= expected_count:
                    logger.info(f"Found all {expected_count} nodes.")
                    ips.sort()
                    return ips[:expected_count]
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    
    ips_found = locals().get("ips", [])
    logger.info(f"Timeout! Only found {len(ips_found)} out of {expected_count} nodes.")
    ips_found.sort()
    return ips_found

def send_command_via_proxy(ip: str, path: str, method: str, port: int, payload: dict = None) -> dict | None:
    """
    Sends a command to a single node via the proxy and waits for/returns the response.
    Returns the ESP32's response body on success, otherwise None.
    """
    url = f"{DEPLOY_SERVER_URL}/nodes/send_command"
    proxy_payload = {
        "ip": ip, "path": path, "method": method, "port": port, 
        "protocol": "http", "payload": payload
    }
    try:
        response = requests.post(url, json=proxy_payload)
        response.raise_for_status()
        proxy_result = response.json()
        if proxy_result.get("result", {}).get("status") == "success":
            return proxy_result.get("result", {}).get("response_body")
        else:
            logger.error(f"Proxy reported failure for {ip}: {proxy_result.get('result', {}).get('detail')}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending command to proxy for node {ip}: {e}")
        return None

def broadcast_command_via_proxy(node_ips: list, path: str, method: str = "POST", port: int = 80, payload: dict = None):
    """Tells the server to broadcast a command with an optional payload to multiple nodes."""
    url = f"{DEPLOY_SERVER_URL}/nodes/broadcast_command"
    proxy_payload = {
        "ips": node_ips, 
        "path": path, 
        "method": method, 
        "port": port, 
        "protocol": "http",
        "payload": payload
    }
    try:
        requests.post(url, json=proxy_payload, timeout=None)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to trigger broadcast command via proxy: {e}")

def rest_api_answers(ip: str) -> bool:
    """True if the device answers an HTTP request (/system/stats answers 204 without a body when idle)."""
    try:
        response = requests.post(f"{DEPLOY_SERVER_URL}/nodes/send_command", timeout=30, json={
            "ip": ip, "path": "/system/stats", "method": "GET", "port": ESP32_API_PORT, "protocol": "http", "payload": None})
        result = response.json().get("result", {})
    except (requests.exceptions.RequestException, ValueError):
        return False
    # The proxy reports an empty body as a failure to parse it, but the device did answer.
    return result.get("status") == "success" or str(result.get("detail", "")).startswith("Expecting value")

def wait_for_rest_api(node_ips: list, timeout_seconds: int = 90) -> bool:
    """Waits until every device answers on its REST interface."""
    pending = list(node_ips)
    start = time.time()
    while pending and time.time() - start < timeout_seconds:
        pending = [ip for ip in pending if not rest_api_answers(ip)]
        if pending:
            logger.info(f"Waiting for the REST interface of {pending}...")
            time.sleep(3)
    if pending:
        logger.error(f"The REST interface of {pending} did not answer within {timeout_seconds}s.")
    return not pending

def trigger_start_on_nodes(node_ips: list, mode: str, cluster_size: int = 0):
    """
    Triggers the /start endpoint on multiple nodes in a specific mode: 'normal', 'join', or 'bootstrap' start
    SRAFT; 'baseline' enables only the TLS and MQTTS baselines, without starting any service of SRAFT.
    """
    if mode not in ["normal", "join", "bootstrap", "baseline"]:
        logger.error(f"Invalid start mode: '{mode}'. Must be 'normal', 'join', 'bootstrap', or 'baseline'.")
        return

    # The monitor may still list a device that is rebooting after the deployment: /start is sent only
    # when the REST interface of every device answers.
    wait_for_rest_api(node_ips)

    if mode == "bootstrap":
        # The list of excluded devices is permanent on the devices: a new test network starts from an empty one.
        broadcast_command_via_proxy(
            node_ips=node_ips,
            path="/test/clear_blacklist",
            method="POST",
            port=ESP32_API_PORT,
            payload={}
        )

    logger.info(f"Triggering /start in '{mode}' mode on {len(node_ips)} nodes via proxy...")
    start_payload = {"mode": mode}
    if mode == "bootstrap" and cluster_size > 0:
        start_payload["cluster_size"] = cluster_size
    
    broadcast_command_via_proxy(
        node_ips=node_ips,
        path="/start",
        method="POST",
        port=ESP32_API_PORT,
        payload=start_payload
    )
    
def request_node_leave(node_ip: str):
    """
    Asks a node to leave the network on its own (planned decommissioning).
    A healthy node that is still running cannot be removed: its verifiers would refuse.
    """
    logger.info(f"Requesting node {node_ip} to leave the network via proxy...")
    url = f"{DEPLOY_SERVER_URL}/nodes/send_command"
    proxy_payload = {
        "ip": node_ip, "path": "/leave", "method": "POST",
        "port": ESP32_API_PORT, "protocol": "http", "payload": {}
    }

    try:
        response = requests.post(url, json=proxy_payload)
        response.raise_for_status()
        return response.json().get("result", {}).get("status") == "success"
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending leave command to proxy for node {node_ip}: {e}")
        return False

def trigger_node_removal(master_ip: str, ip_to_remove: str):
    """
    Asks the master to remove a node. The master queues the removal and answers at once; the end of the
    removal is observed in its state (wait_for_redundancy).
    """
    logger.info(f"Requesting master at {master_ip} to remove node {ip_to_remove} via proxy...")
    payload = {"target_ip": ip_to_remove}
    
    url = f"{DEPLOY_SERVER_URL}/nodes/send_command"
    proxy_payload = {
        "ip": master_ip, "path": "/remove_node", "method": "POST", 
        "port": ESP32_API_PORT, "protocol": "http", "payload": payload
    }
    
    try:
        response = requests.post(url, json=proxy_payload)
        response.raise_for_status()
        
        proxy_result = response.json()
        if proxy_result.get("result", {}).get("status") == "success":
            logger.success(f"Proxy successfully executed /remove_node on {master_ip}.")
            esp_response = proxy_result.get("result", {}).get("response_body")
            if esp_response and esp_response.get("status") == "ok":
                return True
            else:
                logger.error(f"Master node {master_ip} failed to process removal: {esp_response}")
                return False
        else:
            logger.error(f"Proxy reported failure for {master_ip}: {proxy_result.get('result', {}).get('detail')}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending remove command to proxy for node {master_ip}: {e}")
        return False

# Pause after each measured authentication, so that the monitoring server has collected the statistics of
# an operation before the next one starts a phase on the same devices.
OPERATION_PAUSE_S = 3


def run_async_auth(ip: str, path: str, payload: dict, timeout_s: int = 60):
    """
    Starts an authentication on a device and waits for its outcome. The device runs it in its own task and
    is polled, so that its REST interface keeps answering the monitoring server meanwhile.
    Returns True or False, or None if the device did not start it or did not finish in time.
    """
    res = send_command_via_proxy(ip, path, "POST", ESP32_API_PORT, payload)
    if not res or res.get("status") != "started":
        logger.error(f"   -> {path} not started on {ip}: {res}")
        return None
    seq = res.get("seq")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(0.5)
        poll = send_command_via_proxy(ip, path, "POST", ESP32_API_PORT, {"poll": True})
        if poll and poll.get("seq") == seq and poll.get("status") == "done":
            return poll.get("authentication_passed") is True
    logger.error(f"   -> {path} on {ip} did not finish within {timeout_s}s")
    return None


def run_authentication_check(node_ips: list, campaign_id: str) -> int:
    """
    Triggers self-authentication synchronously on each node, checks the direct
    response, and returns the total success count.
    """
    if not node_ips:
        return 0

    logger.info(f"Running SYNCHRONOUS authentication check on {len(node_ips)} nodes...")

    successful_count = 0
    for ip in node_ips:
        logger.info(f"   -> Triggering auth on {ip} and waiting for result...")
        passed = run_async_auth(ip, "/request_authentication", {})
        if passed:
            successful_count += 1
            logger.success(f"   -> Auth SUCCESS for {ip}")
        else:
            logger.error(f"   -> Auth FAILED for {ip}. Outcome: {passed}")
        time.sleep(OPERATION_PAUSE_S)

    return successful_count

def run_baselines(n_nodes: int, campaign_id: str, rounds: int = 2):
    """
    TLS (full handshake and session resumption) and MQTTS baselines, measured apart from SRAFT: the devices are reset and started in 'baseline'
    mode, in which no service of SRAFT runs (no PUF, discovery, Raft, join, removal, periodic checks,
    connection pool, or HAtt prover), so that the baselines are measured on devices that run nothing else.
    The devices are erased and flashed again before. The results go to the same campaign as the SRAFT
    scenarios of the iteration. Every device
    authenticates rounds times with each scheme, as many runs as the SRAFT authentication before and
    after the removal.
    """
    logger.info(f"--- BASELINES (TLS, MQTTS) on {n_nodes} devices started without SRAFT ---")
    # /reset erases the flash of the devices: the firmware is written again, as for the SRAFT scenarios,
    # so that the baselines start from freshly flashed devices.
    trigger_reset(offset=0, count=n_nodes)
    trigger_deployment(offset=0, count=n_nodes)
    ips = wait_for_ips(expected_count=n_nodes, timeout_seconds=180)
    if len(ips) < n_nodes:
        logger.error(f"[{campaign_id}] Only {len(ips)}/{n_nodes} devices online for the baselines.")
        if not ips:
            return
    trigger_start_on_nodes(ips, "baseline")
    time.sleep(3)
    set_monitoring_campaign(campaign_id)
    for r in range(1, rounds + 1):
        logger.info(f"--- SCENARIO 4b: AUTHENTICATION (TLS, round {r}/{rounds}) ---")
        ok = run_tls_authentication_check(ips, campaign_id)
        logger.info(f"TLS auth: {ok}/{len(ips)} nodes passed")
        logger.info(f"--- SCENARIO 4d: AUTHENTICATION (TLS with session resumption, round {r}/{rounds}) ---")
        ok = run_tls_resumed_check(ips, campaign_id)
        logger.info(f"TLS resumed auth: {ok}/{len(ips)} nodes passed")
        logger.info(f"--- SCENARIO 4c: AUTHENTICATION (MQTTS, round {r}/{rounds}) ---")
        ok = run_mqtts_authentication_check(ips, campaign_id)
        logger.info(f"MQTTS auth: {ok}/{len(ips)} nodes passed")


def run_attestation_check(node_ips: list, campaign_id: str) -> dict:
    """
    Cost of a successful attestation (RQ1). Each device is attested once by one of its Verifiers, chosen at
    random, with HAtt bound to a CRP the Verifier holds for it. The request is sent to a random device: if
    it is not a Verifier of the target, it answers with the Verifiers of the target, and the request is
    sent again to one of them. The Verifier runs the attestation in its own task, so that it keeps answering
    the monitoring server, and reports its start and end, between which the monitoring server samples the
    devices; the outcome is then polled. Returns the count of each outcome.
    """
    counts = {"passed": 0, "failed": 0, "no_answer": 0, "error": 0}
    for target_ip in node_ips:
        others = [ip for ip in node_ips if ip != target_ip]
        if not others:
            break
        verifier_ip = random.choice(others)
        res = send_command_via_proxy(verifier_ip, "/request_attestation", "POST", ESP32_API_PORT, {"target_ip": target_ip})
        if res and res.get("status") == "not_verifier":
            verifiers = [ip for ip in res.get("verifiers", []) if ip in others]
            verifier_ip = random.choice(verifiers) if verifiers else None
            res = send_command_via_proxy(verifier_ip, "/request_attestation", "POST", ESP32_API_PORT,
                                         {"target_ip": target_ip}) if verifier_ip else None
        outcome = "error"
        if res and res.get("status") == "started":
            op_id = res.get("operation_id")
            deadline = time.time() + 60
            while time.time() < deadline:
                time.sleep(1)
                poll = send_command_via_proxy(verifier_ip, "/request_attestation", "POST", ESP32_API_PORT, {})
                if poll and poll.get("operation_id") == op_id and poll.get("attestation") != "running":
                    outcome = poll.get("attestation")
                    break
        counts[outcome if outcome in counts else "error"] += 1
        logger.info(f"[{campaign_id}]   -> attestation of {target_ip} by {verifier_ip}: {outcome}")
        # The next attestation starts only after the monitoring server has sampled this one.
        time.sleep(3)
    return counts


def wait_for_redundancy(ips: list, n_members: int, campaign_id: str, timeout_s: int = 900) -> bool:
    """
    Waits until the Coordinator, found among ips, lists n_members members and every member has the target
    number of Verifiers, i.e., until a bootstrap or a removal with its healing is complete.
    """
    start = time.time()
    while time.time() - start < timeout_s:
        time.sleep(5)
        leader_ip, state = coordinator_view(ips)
        if not state:
            continue
        members = len(state.get("members", []))
        min_ver, target = state.get("min_verifiers", -1), state.get("target_verifiers", 0)
        if members == n_members and target > 0 and min_ver >= target:
            logger.info(f"[{campaign_id}] Network ready after {time.time() - start:.0f}s: Coordinator {leader_ip}, "
                        f"{members} members, {min_ver}/{target} Verifiers each")
            return True
    logger.error(f"[{campaign_id}] The network was not ready after {timeout_s}s.")
    return False


def bootstrap_and_wait_redundancy(n_nodes: int, campaign_id: str, timeout_s: int = 900) -> list:
    """
    Bootstraps a network of n_nodes devices and waits until the Coordinator lists all of them as members
    and every member has the target number of Verifiers. Returns the IPs of the devices, or [] on failure.
    """
    trigger_reset(offset=0, count=n_nodes)
    trigger_deployment(offset=0, count=n_nodes)
    all_ips = wait_for_ips(expected_count=n_nodes, timeout_seconds=180)
    if len(all_ips) < n_nodes:
        logger.error(f"Could not bring all {n_nodes} nodes online.")
        return []
    trigger_start_on_nodes(all_ips, "bootstrap", cluster_size=n_nodes)
    return all_ips if wait_for_redundancy(all_ips, n_nodes, campaign_id, timeout_s) else []


def run_attestation_campaign(base_output_dir: str, n_nodes: int, iterations: int):
    """
    Attestation scenario (RQ1): for each iteration, the network of n_nodes devices is bootstrapped under a
    separate campaign identifier, then every device is attested once under the campaign of the iteration,
    whose report (report_scenario_attestation.xlsx) contains only the attestations.
    """
    for i in range(1, iterations + 1):
        campaign_id = f"size_{n_nodes}_iter_{i}_attestation" + (f"_{RUN_TAG}" if RUN_TAG else "")
        output_dir = os.path.join(base_output_dir, "attestation" + (f"_{RUN_TAG}" if RUN_TAG else ""), f"size_{n_nodes}", f"iter_{i}")
        if os.path.exists(os.path.join(output_dir, "report_scenario_attestation.xlsx")):
            logger.warning(f"Results for {campaign_id} already exist at '{output_dir}'. Skipping.")
            continue
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"\n{'='*70}\nATTESTATION TEST: Size={n_nodes}, Iteration={i}/{iterations} (Campaign: {campaign_id})\n{'='*70}")

        set_monitoring_campaign(f"{campaign_id}_setup")
        current_ips = bootstrap_and_wait_redundancy(n_nodes, f"{campaign_id}_setup")
        if not current_ips:
            logger.error(f"Failed to setup cluster for {campaign_id}. Skipping to next iteration.")
            trigger_reset(0, n_nodes)
            time.sleep(5)
            continue
        time.sleep(5)

        # Role of each device, so that the per-device samples of the report can be split by role.
        devices = []
        for ip in current_ips:
            state = send_command_via_proxy(ip, "/raft/state", "GET", ESP32_API_PORT) or {}
            devices.append({"ip": ip, "mac": str(state.get("esp_mac", "")).upper(), "state": state.get("state")})

        set_monitoring_campaign(campaign_id)
        counts = run_attestation_check(current_ips, campaign_id)
        logger.info(f"[{campaign_id}] Attestations: {counts}")
        with open(os.path.join(output_dir, "attestation_outcomes.json"), "w") as f:
            json.dump({"campaign_id": campaign_id, "network_size": n_nodes, "devices": devices, "outcomes": counts}, f, indent=2)

        export_report(campaign_id, output_dir)
        trigger_reset(0, n_nodes)
        time.sleep(10)


def set_https_server(ip: str, enable: bool):
    """Starts or stops the HTTPS server (target of the TLS baseline) of one node."""
    send_command_via_proxy(ip, "/test/https_server", "POST", ESP32_API_PORT, {"enable": enable})


def run_tls_authentication_check(node_ips: list, campaign_id: str) -> int:
    """
    Triggers TLS authentication synchronously on each node via the Raspberry proxy.
    Uses /request_authentication_tls endpoint. Each node authenticates against the next node of the
    list, whose HTTPS server is the only one running during that request.
    """
    if not node_ips:
        return 0

    logger.info(f"Running SYNCHRONOUS TLS authentication check on {len(node_ips)} nodes...")

    successful_count = 0
    for i, ip in enumerate(node_ips):
        target_ip = node_ips[(i + 1) % len(node_ips)] if len(node_ips) > 1 else ip
        set_https_server(target_ip, True)
        time.sleep(1)
        try:
            logger.info(f"   -> Triggering TLS auth on {ip} against {target_ip} via proxy...")
            passed = run_async_auth(ip, "/request_authentication_tls", {"target_ip": target_ip})
        finally:
            set_https_server(target_ip, False)

        if passed:
            successful_count += 1
            logger.success(f"   -> TLS Auth SUCCESS for {ip}")
        else:
            logger.error(f"   -> TLS Auth FAILED for {ip}. Outcome: {passed}")
        time.sleep(OPERATION_PAUSE_S)

    return successful_count

def run_tls_resumed_check(node_ips: list, campaign_id: str) -> int:
    """
    TLS with session resumption (RFC 5077 session tickets). Each node first completes a full handshake with
    the next node of the list, which is not measured and only establishes the session, then resumes that
    session in a new connection; the resumption is the measured authentication ("TLS_RESUMED"). The HTTPS
    server of the target keeps running between the two connections, so that it still holds the key of the
    ticket. A run counts as passed only if the session was actually resumed.
    """
    if not node_ips:
        return 0

    logger.info(f"Running TLS resumption check on {len(node_ips)} nodes...")
    successful_count = 0
    for i, ip in enumerate(node_ips):
        target_ip = node_ips[(i + 1) % len(node_ips)] if len(node_ips) > 1 else ip
        set_https_server(target_ip, True)
        time.sleep(1)
        try:
            logger.info(f"   -> Full handshake of {ip} with {target_ip} (session to resume, not measured)...")
            primed = run_async_auth(ip, "/request_authentication_tls", {"target_ip": target_ip, "mode": "prime"})
            passed = None
            if primed:
                time.sleep(OPERATION_PAUSE_S)
                logger.info(f"   -> Resumption of the session of {ip} with {target_ip}...")
                passed = run_async_auth(ip, "/request_authentication_tls", {"target_ip": target_ip, "mode": "resumed"})
            else:
                logger.error(f"   -> Full handshake of {ip} with {target_ip} failed: no session to resume")
        finally:
            set_https_server(target_ip, False)

        if passed:
            successful_count += 1
            logger.success(f"   -> TLS resumption SUCCESS for {ip}")
        else:
            logger.error(f"   -> TLS resumption FAILED for {ip}. Outcome: {passed}")
        time.sleep(OPERATION_PAUSE_S)

    return successful_count


def set_mqtts_responder(ip: str, enable: bool) -> bool:
    """
    Starts or stops the MQTTS auth responder of one node. The responder keeps a TLS connection to the
    broker, so it runs only on the node that is the target of the current request. When it is started,
    the node answers only once the responder is subscribed to its request topic; returns whether it is.
    """
    res = send_command_via_proxy(ip, "/test/mqtts_responder", "POST", ESP32_API_PORT, {"enable": enable})
    return bool(res) and res.get("status") == "ok"


def run_mqtts_authentication_check(node_ips: list, campaign_id: str) -> int:
    """
    Triggers MQTTS authentication synchronously on each node via the Raspberry proxy.
    Uses /request_authentication_mqtts endpoint. Each node authenticates against the next node of the
    list, whose responder is the only one running during that request, so that no node holds two TLS
    sessions at the same time.
    """
    if not node_ips:
        return 0

    logger.info(f"Running SYNCHRONOUS MQTTS authentication check on {len(node_ips)} nodes...")

    successful_count = 0
    for i, ip in enumerate(node_ips):
        target_ip = node_ips[(i + 1) % len(node_ips)] if len(node_ips) > 1 else ip
        if not set_mqtts_responder(target_ip, True):
            logger.warning(f"   -> MQTTS responder of {target_ip} not subscribed: the request may be lost")
        try:
            logger.info(f"   -> Triggering MQTTS auth on {ip} against {target_ip} via proxy...")
            passed = run_async_auth(ip, "/request_authentication_mqtts", {"target_ip": target_ip})
        finally:
            set_mqtts_responder(target_ip, False)

        if passed:
            successful_count += 1
            logger.success(f"   -> MQTTS Auth SUCCESS for {ip}")
        else:
            logger.error(f"   -> MQTTS Auth FAILED for {ip}. Outcome: {passed}")
        time.sleep(OPERATION_PAUSE_S)

    return successful_count

def request_and_save_report(url: str, output_dir: str):
    """
    Requests a report ZIP from the monitoring server and extracts it.
    """
    logger.info(f"Requesting report from {url}...")
    try:
        response = requests.post(url, timeout=None) 
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(output_dir)
        logger.success(f"Report successfully saved and extracted to '{output_dir}'")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get report from monitoring server: {e}")
    except zipfile.BadZipFile:
        logger.error("Failed to extract report: Monitor returned invalid ZIP file.")
    except Exception as e:
        logger.error(f"An unexpected error occurred during report extraction: {e}")

def setup_cluster(n_nodes: int, campaign_id: str) -> list:
    """
    Orchestrates the setup of a cluster of a specific size.
    This is SCENARIO 2: JOIN
    """
    logger.info(f"--- Setting up cluster for {campaign_id} (Size: {n_nodes}) ---")
    
    trigger_reset(offset=0, count=n_nodes)
    trigger_deployment(offset=0, count=n_nodes)
    
    all_ips = wait_for_ips(expected_count=n_nodes, timeout_seconds=180)
    if len(all_ips) < n_nodes:
        logger.error(f"Could not bring all {n_nodes} nodes online. Aborting campaign.")
        return []
        
    trigger_start_on_nodes(all_ips, "bootstrap", cluster_size=n_nodes)
    
    logger.info(f"[{campaign_id}] Waiting for bootstrap heal to complete...")
    # The state of the Coordinator is polled instead of waiting for WAIT_FOR_BOOTSTRAP_HEAL, whose reply
    # was sometimes never sent although the bootstrap had completed.
    wait_for_redundancy(all_ips, n_nodes, campaign_id, MONITOR_WAIT_TIMEOUT_S)
    time.sleep(5)
    logger.info(f"[{campaign_id}] Bootstrap heal completed.")
    
    leader_ip = get_latest_leader_ip(all_ips)
    if not leader_ip:
        logger.error(f"[{campaign_id}] Could not determine leader after startup. Aborting.")
        return []
    
    logger.info(f"[{campaign_id}] Cluster setup complete. Leader at {leader_ip}.")
    return all_ips

def run_single_removal(known_ips: list, campaign_id: str) -> list:
    """
    Orchestrates the removal of a single node from a cluster.
    This is SCENARIO 3: REMOVAL
    """
    logger.info(f"--- Running single removal for {campaign_id} ---")
    
    master_ip = None
    for attempt in range(5):
        master_ip = get_latest_leader_ip(known_ips)
        if master_ip:
            logger.success(f"Leader found at {master_ip}")
            break
        logger.warning(f"Attempt {attempt+1}/5: Leader not found. Retrying in 3 seconds...")
        time.sleep(3)
    
    if not master_ip:
        logger.error(f"[{campaign_id}] CRITICAL ERROR: Could not determine the cluster leader. Aborting removal test.")
        return known_ips

    node_to_remove = next((ip for ip in reversed(known_ips) if ip != master_ip), None)
    if not node_to_remove:
        logger.error(f"[{campaign_id}] CRITICAL ERROR: Could not select a non-master node to remove. Aborting.")
        return known_ips
        
    known_ips_after_removal = [ip for ip in known_ips if ip != node_to_remove]
    
    logger.info(f"[{campaign_id}] Taking {node_to_remove} offline before its removal...")
    request_node_leave(node_to_remove)
    time.sleep(1)

    logger.info(f"[{campaign_id}] Requesting removal of {node_to_remove}...")
    trigger_node_removal(master_ip, node_to_remove)
    
    logger.info(f"[{campaign_id}] Waiting for REMOVE+HEAL to complete...")
    wait_for_redundancy(known_ips_after_removal, len(known_ips_after_removal), campaign_id, MONITOR_WAIT_TIMEOUT_S)
    time.sleep(5)
    logger.info(f"[{campaign_id}] Confirmation received. Cluster is stable.")
    
    return known_ips_after_removal

def run_integrity_failure_test(n_nodes: int, campaign_id: str):
    """
    Failed-attestation scenario: the last of the n_nodes devices runs the tampered test image, in which
    4 KB of the attestation test region of the reference image are overwritten with random bytes
    (make_tampered_image.py), and the network is bootstrapped. The tampered device fails the attestation of the Coordinator
    at join (and of the voters if it stands for election) and is excluded.
    """
    logger.info(f"--- SCENARIO INTEGRITY FAILURE (Size: {n_nodes}, 1 tampered device) ---")

    trigger_reset(offset=0, count=n_nodes)
    trigger_deployment(offset=0, count=n_nodes - 1)
    logger.info(f"[{campaign_id}] Deploying the tampered image ({TAMPERED_BUILD_DIR}) on the last device...")
    trigger_deployment(offset=n_nodes - 1, count=1, build_dir=TAMPERED_BUILD_DIR)
    all_ips = wait_for_ips(expected_count=n_nodes, timeout_seconds=180)
    if len(all_ips) < n_nodes:
        logger.error(f"Could not bring all {n_nodes} nodes online. Aborting test.")
        return

    set_monitoring_campaign(campaign_id)

    logger.info(f"[{campaign_id}] Triggering /start in 'bootstrap' mode...")
    trigger_start_on_nodes(all_ips, "bootstrap", cluster_size=n_nodes)

    logger.info(f"[{campaign_id}] Waiting for the end of the bootstrap...")
    # A single waiter: the monitor clears the completion event after answering the first one.
    if send_tcp_command("WAIT_FOR_BOOTSTRAP_HEAL", wait_for_reply=True) == "OK":
        logger.success(f"[{campaign_id}] Bootstrap with a tampered device completed.")
    else:
        logger.error(f"[{campaign_id}] The bootstrap with a tampered device did not complete.")

def coordinator_view(ips: list):
    """Returns (ip, state) of the device that reports itself as Coordinator, or (None, None)."""
    for ip in ips:
        res = send_command_via_proxy(ip, "/raft/state", "GET", ESP32_API_PORT)
        if res and str(res.get("state", "")).lower() == "leader":
            return ip, res
    return None, None

def run_fault_scenario(n_nodes: int, campaign_id: str, output_dir: str, fault: str, count: int,
                       include_coordinator: bool, timeout_s: int = 1500):
    """
    Resilience to faults that the network has to detect by itself. After the bootstrap, count devices fail
    at the same time ("crash": they leave the network without notice) or have their software altered while
    they run ("tamper": the attestation test region is rewritten in flash). The Coordinator is among them if
    include_coordinator is set. No removal is requested by the orchestrator: the failures are detected by the
    periodic checks of the Verifiers and by the election. The scenario records when a new Coordinator is in
    place (if needed), when the faulty devices are no longer members, and when every member has again
    ceil(rho N) Verifiers; then the remaining devices authenticate each other.
    """
    logger.info(f"--- SCENARIO FAULTS ({fault}, {count} device(s), coordinator included: {include_coordinator}) ---")
    # The coordination functions need a majority of the devices, so count simultaneous faults can be
    # tolerated only with at least 2 * count + 1 devices. Below that the scenario is not run.
    min_nodes = 2 * count + 1
    if n_nodes < min_nodes:
        logger.warning(f"[{campaign_id}] {count} simultaneous fault(s) need at least {min_nodes} devices, "
                       f"{n_nodes} available: scenario not run.")
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "fault_result.json"), "w") as f:
            json.dump({"fault": fault, "faulty_devices": count, "coordinator_included": include_coordinator,
                       "network_size": n_nodes, "skipped": f"below the minimum of {min_nodes} devices"}, f, indent=2)
        return
    set_monitoring_campaign(campaign_id)
    all_ips = setup_cluster(n_nodes, campaign_id)
    if len(all_ips) < n_nodes:
        return
    leader_ip, _ = coordinator_view(all_ips)
    if not leader_ip:
        logger.error(f"[{campaign_id}] No Coordinator found. Aborting.")
        return

    others = [ip for ip in all_ips if ip != leader_ip]
    victims = ([leader_ip] if include_coordinator else []) + others[::-1]
    victims = victims[:count]
    survivors = [ip for ip in all_ips if ip not in victims]
    logger.info(f"[{campaign_id}] Coordinator {leader_ip}; faulty devices {victims}")

    t0 = time.time()
    for ip in victims:
        payload = {"fault": "crash"} if fault == "crash" else {"fault": "tamper", "bytes": 4096}
        res = send_command_via_proxy(ip, "/test/fault", "POST", ESP32_API_PORT, payload)
        logger.info(f"[{campaign_id}] Fault '{fault}' injected on {ip}: {res}")

    times = {"new_coordinator_s": None, "removed_s": None, "restored_s": None}
    last = {}
    while time.time() - t0 < timeout_s:
        time.sleep(5)
        ip, state = coordinator_view(survivors)
        elapsed = round(time.time() - t0, 1)
        if not ip:
            continue
        if include_coordinator and times["new_coordinator_s"] is None:
            times["new_coordinator_s"] = elapsed
            logger.info(f"[{campaign_id}] New Coordinator {ip} after {elapsed}s")
        members = state.get("members", [])
        min_ver, target = state.get("min_verifiers", -1), state.get("target_verifiers", 0)
        if (members, min_ver) != (last.get("members"), last.get("min")):
            logger.info(f"[{campaign_id}] t={elapsed}s members={members} min_verifiers={min_ver}/{target}")
            last = {"members": members, "min": min_ver}
        if times["removed_s"] is None and not any(v in members for v in victims):
            times["removed_s"] = elapsed
            logger.info(f"[{campaign_id}] Faulty devices removed after {elapsed}s")
        if times["removed_s"] is not None and min_ver >= target:
            times["restored_s"] = elapsed
            logger.info(f"[{campaign_id}] Redundancy restored after {elapsed}s")
            break

    auth_ok = run_authentication_check(survivors, campaign_id) if times["restored_s"] is not None else 0
    result = {"fault": fault, "faulty_devices": count, "coordinator_included": include_coordinator,
              "network_size": n_nodes, "times": times, "authenticated_after": auth_ok, "survivors": len(survivors)}
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "fault_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    if times["restored_s"] is None:
        logger.error(f"[{campaign_id}] The network did not recover within {timeout_s}s: {times}")
    else:
        logger.success(f"[{campaign_id}] Recovered: {times}, {auth_ok}/{len(survivors)} devices authenticated")

def wilson_interval(successes: int, n: int, z: float = 1.96):
    """95% Wilson score interval of a proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return (max(0.0, centre - half), min(1.0, centre + half))

def discover_device_images(expected: dict, n_nodes: int, timeout_seconds: int = 240) -> dict:
    """
    Starts the HAtt Prover on the online devices and maps the identifier of the image each one runs
    to its IP addresses, until every image of expected ({image_id: number of devices}) is found.
    """
    start = time.time()
    found = {}
    while time.time() - start < timeout_seconds:
        found = {}
        # All the devices are queried: the ones of a previous round are online too.
        for ip in wait_for_ips(expected_count=n_nodes, timeout_seconds=60):
            res = send_command_via_proxy(ip, "/test/hatt", "POST", ESP32_API_PORT, {"prover": True})
            if res and res.get("image"):
                found.setdefault(res["image"], []).append(ip)
        if all(len(found.get(image, [])) >= count for image, count in expected.items()):
            return found
        logger.info(f"Images found so far: {found}; waiting for {expected}...")
        time.sleep(10)
    logger.error(f"Not all the images were found: {found}")
    return found

def measure_detection(verifier_ip: str, target_ip: str, runs: int, batch: int) -> dict:
    """The verifier attests the target runs times, in batches, one attestation at a time."""
    counts = {"passed": 0, "failed": 0, "no_answer": 0}
    done = 0
    while done < runs:
        n = min(batch, runs - done)
        res = send_command_via_proxy(verifier_ip, "/test/hatt", "POST", ESP32_API_PORT, {"target_ip": target_ip, "runs": n})
        if not res:
            logger.error(f"   -> batch of {n} attestations of {target_ip} failed, retrying")
            time.sleep(5)
            continue
        for key in counts:
            counts[key] += int(res.get(key, 0))
        done += n
        logger.info(f"   -> {target_ip}: {done}/{runs} attestations, {counts}")
    return counts

def run_detection_test(n_nodes: int, campaign_id: str, output_dir: str):
    """
    Detection rate of the attestation. Two devices run the reference image: one attests the others, and
    the second is a control that must always pass. The other devices run tampered images, in which part of
    the attestation test region was overwritten with random bytes (make_tampered_image.py), several rounds
    being run if there are more images than devices. Each device is attested the same number of times with
    fresh seeds, and the measured rate is compared with the probability predicted for its image.
    The cases are read from the file named by SRAFT_DETECTION_CASES, written by pipeline.py.
    """
    with open(os.environ["SRAFT_DETECTION_CASES"]) as f:
        cfg = json.load(f)
    runs, batch, reference = cfg["runs"], cfg["batch"], cfg["reference"]
    cases = cfg["cases"]
    slots = n_nodes - 2
    logger.info(f"--- SCENARIO ATTESTATION DETECTION ({len(cases)} tampered images, {runs} attestations each) ---")

    trigger_reset(offset=0, count=n_nodes)
    trigger_deployment(offset=0, count=2, build_dir=reference["build_dir"])
    control = {"name": "reference image (control)", "size": 0, "image_id": reference["image_id"], "predicted": 0.0}
    rows = []
    for first in range(0, len(cases), slots):
        round_cases = cases[first:first + slots]
        for j, case in enumerate(round_cases):
            logger.info(f"[{campaign_id}] Deploying the image with {case['size']} tampered bytes on device {2 + j}...")
            trigger_deployment(offset=2 + j, count=1, build_dir=case["build_dir"])
        expected = {reference["image_id"]: 2}
        for case in round_cases:
            expected[case["image_id"]] = 1
        images = discover_device_images(expected, n_nodes)
        if len(images.get(reference["image_id"], [])) < 2:
            logger.error("The two devices with the reference image were not found. Aborting.")
            break
        verifier_ip, control_ip = images[reference["image_id"]][:2]
        targets = ([(control, control_ip)] if first == 0 else []) + \
                  [(case, images[case["image_id"]][0]) for case in round_cases if images.get(case["image_id"])]
        for case, target_ip in targets:
            logger.info(f"[{campaign_id}] {verifier_ip} attests {target_ip} ({case['name']}) {runs} times...")
            t0 = time.time()
            counts = measure_detection(verifier_ip, target_ip, runs, batch)
            answered = counts["passed"] + counts["failed"]
            low, high = wilson_interval(counts["failed"], answered)
            row = {"case": case["name"], "tampered_bytes": case["size"], "image_id": case["image_id"],
                   "changed_words": case.get("changed_words", 0), "changed_bits": case.get("changed_bits", 0),
                   "attestations": answered, "detected": counts["failed"], "no_answer": counts["no_answer"],
                   "measured_rate": counts["failed"] / answered if answered else 0.0,
                   "ci95_low": low, "ci95_high": high, "predicted_rate": case["predicted"],
                   "duration_s": round(time.time() - t0, 1)}
            rows.append(row)
            logger.success(f"[{campaign_id}] {case['name']}: detected {counts['failed']}/{answered} "
                           f"({row['measured_rate']:.3f}, 95% CI {low:.3f}-{high:.3f}), predicted {case['predicted']:.3f}")

    os.makedirs(output_dir, exist_ok=True)
    if rows:
        with open(os.path.join(output_dir, "detection.csv"), "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    with open(os.path.join(output_dir, "detection.json"), "w") as f:
        json.dump({"config": cfg, "results": rows}, f, indent=2)
    logger.info(f"[{campaign_id}] Results saved in {output_dir}")

def run_experiment_loop(base_output_dir: str, node_sizes_to_test: list, min_nodes: int, max_nodes: int, iterations: int):
    logger.info(f"========== STARTING EXPERIMENT LOOP ==========")
    logger.info(f"Node Range: {min_nodes} to {max_nodes}")
    logger.info(f"Iterations per Size: {iterations}")
    
    for n_nodes in node_sizes_to_test:
        for i in range(1, iterations + 1):
            if len(node_sizes_to_test) == 1 and iterations == 1:
                campaign_id = f"single_run_{n_nodes}_nodes"
                output_dir = os.path.join(base_output_dir, campaign_id)
            else:
                campaign_id = f"size_{n_nodes}_iter_{i}"
                output_dir = os.path.join(base_output_dir, f"size_{n_nodes}", f"iter_{i}")
            
            if min_nodes == max_nodes and iterations == 1:
                campaign_id = f"single_run_{n_nodes}_nodes"
                output_dir = os.path.join(base_output_dir, campaign_id)
            else:
                campaign_id = f"size_{n_nodes}_iter_{i}"
                output_dir = os.path.join(base_output_dir, f"size_{n_nodes}", f"iter_{i}")

            if RUN_TAG:
                campaign_id = f"{campaign_id}_{RUN_TAG}"
                output_dir = f"{output_dir}_{RUN_TAG}"
                
            report_file_to_check = os.path.join(output_dir, "report_global_summary.xlsx")
            if os.path.exists(report_file_to_check):
                logger.warning(f"Results for {campaign_id} already exist at '{output_dir}'. Skipping.")
                continue
            
            os.makedirs(output_dir, exist_ok=True)
            
            logger.info(f"\n{'='*70}")
            logger.info(f"STARTING TEST: Size={n_nodes}, Iteration={i}/{iterations} (Campaign: {campaign_id})")
            logger.info(f"{'='*70}")

            set_monitoring_campaign(campaign_id)
            logger.info(f"--- SCENARIO 2: JOIN (Bootstrap) ---")
            current_ips = setup_cluster(n_nodes, campaign_id)
            time.sleep(3)
            if not current_ips:
                logger.error(f"Failed to setup cluster for {campaign_id}. Skipping to next iteration.")
                trigger_reset(0, n_nodes)
                time.sleep(5)
                continue
            
            # Role of each device after the bootstrap, so that the per-device samples can be split by role.
            devices = []
            for ip in current_ips:
                state = send_command_via_proxy(ip, "/raft/state", "GET", ESP32_API_PORT) or {}
                devices.append({"ip": ip, "mac": str(state.get("esp_mac", "")).upper(), "state": state.get("state")})
            with open(os.path.join(output_dir, "devices.json"), "w") as f:
                json.dump({"campaign_id": campaign_id, "network_size": n_nodes, "devices": devices}, f, indent=2)

            logger.info(f"--- SCENARIO 4a: AUTHENTICATION (Post-Join - SRAFT Protocol) ---")
            sraft_successes = run_authentication_check(current_ips, campaign_id)
            logger.info(f"SRAFT auth: {sraft_successes}/{len(current_ips)} nodes passed")
            
            if n_nodes >= RAFT_MINIMUM_SIZE:
                logger.info(f"--- SCENARIO 3: REMOVAL (Post-Join) ---")
                ips_after_removal = run_single_removal(current_ips, campaign_id)
                time.sleep(3)
                logger.info(f"--- SCENARIO 4: AUTHENTICATION (Post-Removal) ---")
                logger.info(f"--- SCENARIO 4a: AUTHENTICATION (Post-Removal - SRAFT Protocol) ---")
                sraft_after = run_authentication_check(ips_after_removal, campaign_id)
                logger.info(f"SRAFT auth (post-removal): {sraft_after}/{len(ips_after_removal)} nodes passed")

            else:
                logger.info(f"Skipping SCENARIO 3 (Removal) for cluster size < {RAFT_MINIMUM_SIZE}")
                
            if not SRAFT_ONLY:
                run_baselines(n_nodes, campaign_id)

            logger.info(f"--- GENERATING REPORT for {campaign_id} ---")
            export_report(campaign_id, output_dir)

            logger.info(f"FINISHED TEST: Size={n_nodes}, Iteration={i}")
            logger.info(f"Resetting all {n_nodes} nodes before next iteration...")
            trigger_reset(0, n_nodes)
            time.sleep(10)

    logger.info("========== EXPERIMENT LOOP COMPLETE ==========")
    
    if max_nodes >= 32:
        logger.info(f"\n{'='*70}")
        logger.info(f"STARTING RQ1 INTEGRITY TEST (Size=32, Iteration=1)")
        logger.info(f"{'='*70}")
        
        rq1_campaign_id = "rq1_integrity_failure_test"
        rq1_output_dir = os.path.join(base_output_dir, rq1_campaign_id)
        os.makedirs(rq1_output_dir, exist_ok=True)

        run_integrity_failure_test(32, rq1_campaign_id)
        
        logger.info(f"--- GENERATING REPORT for {rq1_campaign_id} ---")
        export_report(rq1_campaign_id, rq1_output_dir)
        
        logger.info(f"FINISHED RQ1 TEST. Resetting nodes.")
        trigger_reset(0, 32)
        time.sleep(10)
    else:
        logger.warning(f"Skipping RQ1 integrity test, max nodes ({max_nodes}) is less than 32.")
    
    # The final analysis aggregates every campaign in the database, so it is exported only for the full
    # experiment.
    if len(node_sizes_to_test) == 1:
        return
    logger.info("--- GENERATING FINAL ANALYSIS REPORT ---")
    final_report_url = f"{MONITOR_API_URL}/campaign/export_final_analysis"
    request_and_save_report(final_report_url, base_output_dir)
    logger.info(f"Final analysis saved to '{base_output_dir}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ESP32 Cluster Test Orchestrator")
    parser.add_argument(
        '--full-experiment',
        action='store_true',
        help="Run the full experiment loop (3-32 nodes, 10 iterations each)."
    )
    parser.add_argument(
        '-n', '--nodes',
        type=int,
        default=DEFAULT_SINGLE_RUN_NODES,
        help=f"[Single Run] Run a single experiment with this many nodes (default: {DEFAULT_SINGLE_RUN_NODES})."
    )
    parser.add_argument(
        '-i', '--iterations',
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"[Full Experiment] Number of iterations per cluster size (default: {DEFAULT_ITERATIONS})."
    )
    parser.add_argument(
        '--tag',
        type=str,
        default="",
        help="Suffix appended to the campaign identifiers and output folders (e.g. a timestamp)."
    )
    parser.add_argument(
        '--sraft-only',
        action='store_true',
        help="Measure only the SRAFT authentication (skip the TLS and MQTTS baselines)."
    )
    parser.add_argument(
        '--integrity-test',
        action='store_true',
        help="[Single Run] Run only the failed-attestation scenario with -n devices, the last one tampered."
    )
    parser.add_argument(
        '--fault',
        choices=['crash', 'tamper'],
        help="Resilience scenario: devices crash or have their software altered while they run."
    )
    parser.add_argument(
        '--fault-count', type=int, default=1,
        help="Number of devices hit by the fault at the same time."
    )
    parser.add_argument(
        '--fault-coordinator', action='store_true',
        help="Include the Coordinator among the faulty devices."
    )
    parser.add_argument(
        '--loop', action='store_true',
        help="Run the standard scenarios (join, authentication, removal) -i times with -n devices."
    )
    parser.add_argument(
        '--out', type=str, default="experiment_results",
        help="Base folder of the results."
    )
    parser.add_argument(
        '--attestation-test',
        action='store_true',
        help="Cost of a successful attestation: -i iterations with -n devices, each device attested once by one of its Verifiers."
    )
    parser.add_argument(
        '--detection-test',
        action='store_true',
        help="Measure the detection rate of the attestation on tampered images (cases from SRAFT_DETECTION_CASES)."
    )
    args = parser.parse_args()
    RUN_TAG = args.tag
    SRAFT_ONLY = args.sraft_only

    base_output_dir = args.out
    if args.loop:
        run_experiment_loop(base_output_dir, [args.nodes], args.nodes, args.nodes, args.iterations)
    elif args.full_experiment:
        test_sizes = list(range(MIN_CLUSTER_SIZE_FOR_LOOP, MAX_CLUSTER_SIZE_FOR_LOOP, 2))
        if MAX_CLUSTER_SIZE_FOR_LOOP not in test_sizes:
            test_sizes.append(MAX_CLUSTER_SIZE_FOR_LOOP)
        
        run_experiment_loop(
            base_output_dir, 
            test_sizes,
            MIN_CLUSTER_SIZE_FOR_LOOP,
            MAX_CLUSTER_SIZE_FOR_LOOP,
            args.iterations
        )
    elif args.fault:
        if args.nodes < 2 * args.fault_count + 1:
            # No campaign is started on the monitoring server, so no report is requested.
            run_fault_scenario(args.nodes, f"fault_{args.fault}_{args.fault_count}", os.path.join(
                base_output_dir, f"fault_{args.fault}_{args.fault_count}{'_coord' if args.fault_coordinator else ''}_{args.nodes}_nodes"
                + (f"_{RUN_TAG}" if RUN_TAG else "")), args.fault, args.fault_count, args.fault_coordinator)
            sys.exit(0)
        campaign_id = (f"fault_{args.fault}_{args.fault_count}{'_coord' if args.fault_coordinator else ''}_{args.nodes}_nodes"
                       + (f"_{RUN_TAG}" if RUN_TAG else ""))
        output_dir = os.path.join(base_output_dir, campaign_id)
        run_fault_scenario(args.nodes, campaign_id, output_dir, args.fault, args.fault_count, args.fault_coordinator)
        export_report(campaign_id, output_dir)
        trigger_reset(0, args.nodes)
    elif args.attestation_test:
        run_attestation_campaign(base_output_dir, args.nodes, args.iterations)
    elif args.detection_test:
        campaign_id = f"hatt_detection_{args.nodes}_nodes" + (f"_{RUN_TAG}" if RUN_TAG else "")
        run_detection_test(args.nodes, campaign_id, os.path.join(base_output_dir, campaign_id))
        trigger_reset(0, args.nodes)
    elif args.integrity_test:
        campaign_id = f"integrity_test_{args.nodes}_nodes" + (f"_{RUN_TAG}" if RUN_TAG else "")
        output_dir = os.path.join(base_output_dir, campaign_id)
        os.makedirs(output_dir, exist_ok=True)
        run_integrity_failure_test(args.nodes, campaign_id)
        export_report(campaign_id, output_dir)
        trigger_reset(0, args.nodes)
    else:
        if args.nodes > MAX_CLUSTER_SIZE_FOR_LOOP:
            logger.error(f"Node count ({args.nodes}) exceeds maximum supported ({MAX_CLUSTER_SIZE_FOR_LOOP}).")
        else:
            run_experiment_loop(
                base_output_dir, 
                [args.nodes],
                args.nodes,
                args.nodes,
                1
            )

    logger.info("\nOrchestration complete.")