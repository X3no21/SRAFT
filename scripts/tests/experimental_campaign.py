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

scripts_path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
if scripts_path not in sys.path:
    sys.path.insert(0, scripts_path)
    
from utils.utils import copy_firmware_to_raspberry

RASPBERRY_PI_IP = "iotlabvr.ddns.net"
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


def send_tcp_command(message: str, wait_for_reply: bool = False):
    """
    Helper to send a command to the TCP monitoring server.
    If wait_for_reply is True, it will block until a response is received.
    """
    reply = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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

def set_monitoring_campaign(campaign_id: str):
    """Sets the test context on the monitoring server."""
    logger.info(f"\nSetting monitoring campaign context to: '{campaign_id}'")
    send_tcp_command(f"SET_CAMPAIGN:{campaign_id}")

def trigger_deployment(offset: int, count: int):
    """Makes a POST request to deploy firmware."""
    copy_firmware_to_raspberry()
    url = f"{DEPLOY_SERVER_URL}/deploy"
    payload = {"offset": offset, "count": count}
    logger.info(f"Triggering deployment with offset={offset}, count={count}...")
    try:
        response = requests.post(url, json=payload)
        logger.info("Deployment triggered.")
    except requests.exceptions.RequestException as e:
        logger.info(f"Error triggering deployment: {e}")

def trigger_reset(offset: int, count: int):
    """Makes a POST request to reset all nodes."""
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
                    if res and res.get("state") == "LEADER":
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

def trigger_start_on_nodes(node_ips: list, mode: str, cluster_size: int = 0):
    """Triggers the /start endpoint on multiple nodes in a specific mode ('normal' or 'join' pr 'bootstrap')."""
    if mode not in ["normal", "join", "bootstrap"]:
        logger.error(f"Invalid start mode: '{mode}'. Must be 'normal' or 'join' or 'bootstrap'.")
        return

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
    
def trigger_node_removal(master_ip: str, ip_to_remove: str):
    """
    Sends a blocking request to the master to remove a node and returns the outcome.
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
        response_data = send_command_via_proxy(
            ip=ip,
            path="/request_authentication",
            method="POST",
            port=ESP32_API_PORT,
            payload={}
        )
        
        if response_data and response_data.get("authentication_passed") is True:
            successful_count += 1
            logger.success(f"   -> Auth SUCCESS for {ip}")
        else:
            logger.error(f"   -> Auth FAILED for {ip}. Response: {response_data}")

    return successful_count

def run_tls_authentication_check(node_ips: list, campaign_id: str) -> int:
    """
    Triggers TLS authentication synchronously on each node via the Raspberry proxy.
    Uses /request_authentication_tls endpoint.
    """
    if not node_ips:
        return 0

    logger.info(f"Running SYNCHRONOUS TLS authentication check on {len(node_ips)} nodes...")

    successful_count = 0
    for ip in node_ips:
        logger.info(f"   -> Triggering TLS auth on {ip} via proxy...")
        response_data = send_command_via_proxy(
            ip=ip,
            path="/request_authentication_tls",
            method="POST",
            port=ESP32_API_PORT,
            payload={}
        )
        
        if response_data and response_data.get("authentication_passed") is True:
            successful_count += 1
            logger.success(f"   -> TLS Auth SUCCESS for {ip}")
        else:
            logger.error(f"   -> TLS Auth FAILED for {ip}. Response: {response_data}")

    return successful_count

def run_mqtts_authentication_check(node_ips: list, campaign_id: str) -> int:
    """
    Triggers MQTTS authentication synchronously on each node via the Raspberry proxy.
    Uses /request_authentication_mqtts endpoint.
    """
    if not node_ips:
        return 0

    logger.info(f"Running SYNCHRONOUS MQTTS authentication check on {len(node_ips)} nodes...")

    successful_count = 0
    for ip in node_ips:
        logger.info(f"   -> Triggering MQTTS auth on {ip} via proxy...")
        response_data = send_command_via_proxy(
            ip=ip,
            path="/request_authentication_mqtts",
            method="POST",
            port=ESP32_API_PORT,
            payload={}
        )
        
        if response_data and response_data.get("authentication_passed") is True:
            successful_count += 1
            logger.success(f"   -> MQTTS Auth SUCCESS for {ip}")
        else:
            logger.error(f"   -> MQTTS Auth FAILED for {ip}. Response: {response_data}")

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
    send_tcp_command("WAIT_FOR_BOOTSTRAP_HEAL", wait_for_reply=True)
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
    
    logger.info(f"[{campaign_id}] Requesting removal of {node_to_remove}...")
    trigger_node_removal(master_ip, node_to_remove)
    
    logger.info(f"[{campaign_id}] Waiting for REMOVE+HEAL to complete...")
    send_tcp_command("WAIT_FOR_REMOVE_COMPLETE", wait_for_reply=True)
    logger.info(f"[{campaign_id}] Confirmation received. Cluster is stable.")
    
    return known_ips_after_removal

def run_integrity_failure_test(n_nodes: int, campaign_id: str):
    """
    Runs a special test for Integrity Failure Detection.
    It provisions 32 nodes, tampers with their secrets, and measures
    how long it takes for followers to detect the failure during an election.
    """
    logger.info(f"--- SCENARIO INTEGRITY FAILURE (Size: {n_nodes}) ---")
    
    trigger_reset(offset=0, count=n_nodes)
    trigger_deployment(offset=0, count=n_nodes)
    all_ips = wait_for_ips(expected_count=n_nodes, timeout_seconds=180)
    if len(all_ips) < n_nodes:
        logger.error(f"Could not bring all {n_nodes} nodes online. Aborting test.")
        return

    set_monitoring_campaign(campaign_id)
    logger.info(f"[{campaign_id}] Tampering secrets on all {n_nodes} nodes...")
    broadcast_command_via_proxy(
        node_ips=all_ips,
        path="/test/tamper_secret",
        method="POST",
        port=ESP32_API_PORT,
        payload={}
    )
    logger.info(f"[{campaign_id}] Secrets tampered. Waiting 2s.")
    time.sleep(2)
    
    send_tcp_command("WAIT_FOR_BOOTSTRAP_HEAL", wait_for_reply=False)

    logger.info(f"[{campaign_id}] Triggering /start in 'bootstrap' mode...")
    trigger_start_on_nodes(all_ips, "bootstrap", cluster_size=n_nodes)
    
    logger.info(f"[{campaign_id}] Waiting for failure detection event...")
    send_tcp_command("WAIT_FOR_BOOTSTRAP_HEAL", wait_for_reply=True)
    logger.success(f"[{campaign_id}] Integrity failure detected and processed by server.")

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
            
            logger.info(f"--- SCENARIO 4a: AUTHENTICATION (Post-Join - SRAFT Protocol) ---")
            sraft_successes = run_authentication_check(current_ips, campaign_id)
            logger.info(f"SRAFT auth: {sraft_successes}/{len(current_ips)} nodes passed")
            
            logger.info(f"--- SCENARIO 4b: AUTHENTICATION (Post-Join - TLS) ---")
            tls_successes = run_tls_authentication_check(current_ips, campaign_id)
            logger.info(f"TLS auth: {tls_successes}/{len(current_ips)} nodes passed")
            
            logger.info(f"--- SCENARIO 4c: AUTHENTICATION (Post-Join - MQTTS) ---")
            mqtts_successes = run_mqtts_authentication_check(current_ips, campaign_id)
            logger.info(f"MQTTS auth: {mqtts_successes}/{len(current_ips)} nodes passed")
            if n_nodes >= RAFT_MINIMUM_SIZE:
                logger.info(f"--- SCENARIO 3: REMOVAL (Post-Join) ---")
                ips_after_removal = run_single_removal(current_ips, campaign_id)
                time.sleep(3)
                logger.info(f"--- SCENARIO 4: AUTHENTICATION (Post-Removal) ---")
                logger.info(f"--- SCENARIO 4a: AUTHENTICATION (Post-Removal - SRAFT Protocol) ---")
                run_authentication_check(ips_after_removal, campaign_id)
                
                logger.info(f"--- SCENARIO 4b: AUTHENTICATION (Post-Removal - TLS) ---")
                run_tls_authentication_check(ips_after_removal, campaign_id)
                
                logger.info(f"--- SCENARIO 4c: AUTHENTICATION (Post-Removal - MQTTS) ---")
                run_mqtts_authentication_check(ips_after_removal, campaign_id)
            else:
                logger.info(f"Skipping SCENARIO 3 (Removal) for cluster size < {RAFT_MINIMUM_SIZE}")
                
            logger.info(f"--- GENERATING REPORT for {campaign_id} ---")
            report_url = f"{MONITOR_API_URL}/campaign/export_one/{campaign_id}"
            request_and_save_report(report_url, output_dir)

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
        report_url = f"{MONITOR_API_URL}/campaign/export_one/{rq1_campaign_id}"
        request_and_save_report(report_url, rq1_output_dir)
        
        logger.info(f"FINISHED RQ1 TEST. Resetting nodes.")
        trigger_reset(0, 32)
        time.sleep(10)
    else:
        logger.warning(f"Skipping RQ1 integrity test, max nodes ({max_nodes}) is less than 32.")
    
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
    args = parser.parse_args()
    
    base_output_dir = "experiment_results"
    if args.full_experiment:
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