import os
import re
import sys
import threading
import time
import socket
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
import requests
from concurrent.futures import ThreadPoolExecutor
import uvicorn
import pandas as pd
from fastapi import FastAPI, HTTPException
from loguru import logger
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
from sqlalchemy.engine.url import make_url
from sqlalchemy import func
from sqlalchemy.orm import Session
from fastapi import Depends
from pydantic import BaseModel
import subprocess
import numpy as np
import random
import io
import zipfile
import tempfile
import shutil
from fastapi.responses import FileResponse, StreamingResponse

HOST = '0.0.0.0'
LOG_PORT_TCP = 9001
API_PORT_HTTP = 9002
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://raft:CHANGE_ME@localhost/logger_db",
)
POLLING_INTERVAL_SECONDS = 0.5
HEARTBEAT_TIMEOUT_SECONDS = 90
REAPER_INTERVAL_SECONDS = 60
ESP32_API_PORT = 80

remove_completed_event = threading.Event()

engine = create_engine(DATABASE_URL)
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()

class OnlineNode(Base):
    """Represents a node currently online and sending heartbeats."""
    __tablename__ = "online_nodes"
    ip_address = Column(String, primary_key=True)
    mac_address = Column(String, nullable=False, index=True, unique=True)
    last_seen = Column(DateTime(timezone=True), nullable=False)

class ElectionLog(Base):
    """Logs events related to leader elections (start and completion)."""
    __tablename__ = "election_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String, index=True)
    event = Column(String)
    term = Column(Integer)
    node_mac = Column(String, index=True)

class JoinLog(Base):
    """Logs events related to nodes joining the cluster."""
    __tablename__ = "join_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String, index=True)
    event = Column(String)
    node_mac = Column(String)

class RemoveLog(Base):
    """Logs events related to nodes being removed from the cluster."""
    __tablename__ = "remove_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String, index=True)
    event = Column(String)
    removed_node_mac = Column(String)
    reporter_mac = Column(String)

class AuthLog(Base):
    """Logs the success or failure of an authentication event."""
    __tablename__ = "auth_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String, index=True)
    event = Column(String)
    authenticated_node_mac = Column(String)
    auth_type = Column(String)  # "SRAFT", "TLS", "TLS_RESUMED", or "MQTTS"


class ElectionStat(Base):
    """Stores system statistics polled during an election operation."""
    __tablename__ = "election_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String)
    node_mac = Column(String)
    cpu_usage_percent = Column(Float)
    memory_load_percent = Column(Float)
    estimated_power_mw = Column(Float)
    auc_cpu_percent_seconds = Column(Float)
    auc_memory_percent_seconds = Column(Float)
    auc_power_mw_seconds = Column(Float)

class JoinStat(Base):
    """Stores system statistics polled during a join operation."""
    __tablename__ = "join_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String)
    node_mac = Column(String)
    cpu_usage_percent = Column(Float)
    memory_load_percent = Column(Float)
    estimated_power_mw = Column(Float)
    auc_cpu_percent_seconds = Column(Float)
    auc_memory_percent_seconds = Column(Float)
    auc_power_mw_seconds = Column(Float)

class RemoveStat(Base):
    """Stores system statistics polled during a remove operation."""
    __tablename__ = "remove_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String)
    node_mac = Column(String)
    cpu_usage_percent = Column(Float)
    memory_load_percent = Column(Float)
    estimated_power_mw = Column(Float)
    auc_cpu_percent_seconds = Column(Float)
    auc_memory_percent_seconds = Column(Float)
    auc_power_mw_seconds = Column(Float)

class AuthStat(Base):
    """Stores system statistics polled during an authentication test campaign."""
    __tablename__ = "auth_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String)
    node_mac = Column(String)
    cpu_usage_percent = Column(Float)
    memory_load_percent = Column(Float)
    estimated_power_mw = Column(Float)
    auc_cpu_percent_seconds = Column(Float)
    auc_memory_percent_seconds = Column(Float)
    auc_power_mw_seconds = Column(Float)
    
class HealingLog(Base):
    """Logs events related to the cluster's self-healing process."""
    __tablename__ = "healing_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String, index=True)
    event = Column(String)
    node_mac = Column(String)

class HealingStat(Base):
    """Stores system statistics polled during a healing operation."""
    __tablename__ = "healing_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String)
    node_mac = Column(String)
    cpu_usage_percent = Column(Float)
    memory_load_percent = Column(Float)
    estimated_power_mw = Column(Float)
    auc_cpu_percent_seconds = Column(Float)
    auc_memory_percent_seconds = Column(Float)
    auc_power_mw_seconds = Column(Float)
    
class BootstrapStat(Base):
    """Stores system statistics for the entire initial bootstrap process."""
    __tablename__ = "bootstrap_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String)
    node_mac = Column(String)
    cpu_usage_percent = Column(Float)
    memory_load_percent = Column(Float)
    estimated_power_mw = Column(Float)
    auc_cpu_percent_seconds = Column(Float)
    auc_memory_percent_seconds = Column(Float)
    auc_power_mw_seconds = Column(Float)
    
class AttestLog(Base):
    """Logs the start and the outcome of an attestation requested by the orchestrator (RQ1)."""
    __tablename__ = "attest_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String, index=True)
    event = Column(String)
    attested_node_mac = Column(String)
    verifier_mac = Column(String)

class AttestStat(Base):
    """Stores system statistics polled during an attestation."""
    __tablename__ = "attest_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String)
    node_mac = Column(String)
    cpu_usage_percent = Column(Float)
    memory_load_percent = Column(Float)
    estimated_power_mw = Column(Float)
    auc_cpu_percent_seconds = Column(Float)
    auc_memory_percent_seconds = Column(Float)
    auc_power_mw_seconds = Column(Float)

class IntegrityFailureLog(Base):
    """Logs events related to integrity check failures."""
    __tablename__ = "integrity_failure_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True))
    campaign_id = Column(String)
    operation_id = Column(String, index=True)
    event = Column(String)
    failed_node_mac = Column(String)
    reporter_node_mac = Column(String)
    
class SummaryStat(Base):
    """Stores aggregated, high-level statistics for a completed phase."""
    __tablename__ = "summary_stats"
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(String, index=True)
    operation_id = Column(String, index=True)
    phase_type = Column(String)
    start_time = Column(DateTime(timezone=True))
    end_time = Column(DateTime(timezone=True))
    duration_seconds = Column(Float)
    outcome = Column(String)
    participating_nodes_count = Column(Integer)
    cluster_avg_cpu = Column(Float)
    cluster_avg_memory = Column(Float)
    cluster_avg_power = Column(Float)
    cluster_std_cpu = Column(Float)
    cluster_std_memory = Column(Float)
    cluster_std_power = Column(Float)


PHASE_CONFIG = {
    "BOOTSTRAP": {
        "log_model": HealingLog,
        "stat_model": BootstrapStat,
        "end_events": ['BOOTSTRAP_COMPLETE'],
    },
    "ELECTION": {
        "log_model": ElectionLog,
        "stat_model": ElectionStat,
        "end_events": ['ELECTED', 'STEPDOWN'],
    },
    "JOIN": {
        "log_model": JoinLog,
        "stat_model": JoinStat,
        "end_events": ['COMPLETE', 'FAILED'],
    },
    "REMOVE": {
        "log_model": RemoveLog,
        "stat_model": RemoveStat,
        "end_events": ['COMPLETE', 'FAILED'],
    },
    "HEAL": {
        "log_model": HealingLog,
        "stat_model": HealingStat,
        "end_events": ['COMPLETE', 'FAILED'],
    },
    "HEALING_PHASE": {
        "log_model": HealingLog,
        "stat_model": HealingStat,
        "end_events": ['COMPLETE', 'FAILED'],
    },
    "AUTH": {
        "log_model": AuthLog,
        "stat_model": AuthStat,
        "end_events": ['SUCCESS', 'FAILURE'],
    },
    "INTEGRITY_CHECK": {
        "log_model": AttestLog,
        "stat_model": AttestStat,
        "end_events": ['SUCCESS', 'FAILURE'],
    },
    "INTEGRITY_TEST": {
        "log_model": IntegrityFailureLog,
        "stat_model": ElectionStat,
        "end_events": ['FAILED'],
    },
}

phase_prefix_map = {
    "election_": "ELECTION", "join_": "JOIN", "remove_": "REMOVE",
    "heal_": "HEAL", "auth_": "AUTH", "bootstrap_": "BOOTSTRAP",
    "healing_phase_": "HEALING_PHASE", "integrity_": "INTEGRITY_TEST",
    "attest_": "INTEGRITY_CHECK"
}

cluster_nodes = set()
state_lock = threading.Lock()
current_campaign_id = "default"
bootstrap_completed = threading.Event()
leader_elected_event = threading.Event()
node_verifier_mapping = {}

pending_end_events = []
pending_events_lock = threading.Lock()
all_jobs_processed_event = threading.Event()
all_jobs_processed_event.set()

shutdown_event = threading.Event()
active_worker_threads = []


def init_db():
    """Initializes the database by creating all tables from the models."""
    logger.info(f"Initializing database connection to {engine.url.database}...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database is ready.")
    except Exception as e:
        logger.error(f"CRITICAL: Database error during initialization: {e}")
        sys.exit(1)

def get_session():
    """Provides a new database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def _try_process_end_event(session, job_data, current_online_nodes):
    """
    Attempts to process a single end-phase event (COMPLETE, FAILED, etc.).
    This function queries for the matching START log.
    If found, it logs the END event, commits, and triggers stats collection.
    
    Returns:
        True if the event was successfully processed and committed.
        False if the matching START log was not found (or on other errors).
    """
    try:
        event_name = job_data['event_name']
        node_mac = job_data['node_mac']
        timestamp = job_data['timestamp']
        campaign_id = job_data['campaign_id']
        
        if event_name in ['JOIN_COMPLETE', 'JOIN_FAILED']:
            event_type = 'COMPLETE' if event_name == 'JOIN_COMPLETE' else 'FAILED'
            start_log = session.query(JoinLog).filter(
                JoinLog.campaign_id == campaign_id,
                JoinLog.event == 'START',
                JoinLog.node_mac == node_mac,
                JoinLog.operation_id.like(f'join_{node_mac}_%')
            ).order_by(JoinLog.timestamp.desc()).first()
            
            if start_log:
                op_id = start_log.operation_id
                session.add(JoinLog(timestamp=timestamp, campaign_id=campaign_id, event=event_type, node_mac=node_mac, operation_id=op_id))
                log_end_of_phase_stats(op_id, JoinStat, nodes_to_query=current_online_nodes)
                session.commit()
                return True
            else:
                return False

        elif event_name == 'REMOVE_COMPLETE':
            event_type = 'COMPLETE'
            removed_mac = node_mac

            start_log = session.query(RemoveLog).filter(
                RemoveLog.campaign_id == campaign_id,
                RemoveLog.event == 'START',
                RemoveLog.removed_node_mac == removed_mac,
                RemoveLog.operation_id.like(f'remove_{removed_mac}_%')
            ).order_by(RemoveLog.timestamp.desc()).first()

            if start_log:
                op_id = start_log.operation_id
                session.add(RemoveLog(timestamp=timestamp, campaign_id=campaign_id, event=event_type, removed_node_mac=removed_mac, reporter_mac='master', operation_id=op_id))
                log_end_of_phase_stats(op_id, RemoveStat, nodes_to_query=current_online_nodes)
                session.commit()
                return True
            else:
                return False
        
        elif event_name in ['HEALING_PHASE_COMPLETE', 'HEALING_PHASE_FAILED']:
            event_type = 'COMPLETE' if event_name == 'HEALING_PHASE_COMPLETE' else 'FAILED'
            healed_node_mac = node_mac

            start_log = session.query(HealingLog).filter(
                HealingLog.campaign_id == campaign_id,
                HealingLog.event == 'START',
                HealingLog.node_mac == healed_node_mac,
                HealingLog.operation_id.like(f'healing_phase_{healed_node_mac}_%')
            ).order_by(HealingLog.timestamp.desc()).first()
            
            if start_log:
                op_id_phase = start_log.operation_id
                session.add(HealingLog(timestamp=timestamp, campaign_id=campaign_id, event=event_type, node_mac=healed_node_mac, operation_id=op_id_phase))
                log_end_of_phase_stats(op_id_phase, HealingStat, nodes_to_query=current_online_nodes)
                remove_completed_event.set()
                session.commit()
                return True
            else:
                return False

        elif event_name in ['HEAL_COMPLETE', 'HEAL_FAILED']:
            event_type = 'COMPLETE' if event_name == 'HEAL_COMPLETE' else 'FAILED'
            healed_node_mac = node_mac

            start_log = session.query(HealingLog).filter(
                HealingLog.campaign_id == campaign_id,
                HealingLog.event == 'START',
                HealingLog.node_mac == healed_node_mac,
                HealingLog.operation_id.like(f'heal_{healed_node_mac}_%')
            ).order_by(HealingLog.timestamp.desc()).first()

            if start_log:
                op_id_heal = start_log.operation_id
                session.add(HealingLog(timestamp=timestamp, campaign_id=campaign_id, event=event_type, node_mac=healed_node_mac, operation_id=op_id_heal))
                log_end_of_phase_stats(op_id_heal, HealingStat, nodes_to_query=current_online_nodes)
                session.commit()
                return True
            else:
                return False
            
        elif event_name == 'INTEGRITY_CHECK_FAILED':
            event_type = 'FAILED'
            failed_node_mac = job_data['node_mac']
            reporter_node_mac = job_data.get('reporter_mac')
            
            start_log = session.query(IntegrityFailureLog).filter(
                IntegrityFailureLog.campaign_id == campaign_id,
                IntegrityFailureLog.event == 'START',
                IntegrityFailureLog.failed_node_mac == failed_node_mac
            ).order_by(IntegrityFailureLog.timestamp.desc()).first()
            
            if start_log:
                op_id = start_log.operation_id
                session.add(IntegrityFailureLog(
                    timestamp=timestamp, 
                    campaign_id=campaign_id, 
                    event=event_type, 
                    operation_id=op_id,
                    failed_node_mac=failed_node_mac,
                    reporter_node_mac=reporter_node_mac
                ))
                log_end_of_phase_stats(op_id, ElectionStat, nodes_to_query=current_online_nodes)
                session.commit()
                return True
            else:
                return False

        return True
    except Exception as e:
        logger.error(f"Error in _try_process_end_event for {job_data.get('event_name')}: {e}", exc_info=True)
        session.rollback()
        return False

# One single-thread executor per device: the requests to a device (start of a phase, then its statistics)
# are sent in order, while different devices are served in parallel. A device that answers slowly, e.g.,
# while it runs the operation being measured, delays only its own requests.
NODE_HTTP_TIMEOUT = (3, 30)
_node_executors = {}
_node_executors_lock = threading.Lock()


def _node_executor(node_ip: str) -> ThreadPoolExecutor:
    with _node_executors_lock:
        executor = _node_executors.get(node_ip)
        if executor is None:
            executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"node-{node_ip}")
            _node_executors[node_ip] = executor
        return executor


def _post_start_phase(node_ip: str, attempts: int = 3):
    # A start that is not delivered would make the next end of phase on this device close the wrong phase, so
    # it is retried (on the executor of the device, before any later request to it) when the connection
    # failed. A read timeout is not retried: the device received the request, and a second one would open
    # the phase twice.
    for attempt in range(1, attempts + 1):
        try:
            requests.post(f"http://{node_ip}:{ESP32_API_PORT}/system/stats/start_phase", timeout=NODE_HTTP_TIMEOUT)
            return
        except requests.exceptions.ReadTimeout as e:
            logger.warning(f"start_phase on node {node_ip} sent but not answered in time (not retried): {e}")
            return
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not trigger start_phase on node {node_ip} (attempt {attempt}/{attempts}): {e}")


def _get_phase_stats(node_ip: str):
    """Ends the current phase on a device and returns its aggregates, or None."""
    try:
        response = requests.get(f"http://{node_ip}:{ESP32_API_PORT}/system/stats", timeout=NODE_HTTP_TIMEOUT)
        return response.json() if response.status_code == 200 else None
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.error(f"Could not contact node {node_ip} for stats: {e}")
        return None


def _async_log_stats_worker(operation_id: str, model_class, nodes_to_query: list, campaign_id_override: str = None):
    """
    At the end of a phase, queries all online nodes for their aggregate stats
    and logs one entry per node to the appropriate database table.
    """
    
    with state_lock:
        campaign_id = campaign_id_override if campaign_id_override else current_campaign_id

    # logger.info(f"[{campaign_id} | {operation_id}] Phase ended. Collecting aggregate stats from all cluster nodes...")

    session = SessionLocal()
    
    ip_mac_map = {}
    try:
        all_nodes = session.query(OnlineNode).filter(OnlineNode.ip_address.in_(nodes_to_query)).all()
        ip_mac_map = {node.ip_address: node.mac_address for node in all_nodes}
    except Exception as e:
        logger.error(f"Stats worker [{operation_id}] could not build IP-MAC map: {e}")
    
    try:
        measurement_timestamp = datetime.now(timezone.utc)
        if not nodes_to_query:
            return

        # The statistics of all the devices are requested in parallel, each after the requests already queued
        # for that device (in particular the start of this phase).
        futures = {node_ip: _node_executor(node_ip).submit(_get_phase_stats, node_ip) for node_ip in nodes_to_query}
        for node_ip, future in futures.items():
            node_mac = ip_mac_map.get(node_ip)
            if not node_mac:
                logger.warning(f"[{campaign_id} | {operation_id}] No MAC found for IP {node_ip}. Skipping stats log.")
                continue
            stats = future.result()
            if not stats:
                continue
            cpu_stats = stats.get('cpu', {})
            mem_stats = stats.get('memory', {})
            pow_stats = stats.get('power', {})
            session.add(model_class(
                timestamp=measurement_timestamp,
                campaign_id=campaign_id,
                operation_id=operation_id,
                node_mac=node_mac,
                cpu_usage_percent=cpu_stats.get('average_percent', 0.0),
                memory_load_percent=mem_stats.get('average_percent', 0.0),
                estimated_power_mw=pow_stats.get('average_mw', 0.0),
                auc_cpu_percent_seconds=cpu_stats.get('auc_percent_seconds', 0.0),
                auc_memory_percent_seconds=mem_stats.get('auc_percent_seconds', 0.0),
                auc_power_mw_seconds=pow_stats.get('auc_mw_seconds', 0.0)
            ))

        session.commit()
    except Exception as e:
        logger.error(f"A database error occurred during stats logging for {operation_id}: {e}")
        session.rollback()
    finally:
        session.close()
        
def log_end_of_phase_stats(operation_id: str, model_class, nodes_to_query: list, campaign_id_override: str = None):
    """
    Spawns a new worker thread to collect and log aggregate stats 
    from all cluster nodes without blocking the main message processing loop.
    """
    with state_lock:
        campaign_id = campaign_id_override if campaign_id_override else current_campaign_id
        
        if shutdown_event.is_set():
            logger.warning(f"Shutdown in progress. Ignoring request to log stats for op '{operation_id}'.")
            return
        
        if not nodes_to_query:
             logger.warning(f"[{campaign_id} | {operation_id}] log_end_of_phase_stats called with empty node list. No stats will be collected.")
             return

        stats_thread = threading.Thread(
            target=_async_log_stats_worker,
            args=(operation_id, model_class, nodes_to_query, campaign_id)
        )
        stats_thread.start()
        
        active_worker_threads.append(stats_thread)
        finished_threads = [t for t in active_worker_threads if not t.is_alive()]
        for t in finished_threads:
            active_worker_threads.remove(t)
            
def _trigger_start_phase_on_all_nodes():
    """
    Starts a phase on all online nodes. The requests are queued on the executor of each node and sent in
    parallel, so that the caller (which then logs the start of the operation) is not delayed by a node
    that answers slowly.
    """
    with state_lock:
        nodes_to_query = list(cluster_nodes)

    for node_ip in nodes_to_query:
        _node_executor(node_ip).submit(_post_start_phase, node_ip)

def retry_worker_thread():
    """
    Periodically retries processing end-phase events that failed 
    because their START log was not yet visible in the database.
    """
    logger.info("Retry worker thread started.")
    while not shutdown_event.is_set():
        try:
            shutdown_event.wait(timeout=0.01)
            if shutdown_event.is_set():
                break

            with pending_events_lock:
                if not pending_end_events:
                    all_jobs_processed_event.set()
                    continue

                processed_jobs = []
                session = SessionLocal()
                try:
                    with state_lock:
                        current_online_nodes = list(cluster_nodes)

                    for job in pending_end_events:
                        success = _try_process_end_event(session, job, current_online_nodes)
                        if success:
                            processed_jobs.append(job)
                    
                    for job in processed_jobs:
                        pending_end_events.remove(job)

                finally:
                    session.close()

        except Exception as e:
            logger.error(f"Error in retry_worker_thread: {e}", exc_info=True)
    logger.info("Retry worker thread stopped.")
    
def get_mac_from_ip(db_session, ip_addr: str) -> str | None:
    """
    Fetches a MAC address from an IP using the OnlineNode table.
    This is a critical helper for translating real-time IPs to static MAC IDs.
    """
    if not ip_addr:
        return None
    try:
        # Query the OnlineNode table for the corresponding MAC
        node = db_session.query(OnlineNode.mac_address).filter(OnlineNode.ip_address == ip_addr).first()
        return node.mac_address if node else None
    except Exception as e:
        logger.warning(f"Error during MAC lookup for IP {ip_addr}: {e}")
        return None

def parse_and_log_message(message: str, from_ip: str, conn: socket.socket = None):
    """
    Parses incoming TCP messages and logs them to the appropriate database tables
    using MAC addresses as the primary identifier.
    
    - Handles NODE_ONLINE:IP:MAC to update the IP-MAC translation table.
    - Handles self-reported events (e.g., ELECTION_START) that now send a MAC.
    - Handles leader-reported events (e.g., REMOVE_START) that send an IP,
      and performs a MAC lookup.
    """
    global current_campaign_id
    session = SessionLocal()
    try:
        full_message = message.strip()
        timestamp_str = None
        payload = full_message
        
        if '|' in full_message:
            parts = full_message.split('|', 1)
            if len(parts) == 2:
                timestamp_str, payload = parts
                
        if timestamp_str:
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            timestamp = datetime.fromisoformat(timestamp_str)
        else:
            timestamp = datetime.now(timezone.utc)
            
        clean_message = payload.strip()
        # The event name ends at the first ':' or '|': events such as AUTH_START separate their fields
        # with '|' and carry MAC addresses, which contain ':'.
        name_match = re.match(r'([A-Za-z_]+)([:|])(.*)', clean_message, re.S)
        if name_match:
            event_name = name_match.group(1)
            data = name_match.group(3)
        else:
            event_name = clean_message
            data = ""
            
        if event_name == 'SET_CAMPAIGN':
            new_campaign_id = data
            with state_lock:
                current_campaign_id = new_campaign_id
            logger.success(f"CAMPAIGN SWITCHED to '{current_campaign_id}' by orchestrator.")
            session.commit()
            return
        
        with state_lock:
            campaign_id = current_campaign_id
            current_online_nodes = list(cluster_nodes)

        if event_name not in ['JOIN_VERIFIERS', 'NODE_ALIVE', 'WAIT_FOR_BOOTSTRAP_HEAL', 'WAIT_FOR_REMOVE_COMPLETE']:
            logger.info(f"[{campaign_id}] {clean_message} from {from_ip}")

        job_data_for_retry = None
        reporter_mac = get_mac_from_ip(session, from_ip)

        if event_name == 'NODE_ONLINE':
            parts = data.split(':', 1)
            if len(parts) == 2:
                ip = parts[0]
                mac = parts[1].upper()
                new_node = OnlineNode(ip_address=ip, mac_address=mac, last_seen=timestamp)
                session.merge(new_node)
                with state_lock:
                    cluster_nodes.add(ip)
            else:
                logger.warning(f"Received malformed NODE_ONLINE from {from_ip} (missing IP or MAC).")
        
        elif event_name == 'NODE_ALIVE':
            parts = data.split(':', 1)
            if len(parts) >= 1:
                ip = parts[0]
                session.query(OnlineNode).filter(OnlineNode.ip_address == ip).update({"last_seen": timestamp})
            else:
                 logger.warning(f"Malformed NODE_ALIVE from {from_ip}")

        elif event_name == 'ELECTION_START':
            parts = data.split(':', 1)
            if len(parts) == 2:
                term, node_mac = int(parts[0]), parts[1].upper()
                op_id = f"election_{term}"
                _trigger_start_phase_on_all_nodes()
                session.add(ElectionLog(timestamp=timestamp, campaign_id=campaign_id, event='START', term=term, node_mac=node_mac, operation_id=op_id))
                
                integrity_op_id = f"integrity_{node_mac}_{term}"
                session.add(IntegrityFailureLog(
                    timestamp=timestamp,
                    campaign_id=campaign_id,
                    event='START',
                    operation_id=integrity_op_id,
                    failed_node_mac=node_mac,
                    reporter_node_mac=None
                ))
            else:
                logger.warning(f"Malformed ELECTION_START from {from_ip}")


        elif event_name in ['LEADER_ELECTED', 'CANDIDATE_STEPDOWN']:
            parts = data.split(':', 1)
            if len(parts) == 2:
                term, node_mac = int(parts[0]), parts[1].upper()
                op_id = f"election_{term}"
                event_type = 'ELECTED' if event_name == 'LEADER_ELECTED' else 'STEPDOWN'
                session.add(ElectionLog(timestamp=timestamp, campaign_id=campaign_id, event=event_type, term=term, node_mac=node_mac, operation_id=op_id))
                if event_type == 'ELECTED':
                    log_end_of_phase_stats(op_id, ElectionStat, nodes_to_query=current_online_nodes)
            else:
                logger.warning(f"Malformed {event_name} from {from_ip}")

        elif event_name == 'JOIN_START':
            ip_or_mac = data
            node_mac = None
            if ':' in ip_or_mac:
                node_mac = ip_or_mac.upper()
            else:
                node_mac = get_mac_from_ip(session, ip_or_mac)

            if not node_mac:
                logger.error(f"[{campaign_id}] Cannot log JOIN_START: MAC not found for '{ip_or_mac}'. Dropping event.")
                return

            op_id = f"join_{node_mac}_{int(timestamp.timestamp())}"
            _trigger_start_phase_on_all_nodes()
            session.add(JoinLog(timestamp=timestamp, campaign_id=campaign_id, event='START', node_mac=node_mac, operation_id=op_id))
            session.commit()

        elif event_name in ['JOIN_COMPLETE', 'JOIN_FAILED']:
            ip_or_mac = data
            node_mac = None
            node_ip = "N/A"
            
            if ':' in ip_or_mac:
                node_mac = ip_or_mac.upper()
            else: # È un IP
                node_ip = ip_or_mac
                node_mac = get_mac_from_ip(session, node_ip)

            if not node_mac:
                 logger.error(f"[{campaign_id}] Cannot log {event_name}: MAC for '{ip_or_mac}' not found. Dropping.")
                 return
                 
            job_data = {
                'event_name': event_name, 
                'node_ip': node_ip,
                'node_mac': node_mac,
                'timestamp': timestamp, 
                'campaign_id': campaign_id
            }
            if not _try_process_end_event(session, job_data, current_online_nodes):
                job_data_for_retry = job_data
                
        elif event_name == 'JOIN_FAILED_INTEGRITY':
            node_ip = data
            node_mac = get_mac_from_ip(session, node_ip)
            op_id = f"join_{node_mac or node_ip}"
            session.add(JoinLog(timestamp=timestamp, campaign_id=campaign_id, event='FAILED_INTEGRITY', node_mac=node_mac, operation_id=op_id))
            
        elif event_name == 'INTEGRITY_CHECK_FAILED':
            parts = data.split(':', 1)
            if len(parts) == 2:
                failed_mac = parts[0].upper()
                reporter_mac = parts[1].upper()

                job_data = {
                    'event_name': 'INTEGRITY_CHECK_FAILED',
                    'node_mac': failed_mac,
                    'reporter_mac': reporter_mac,
                    'timestamp': timestamp,
                    'campaign_id': campaign_id
                }
                
                if not _try_process_end_event(session, job_data, current_online_nodes):
                    with pending_events_lock:
                        pending_end_events.append(job_data)
                        all_jobs_processed_event.clear()
            else:
                logger.warning(f"Malformed INTEGRITY_CHECK_FAILED from {from_ip}")
            
        elif event_name == 'JOIN_FAILED_DISCOVERY_MAC':
            node_ip = data
            node_mac = get_mac_from_ip(session, node_ip)
            op_id = f"join_{node_mac or node_ip}"
            session.add(JoinLog(timestamp=timestamp, campaign_id=campaign_id, event='FAILED_DISCOVERY_MAC', node_mac=node_mac, operation_id=op_id))

        elif event_name == 'REMOVE_START':
            removed_ip = data
            removed_mac = get_mac_from_ip(session, removed_ip)
            
            if not removed_mac:
                logger.error(f"[{campaign_id}] Cannot log REMOVE_START: MAC for IP {removed_ip} not found. Dropping event.")
                return

            op_id = f"remove_{removed_mac}_{int(timestamp.timestamp())}"
            _trigger_start_phase_on_all_nodes()
            session.add(RemoveLog(timestamp=timestamp, campaign_id=campaign_id, event='START', removed_node_mac=removed_mac, reporter_mac=reporter_mac, operation_id=op_id))
            
            with state_lock:
                cluster_nodes.discard(removed_ip)
                node_verifier_mapping.pop(removed_ip, None)
                for node, verifiers in node_verifier_mapping.items():
                    verifiers.discard(removed_ip)
            session.commit()

        elif event_name == 'REMOVE_COMPLETE':
            removed_ip = data
            removed_mac = get_mac_from_ip(session, removed_ip)
            if not removed_mac:
                 logger.error(f"[{campaign_id}] Cannot log {event_name}: MAC for IP {removed_ip} not found. Dropping.")
                 return
                 
            job_data = {
                'event_name': event_name, 
                'node_ip': removed_ip,
                'node_mac': removed_mac,
                'timestamp': timestamp, 
                'campaign_id': campaign_id
            }
            if not _try_process_end_event(session, job_data, current_online_nodes):
                job_data_for_retry = job_data
            
            with state_lock:
                cluster_nodes.discard(removed_ip)
                node_verifier_mapping.pop(removed_ip, None)
                for node, verifiers in node_verifier_mapping.items():
                    verifiers.discard(removed_ip)
            
        elif event_name == 'HEALING_PHASE_START':
            healed_ip = data
            healed_mac = get_mac_from_ip(session, healed_ip)
            if not healed_mac:
                 healed_mac = f"unknown_mac_for_ip_{healed_ip}"
                 
            op_id_phase = f"healing_phase_{healed_mac}_{int(timestamp.timestamp())}"
            _trigger_start_phase_on_all_nodes()
            session.add(HealingLog(timestamp=timestamp, campaign_id=campaign_id, event='START', node_mac=healed_mac, operation_id=op_id_phase))
            session.commit()

        elif event_name in ['HEALING_PHASE_COMPLETE', 'HEALING_PHASE_FAILED']:
            healed_ip = data
            healed_mac = get_mac_from_ip(session, healed_ip)
            if not healed_mac:
                healed_mac = f"unknown_mac_for_ip_{healed_ip}"

            job_data = {
                'event_name': event_name, 
                'node_ip': healed_ip,
                'node_mac': healed_mac,
                'timestamp': timestamp, 
                'campaign_id': campaign_id
            }
            if not _try_process_end_event(session, job_data, current_online_nodes):
                job_data_for_retry = job_data
            
        elif event_name == 'AUTH_START':
            # Format: AUTH_START|<op_id>|<mac>|<type>
            parts = data.split('|')
            if len(parts) >= 2:
                op_id, node_mac = parts[0], parts[1].upper()
                auth_type = parts[2] if len(parts) > 2 else "SRAFT"
                _trigger_start_phase_on_all_nodes()
                session.add(AuthLog(
                    timestamp=timestamp, 
                    campaign_id=campaign_id, 
                    event='START', 
                    authenticated_node_mac=node_mac, 
                    operation_id=op_id,
                    auth_type=auth_type
                ))
                session.commit()
            else:
                logger.warning(f"Malformed AUTH_START from {from_ip}")

        elif event_name == 'AUTH_RESULT_EVENT':
            # Format: AUTH_RESULT_EVENT|<result>|<op_id>|<mac>|<type>
            parts = data.split('|')
            if len(parts) >= 3:
                result_flag, op_id, target_mac = parts[0], parts[1], parts[2].upper()
                auth_type = parts[3] if len(parts) > 3 else "SRAFT"
                event_type = 'SUCCESS' if result_flag == '1' else 'FAILURE'
                session.add(AuthLog(
                    timestamp=timestamp, 
                    campaign_id=campaign_id, 
                    event=event_type, 
                    authenticated_node_mac=target_mac, 
                    operation_id=op_id,
                    auth_type=auth_type
                ))
                log_end_of_phase_stats(op_id, AuthStat, nodes_to_query=current_online_nodes)
            else:
                logger.warning(f"Malformed AUTH_RESULT_EVENT from {from_ip}")
            
        elif event_name == 'ATTEST_START':
            # Format: ATTEST_START|<op_id>|<attested mac>, sent by the Verifier
            parts = data.split('|')
            if len(parts) >= 2:
                op_id, node_mac = parts[0], parts[1].upper()
                _trigger_start_phase_on_all_nodes()
                session.add(AttestLog(
                    timestamp=timestamp,
                    campaign_id=campaign_id,
                    event='START',
                    attested_node_mac=node_mac,
                    verifier_mac=reporter_mac,
                    operation_id=op_id
                ))
                session.commit()
            else:
                logger.warning(f"Malformed ATTEST_START from {from_ip}")

        elif event_name == 'ATTEST_RESULT_EVENT':
            # Format: ATTEST_RESULT_EVENT|<result>|<op_id>|<attested mac>
            parts = data.split('|')
            if len(parts) >= 3:
                result_flag, op_id, node_mac = parts[0], parts[1], parts[2].upper()
                session.add(AttestLog(
                    timestamp=timestamp,
                    campaign_id=campaign_id,
                    event='SUCCESS' if result_flag == '1' else 'FAILURE',
                    attested_node_mac=node_mac,
                    verifier_mac=reporter_mac,
                    operation_id=op_id
                ))
                log_end_of_phase_stats(op_id, AttestStat, nodes_to_query=current_online_nodes)
            else:
                logger.warning(f"Malformed ATTEST_RESULT_EVENT from {from_ip}")

        elif event_name == 'JOIN_VERIFIERS':
            try:
                parts = data.split(':', 1)
                if len(parts) == 2:
                    node_ip = parts[0]
                    verifier_list_str = parts[1]
                    verifiers = set(verifier_list_str.split(','))
                    with state_lock:
                        if node_ip not in node_verifier_mapping:
                            node_verifier_mapping[node_ip] = set()
                        node_verifier_mapping[node_ip].update(verifiers)
                else:
                    logger.warning(f"Malformed JOIN_VERIFIERS from {from_ip}")
            except Exception as e:
                logger.warning(f"Could not parse JOIN_VERIFIERS message: {e}")

        elif event_name == 'HEAL_START':
            node_ip_healed = data
            node_mac_healed = get_mac_from_ip(session, node_ip_healed)
            if not node_mac_healed:
                 logger.error(f"[{campaign_id}] Cannot log {event_name}: MAC for IP {node_ip_healed} not found. Dropping.")
                 return

            op_id_heal = f"heal_{node_mac_healed}_{int(timestamp.timestamp())}"
            _trigger_start_phase_on_all_nodes()
            session.add(HealingLog(timestamp=timestamp, campaign_id=campaign_id, event='START', node_mac=node_mac_healed, operation_id=op_id_heal))
            session.commit()

        elif event_name in ['HEAL_COMPLETE', 'HEAL_FAILED']:
            node_ip_healed = data
            node_mac_healed = get_mac_from_ip(session, node_ip_healed)
            if not node_mac_healed:
                 logger.error(f"[{campaign_id}] Cannot log {event_name}: MAC for IP {node_ip_healed} not found. Dropping.")
                 return
                 
            job_data = {
                'event_name': event_name, 
                'node_ip': node_ip_healed,
                'node_mac': node_mac_healed,
                'timestamp': timestamp, 
                'campaign_id': campaign_id
            }
            if not _try_process_end_event(session, job_data, current_online_nodes):
                job_data_for_retry = job_data

        elif event_name == 'BOOTSTRAP_START':
            node_mac = data.upper()
            op_id = f"bootstrap_{campaign_id}"
            _trigger_start_phase_on_all_nodes()
            session.add(HealingLog(timestamp=timestamp, campaign_id=campaign_id, event='BOOTSTRAP_START', node_mac=node_mac, operation_id=op_id))
            session.commit()

        elif event_name == 'BOOTSTRAP_COMPLETE':
            node_mac = data.upper()
            op_id = f"bootstrap_{campaign_id}"
            session.add(HealingLog(timestamp=timestamp, campaign_id=campaign_id, event='BOOTSTRAP_COMPLETE', node_mac=node_mac, operation_id=op_id))
            log_end_of_phase_stats(op_id, BootstrapStat, nodes_to_query=current_online_nodes)
            bootstrap_completed.set()
        
        elif event_name == 'WAIT_FOR_BOOTSTRAP_HEAL':
            bootstrap_completed.wait()
            if conn: conn.sendall(b"OK")
            bootstrap_completed.clear()

        elif event_name == 'WAIT_FOR_REMOVE_COMPLETE':
            remove_completed_event.wait()
            if conn: conn.sendall(b"OK")
            remove_completed_event.clear()

        if event_name not in [
            'HEAL_START', 'JOIN_START', 'SET_CAMPAIGN', 'JOIN_VERIFIERS',
            'REMOVE_START', 'HEALING_PHASE_START', 'AUTH_START', 'ATTEST_START', 'BOOTSTRAP_START',
            'JOIN_COMPLETE', 'JOIN_FAILED', 'REMOVE_COMPLETE', 
            'HEALING_PHASE_COMPLETE', 'HEALING_PHASE_FAILED',
            'HEAL_COMPLETE', 'HEAL_FAILED', 'INTEGRITY_CHECK_FAILED'
        ]:
            session.commit()

        if job_data_for_retry:
            with pending_events_lock:
                pending_end_events.append(job_data_for_retry)
                all_jobs_processed_event.clear()

    except (ValueError, IndexError) as e:
        logger.warning(f"Could not parse malformed message '{message}': {e}")
        session.rollback()
    except Exception as e:
        logger.error(f"Error processing message '{message}': {e}", exc_info=True)
        session.rollback()
    finally:
        session.close()
                        
def reaper_thread():
    """Periodically removes nodes from the online list if they haven't sent a heartbeat."""
    logger.info("Reaper thread started.")
    while True:
        time.sleep(REAPER_INTERVAL_SECONDS)
        session = SessionLocal()
        try:
            timeout_threshold = datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS)
            query = session.query(OnlineNode).filter(OnlineNode.last_seen < timeout_threshold)
            inactive_nodes = query.all()
            if inactive_nodes:
                inactive_ips = [node.ip_address for node in inactive_nodes]
                logger.info(f"Reaper: Removing {len(inactive_ips)} inactive nodes: {inactive_ips}")
                query.delete(synchronize_session=False)
                session.commit()
                with state_lock:
                    for ip in inactive_ips:
                        cluster_nodes.discard(ip)
        except Exception as e:
            logger.error(f"Reaper thread error: {e}")
            session.rollback()
        finally:
            session.close()

def client_handler(conn: socket.socket, addr: tuple):
    """
    Handles a single incoming client connection for the TCP server,
    reading all data until the connection is closed.
    """
    from_ip = addr[0]
    full_message = ""
    try:
        with conn:
            while True:
                chunk = conn.recv(2048)
                if not chunk:
                    break
                full_message += chunk.decode('utf-8')
            
            if full_message:
                parse_and_log_message(full_message, from_ip, conn)

    except Exception as e:
        logger.error(f"Error in client thread for {from_ip}: {e}")
        
def run_tcp_server():
    """Runs the main TCP server loop to listen for messages from ESP32 nodes."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, LOG_PORT_TCP))
            s.listen()
            logger.info(f"TCP logging server is running on {HOST}:{LOG_PORT_TCP}")
            while not shutdown_event.is_set():
                client_socket, addr = s.accept()
                if shutdown_event.is_set():
                    client_socket.close()
                    break
                handler_thread = threading.Thread(target=client_handler, args=(client_socket, addr), daemon=True)
                handler_thread.start()
    except Exception as e:
        if not shutdown_event.is_set():
            logger.error(f"A critical error occurred in the main TCP server loop: {e}")
    logger.info("TCP logging server has stopped.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup and shutdown events for the FastAPI application."""
    logger.info("API server is running.")
    yield
    logger.info("API server is shutting down.")

api_app = FastAPI(lifespan=lifespan)

class CampaignStartRequest(BaseModel):
    """Pydantic model for the /campaign/start request body."""
    campaign_id: str
    
class AttestationRequest(BaseModel):
    """Pydantic model for the /trigger/attestation request body."""
    node_ip: str

def _generate_summary_for_phase(db: Session, campaign_id: str, type: str, log_model, stat_model, end_events: list):
    """
    Calculates summary for a single phase type per operation_id.
    MODIFIED: Now also calculates and stores stddev for cluster stats.
    """
    op_ids_query = db.query(log_model.operation_id).filter(
        log_model.campaign_id == campaign_id,
        log_model.operation_id.isnot(None)
    ).distinct()
    op_ids = [row[0] for row in op_ids_query]

    if not op_ids:
        return

    for op_id in op_ids:
        current_op_id_type = None
        for prefix, phase_name in phase_prefix_map.items():
            if op_id.startswith(prefix):
                current_op_id_type = phase_name
                break

        if current_op_id_type != type:
            continue
        
        # Operation identifiers (e.g. election_<term>) repeat across campaigns, so every query is
        # restricted to the campaign.
        start_log = db.query(log_model).filter(log_model.campaign_id == campaign_id, log_model.operation_id == op_id, log_model.event.ilike('%START%')).order_by(log_model.timestamp.asc()).first()
        end_log = db.query(log_model).filter(log_model.campaign_id == campaign_id, log_model.operation_id == op_id, log_model.event.in_(end_events)).order_by(log_model.timestamp.desc()).first()

        if not start_log or not end_log: continue

        duration = (end_log.timestamp - start_log.timestamp).total_seconds()
        if duration < 0: continue

        outcome = "FAILURE"
        if type == "ELECTION":
            success_log = db.query(log_model).filter(
                log_model.campaign_id == campaign_id,
                log_model.operation_id == op_id, 
                log_model.event == 'ELECTED'
            ).first()
            if success_log:
                outcome = "SUCCESS"
        else:
            if end_log.event not in ['FAILED', 'STEPDOWN', 'FAILURE', 'HEAL_FAILED']:
                outcome = "SUCCESS"
        
        avg_stats_and_count = db.query(
            func.avg(stat_model.cpu_usage_percent),
            func.stddev(stat_model.cpu_usage_percent),
            func.avg(stat_model.memory_load_percent),
            func.stddev(stat_model.memory_load_percent),
            func.avg(stat_model.estimated_power_mw),
            func.stddev(stat_model.estimated_power_mw),
            func.count(stat_model.id)
        ).filter(stat_model.campaign_id == campaign_id, stat_model.operation_id == op_id).one_or_none()

        if not avg_stats_and_count or avg_stats_and_count[6] == 0:
            logger.warning(f"No stats found in {stat_model.__tablename__} for {op_id}, skipping summary row.")
            continue

        avg_cpu = avg_stats_and_count[0] or 0.0
        std_cpu = avg_stats_and_count[1] or 0.0
        avg_mem = avg_stats_and_count[2] or 0.0
        std_mem = avg_stats_and_count[3] or 0.0
        avg_pow = avg_stats_and_count[4] or 0.0
        std_pow = avg_stats_and_count[5] or 0.0
        nodes_that_reported_count = avg_stats_and_count[6] or 0

        summary_entry = SummaryStat(
            campaign_id=campaign_id,
            operation_id=op_id,
            phase_type=type,
            start_time=start_log.timestamp,
            end_time=end_log.timestamp,
            duration_seconds=duration,
            outcome=outcome,
            participating_nodes_count=nodes_that_reported_count,
            cluster_avg_cpu=avg_cpu,
            cluster_std_cpu=std_cpu,
            cluster_avg_memory=avg_mem,
            cluster_std_memory=std_mem,
            cluster_avg_power=avg_pow,
            cluster_std_power=std_pow
        )
        db.add(summary_entry)
            
@api_app.get("/query/online_nodes", response_model=dict)
def get_online_nodes(db: Session = Depends(get_session)):
    """Returns a list of all nodes currently considered online."""
    nodes = db.query(OnlineNode.ip_address).order_by(OnlineNode.last_seen.desc()).all()
    return {"nodes": [node.ip_address for node in nodes]}

@api_app.get("/query/latest_leader", response_model=dict)
def get_leader(db: Session = Depends(get_session)):
    """
    Finds the MAC address of the latest elected leader, then finds its
    current IP address from the OnlineNode table.
    """
    result = db.query(ElectionLog.node_mac).filter(ElectionLog.event == 'ELECTED').order_by(ElectionLog.timestamp.desc()).first()
    if result and result[0]:
        leader_mac = result[0]
        node = db.query(OnlineNode.ip_address).filter(
            OnlineNode.mac_address == leader_mac
        ).first()
        
        if node and node.ip_address:
            return {"leader_ip": node.ip_address, "leader_mac": leader_mac}
        else:
            logger.warning(f"Found leader MAC ({leader_mac}) but could not find its current IP in OnlineNode table.")
            raise HTTPException(status_code=404, detail=f"Leader (MAC: {leader_mac}) is offline.")

    raise HTTPException(status_code=404, detail="Leader not found")

@api_app.get("/query/auth_success_count", response_model=dict)
def get_auth_success_count(campaign_id: str, db: Session = Depends(get_session)):
    """Returns the number of successful authentications for a given campaign."""
    count = db.query(AuthLog).filter(AuthLog.campaign_id == campaign_id, AuthLog.event == 'SUCCESS').count()
    return {"campaign_id": campaign_id, "successful_authentications": count}

def _wait_for_pending_jobs():
    """Waits for all background logging and stats jobs to complete."""
    logger.info("Waiting for all pending log events to be processed before exporting...")
    wait_timeout = 30.0
    if not all_jobs_processed_event.wait(timeout=wait_timeout):
        with pending_events_lock:
            pending_count = len(pending_end_events)
        logger.error(f"Export timed out after {wait_timeout}s. {pending_count} events are still pending. Report may be incomplete.")
    else:
        logger.info("All pending log events processed.")
    
    logger.info("Waiting 5 seconds for final stats events to settle...")
    time.sleep(5)
    
    with state_lock:
        threads_to_join = list(active_worker_threads)
    
    if threads_to_join:
        logger.info(f"Waiting for {len(threads_to_join)} active statistics job(s) to complete...")
        for thread in threads_to_join:
            thread.join()
        logger.info("All statistics jobs have completed.")

def _generate_and_commit_summary(campaign_id: str, db: Session):
    """
    Helper function to generate summary stats for a *single* campaign.
    """
    logger.info(f"[{campaign_id}] Populating base summary_stats table...")
    db.query(SummaryStat).filter(SummaryStat.campaign_id == campaign_id).delete()
    
    for phase_type, config in PHASE_CONFIG.items():
        _generate_summary_for_phase(
            db=db,
            campaign_id=campaign_id,
            type=phase_type,
            log_model=config["log_model"],
            stat_model=config["stat_model"],
            end_events=config["end_events"]
        )
    
    db.commit()

def _format_summary_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Applies standard formatting to summary DataFrames."""
    
    if 'outcome' in df.columns:
        df['total_ops'] = df.groupby('operation_id')['outcome'].transform('count')
        df_success = df[df['outcome'] == 'SUCCESS'].groupby('operation_id')['outcome'].transform('count').fillna(0)
        df['success_count'] = df_success
        df.fillna({'success_count': 0}, inplace=True)

        df['operations'] = df.apply(
            lambda row: f"{int(row.get('success_count', 0))}/{int(row.get('total_ops', 0))}" if row.get('phase_type') in ['ELECTION', 'JOIN', 'REMOVE', 'HEAL', 'AUTH', 'INTEGRITY_CHECK'] else 'N/A', axis=1
        )
        df['success_rate_perc'] = df.apply(
            lambda row: (row.get('success_count', 0) / row.get('total_ops', 1)) * 100 if row.get('total_ops', 0) > 0 else 0.0, axis=1
        )
    else:
        df['operations'] = 'N/A'
        df['success_rate_perc'] = 0.0

    df.rename(columns={
        'participating_nodes_count': 'num_nodes',
        'duration_seconds': 'avg_duration_s',
        'cluster_avg_cpu': 'avg_cluster_cpu_perc',
        'cluster_std_cpu': 'std_cluster_cpu_perc',
        'cluster_avg_memory': 'avg_cluster_mem_perc',
        'cluster_std_memory': 'std_cluster_mem_perc',
        'cluster_avg_power': 'avg_cluster_power_mW',
        'cluster_std_power': 'std_cluster_power_mW'
    }, inplace=True)

    columns_ordered = [
        'campaign_id', 'phase_type', 'operations', 'num_nodes',
        'success_rate_perc', 'avg_duration_s', 
        'avg_cluster_cpu_perc', 'std_cluster_cpu_perc', 
        'avg_cluster_mem_perc', 'std_cluster_mem_perc', 
        'avg_cluster_power_mW', 'std_cluster_power_mW'
    ]
    
    final_columns = [col for col in columns_ordered if col in df.columns]
    df_copy = df[final_columns].copy()
    float_cols_to_round = [
        'success_rate_perc', 'avg_duration_s', 'avg_cluster_cpu_perc', 'std_cluster_cpu_perc',
        'avg_cluster_mem_perc', 'std_cluster_mem_perc', 'avg_cluster_power_mW', 'std_cluster_power_mW'
    ]
    for col in float_cols_to_round:
        if col in df_copy.columns:
            df_copy.loc[:, col] = df_copy[col].round(4)
            
    if 'num_nodes' in df_copy.columns:
        df_copy.loc[:, 'num_nodes'] = df_copy['num_nodes'].round().astype(int)
    
    return df_copy

@api_app.post("/campaign/export_one/{campaign_id}", response_model=dict)
def export_one_campaign_summary(campaign_id: str, db: Session = Depends(get_session)):
    """
    Generates the 5 report files for a SINGLE campaign and returns them as a ZIP.
    This is for the per-iteration reports.
    """
    _wait_for_pending_jobs()
    
    try:
        _generate_and_commit_summary(campaign_id, db)

        summaries_query = db.query(SummaryStat).filter(SummaryStat.campaign_id == campaign_id)
        summaries_df = pd.read_sql(summaries_query.statement, summaries_query.session.bind)
        
        if summaries_df.empty:
            raise HTTPException(status_code=404, detail=f"No summary data found for campaign '{campaign_id}'.")

        formatted_df = _format_summary_dataframe(summaries_df)
        # SummaryStat does not record the scheme of an authentication: it is taken from its START log, so
        # that SRAFT, TLS, and MQTTS are reported separately.
        auth_types = dict(db.query(AuthLog.operation_id, AuthLog.auth_type).filter(
            AuthLog.campaign_id == campaign_id, AuthLog.event == 'START').all())
        formatted_df['auth_type'] = summaries_df['operation_id'].map(auth_types)
        formatted_df.loc[formatted_df['phase_type'] != 'AUTH', 'auth_type'] = None

        temp_dir = tempfile.mkdtemp()
        try:
            # Samples of every device in every operation, with the duration and the outcome of the
            # operation, so that the costs can be reported per device and per role.
            per_device_frames = []
            for phase_type, config in PHASE_CONFIG.items():
                phase_ops = summaries_df[summaries_df['phase_type'] == phase_type]
                if phase_ops.empty:
                    continue
                stat_model = config["stat_model"]
                stats_query = db.query(stat_model).filter(stat_model.campaign_id == campaign_id,
                                                          stat_model.operation_id.in_(phase_ops['operation_id'].tolist()))
                phase_df = pd.read_sql(stats_query.statement, db.bind)
                if phase_df.empty:
                    continue
                duration_col = 'avg_duration_s' if 'avg_duration_s' in phase_ops.columns else 'duration_seconds'
                ops = phase_ops[['operation_id', duration_col, 'outcome']].rename(columns={duration_col: 'duration_s'})
                phase_df = phase_df.merge(ops, on='operation_id', how='left')
                phase_df['phase_type'] = phase_type
                phase_df['auth_type'] = phase_df['operation_id'].map(auth_types) if phase_type == 'AUTH' else None
                phase_df['timestamp'] = phase_df['timestamp'].astype(str)
                per_device_frames.append(phase_df.drop(columns=['id']))
            if per_device_frames:
                pd.concat(per_device_frames, ignore_index=True).to_excel(
                    os.path.join(temp_dir, "report_per_device.xlsx"), index=False, engine='openpyxl')

            global_summary_to_save = formatted_df.sort_values(by=['phase_type'])
            global_summary_to_save.to_excel(os.path.join(temp_dir, "report_global_summary.xlsx"), index=False, engine='openpyxl')
            agg_rules = {
                'num_nodes': 'mean',
                'success_rate_perc': 'mean',
                'avg_duration_s': 'mean',
                'avg_cluster_cpu_perc': 'mean',
                'std_cluster_cpu_perc': 'mean',
                'avg_cluster_mem_perc': 'mean',
                'std_cluster_mem_perc': 'mean',
                'avg_cluster_power_mW': 'mean',
                'std_cluster_power_mW': 'mean',
                'operations': 'count'
            }
            
            agg_df = formatted_df.groupby(['campaign_id', 'phase_type']).agg(agg_rules).reset_index()
            agg_df.rename(columns={'operations': 'ops_count_in_avg'}, inplace=True)
            
            float_cols = [col for col in agg_df.columns if agg_df[col].dtype == 'float64']
            if float_cols:
                agg_df[float_cols] = agg_df[float_cols].round(4)
            if 'num_nodes' in agg_df.columns:
                agg_df['num_nodes'] = agg_df['num_nodes'].round().astype(int)

            election_df = agg_df[agg_df['phase_type'] == 'ELECTION']
            election_df.to_excel(os.path.join(temp_dir, "report_scenario_election.xlsx"), index=False, engine='openpyxl')
            
            join_df = agg_df[agg_df['phase_type'].isin(['BOOTSTRAP', 'JOIN'])].copy()
            join_order = ['BOOTSTRAP', 'JOIN']
            join_df['phase_type'] = pd.Categorical(join_df['phase_type'], categories=join_order, ordered=True)
            join_df = join_df.sort_values(by=['phase_type'])
            join_df.to_excel(os.path.join(temp_dir, "report_scenario_join.xlsx"), index=False, engine='openpyxl')
            
            removal_df = agg_df[agg_df['phase_type'].isin(['REMOVE', 'HEALING_PHASE', 'HEAL'])].copy()
            removal_order = ['REMOVE', 'HEALING_PHASE', 'HEAL']
            removal_df['phase_type'] = pd.Categorical(removal_df['phase_type'], categories=removal_order, ordered=True)
            removal_df = removal_df.sort_values(by=['phase_type'])
            removal_df.to_excel(os.path.join(temp_dir, "report_scenario_removal.xlsx"), index=False, engine='openpyxl')

            attestation_df = agg_df[agg_df['phase_type'] == 'INTEGRITY_CHECK']
            if not attestation_df.empty:
                attestation_df.to_excel(os.path.join(temp_dir, "report_scenario_attestation.xlsx"), index=False, engine='openpyxl')
                # Samples of each device in each attestation, with the duration of the attestation,
                # so that the cost can be reported per device and per role.
                stats_query = db.query(AttestStat).filter(AttestStat.campaign_id == campaign_id)
                per_device_df = pd.read_sql(stats_query.statement, db.bind)
                # summaries_df has been renamed in place by _format_summary_dataframe.
                duration_col = 'avg_duration_s' if 'avg_duration_s' in summaries_df.columns else 'duration_seconds'
                durations = summaries_df[summaries_df['phase_type'] == 'INTEGRITY_CHECK'][['operation_id', duration_col, 'outcome']]
                durations = durations.rename(columns={duration_col: 'duration_s'})
                per_device_df = per_device_df.merge(durations, on='operation_id', how='left')
                starts_query = db.query(AttestLog.operation_id, AttestLog.attested_node_mac, AttestLog.verifier_mac).filter(
                    AttestLog.campaign_id == campaign_id, AttestLog.event == 'START')
                starts_df = pd.read_sql(starts_query.statement, db.bind)
                per_device_df = per_device_df.merge(starts_df, on='operation_id', how='left')
                # Excel does not store time zones.
                per_device_df['timestamp'] = per_device_df['timestamp'].astype(str)
                per_device_df.to_excel(os.path.join(temp_dir, "report_attestation_per_device.xlsx"), index=False, engine='openpyxl')

            auth_rows = formatted_df[formatted_df['phase_type'] == 'AUTH']
            auth_agg = auth_rows.groupby(['campaign_id', 'phase_type', 'auth_type']).agg(agg_rules).reset_index() \
                if not auth_rows.empty else pd.DataFrame(columns=['auth_type'])
            auth_agg = auth_agg.rename(columns={'operations': 'ops_count_in_avg'})
            auth_custom_df = auth_agg[auth_agg['auth_type'] == 'SRAFT']
            if not auth_custom_df.empty:
                auth_custom_df.to_excel(os.path.join(temp_dir, "report_auth_sraft.xlsx"), index=False, engine='openpyxl')
            
            auth_tls_df = auth_agg[auth_agg['auth_type'] == 'TLS']
            if not auth_tls_df.empty:
                auth_tls_df.to_excel(os.path.join(temp_dir, "report_auth_tls.xlsx"), index=False, engine='openpyxl')
            
            auth_tls_resumed_df = auth_agg[auth_agg['auth_type'] == 'TLS_RESUMED']
            if not auth_tls_resumed_df.empty:
                auth_tls_resumed_df.to_excel(os.path.join(temp_dir, "report_auth_tls_resumed.xlsx"), index=False, engine='openpyxl')

            auth_mqtts_df = auth_agg[auth_agg['auth_type'] == 'MQTTS']
            if not auth_mqtts_df.empty:
                auth_mqtts_df.to_excel(os.path.join(temp_dir, "report_auth_mqtts.xlsx"), index=False, engine='openpyxl')
            
            if auth_custom_df.empty and auth_tls_df.empty and auth_tls_resumed_df.empty and auth_mqtts_df.empty:
                auth_df = agg_df[agg_df['phase_type'] == 'AUTH']
                if not auth_df.empty:
                    auth_df.to_excel(os.path.join(temp_dir, "report_scenario_authentication.xlsx"), index=False, engine='openpyxl')
            
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        zip_file.write(os.path.join(root, file), arcname=file)
                        
            zip_buffer.seek(0)
            return StreamingResponse(
                zip_buffer, 
                media_type='application/zip', 
                headers={'Content-Disposition': f'attachment; filename="report_{campaign_id}.zip"'}
            )

        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    except Exception as e:
        logger.error(f"Failed to generate report for campaign '{campaign_id}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    
def _generate_intra_device_analysis(db: Session):
    """
    Calculates intra-device statistics.
    
    This function queries all raw statistic tables (JoinStat, ElectionStat, etc.),
    groups them by cluster_size, phase_type, and node_ip.
    It first calculates the average performance for each node across all iterations
    of a given cluster size.
    It then calculates the average and standard deviation *of those averages*
    to get the final "average intra-device" metrics.
    
    Returns:
        dict: A dictionary mapping phase_type to its aggregated DataFrame.
    """
    logger.info("Calculating intra-device statistics from raw tables...")
    all_raw_stats_df = []

    for phase_type, config in PHASE_CONFIG.items():
        stat_model = config["stat_model"]
        
        query = db.query(
            stat_model.campaign_id,
            stat_model.node_mac,
            stat_model.cpu_usage_percent,
            stat_model.memory_load_percent,
            stat_model.estimated_power_mw
        )
        df = pd.read_sql(query.statement, db.bind)
        
        if df.empty:
            logger.warning(f"No raw stats found for phase '{phase_type}', skipping intra-device analysis for it.")
            continue
            
        df['phase_type'] = phase_type
        all_raw_stats_df.append(df)

    if not all_raw_stats_df:
        logger.error("No raw statistics found in any table. Cannot generate intra-device report.")
        return {}

    full_df = pd.concat(all_raw_stats_df)
    size_extract = full_df['campaign_id'].str.extract(r'size_(\d+)_iter|single_run_(\d+)_nodes')
    
    full_df['cluster_size'] = size_extract[0].fillna(size_extract[1])
    
    full_df.dropna(subset=['cluster_size'], inplace=True)
    full_df['cluster_size'] = full_df['cluster_size'].astype(int)

    intra_device_avg_df = full_df.groupby(['cluster_size', 'phase_type', 'node_mac']).agg(
        avg_cpu=('cpu_usage_percent', 'mean'),
        avg_mem=('memory_load_percent', 'mean'),
        avg_pow=('estimated_power_mw', 'mean')
    ).reset_index()

    final_intra_device_summary = intra_device_avg_df.groupby(['cluster_size', 'phase_type']).agg(
        intra_device_cpu_mean=('avg_cpu', 'mean'),
        intra_device_cpu_std=('avg_cpu', 'std'),
        intra_device_mem_mean=('avg_mem', 'mean'),
        intra_device_mem_std=('avg_mem', 'std'),
        intra_device_pow_mean=('avg_pow', 'mean'),
        intra_device_pow_std=('avg_pow', 'std')
    ).reset_index()
    
    analysis_dataframes = {}
    for phase_type in final_intra_device_summary['phase_type'].unique():
        df_phase = final_intra_device_summary[
            final_intra_device_summary['phase_type'] == phase_type
        ].sort_values(by='cluster_size')
        
        float_cols = [col for col in df_phase.columns if df_phase[col].dtype == 'float64']
        df_phase[float_cols] = df_phase[float_cols].fillna(0.0).round(4)
        
        analysis_dataframes[phase_type] = df_phase

    logger.info("Intra-device analysis complete.")
    return analysis_dataframes

@api_app.post("/campaign/export_final_analysis", response_model=dict)
def export_final_analysis(db: Session = Depends(get_session)):
    """
    Generates a final analysis report by aggregating stats across all
    iterations for each cluster size. Returns as a ZIP.
    
    This now generates TWO sets of analyses:
    1. Inter-Device (Legacy): The average of cluster-wide averages from SummaryStat.
    2. Intra-Device (New): The average of node-specific averages from raw *Stat tables.
    """
    _wait_for_pending_jobs()
    
    try:
        logger.info("Generating inter-device analysis (average of cluster averages)...")
        all_summaries_query = db.query(SummaryStat)
        df_inter = pd.read_sql(all_summaries_query.statement, all_summaries_query.session.bind)
        
        if df_inter.empty:
            logger.warning("No summary data found. Skipping inter-device analysis.")
        else:
            size_extract = df_inter['campaign_id'].str.extract(r'size_(\d+)_iter|single_run_(\d+)_nodes')
    
            df_inter['cluster_size'] = size_extract[0].fillna(size_extract[1])

            df_inter.dropna(subset=['cluster_size'], inplace=True)
            df_inter['cluster_size'] = df_inter['cluster_size'].astype(int)

            grouped = df_inter.groupby(['cluster_size', 'phase_type'])
            final_agg_df = grouped.agg(
                iterations_count=('campaign_id', 'nunique'),
                duration_mean=('duration_seconds', 'mean'),
                duration_std=('duration_seconds', 'std'),
                cpu_mean=('cluster_avg_cpu', 'mean'),
                cpu_std=('cluster_avg_cpu', 'std'),
                memory_mean=('cluster_avg_memory', 'mean'),
                memory_std=('cluster_avg_memory', 'std'),
                power_mean=('cluster_avg_power', 'mean'),
                power_std=('cluster_avg_power', 'std'),
                avg_interdevice_cpu_std=('cluster_std_cpu', 'mean'),
                avg_interdevice_memory_std=('cluster_std_memory', 'mean'),
                avg_interdevice_power_std=('cluster_std_power', 'mean'),
                total_success=('outcome', lambda x: (x == 'SUCCESS').sum()),
                total_ops=('outcome', 'count')
            ).reset_index()

            final_agg_df['success_rate_perc'] = (final_agg_df['total_success'] / final_agg_df['total_ops']) * 100

        logger.info("Generating intra-device analysis (average of node-averages)...")
        intra_device_reports = _generate_intra_device_analysis(db)

        temp_dir = tempfile.mkdtemp()
        try:
            if not df_inter.empty:
                metric_cols = [
                    'duration_mean', 'duration_std',
                    'cpu_mean', 'cpu_std', 'avg_interdevice_cpu_std',
                    'memory_mean', 'memory_std', 'avg_interdevice_memory_std',
                    'power_mean', 'power_std', 'avg_interdevice_power_std'
                ]
                base_cols = ['cluster_size', 'iterations_count', 'success_rate_perc']
                
                for phase in final_agg_df['phase_type'].unique():
                    phase_df = final_agg_df[final_agg_df['phase_type'] == phase].copy()
                    if not phase_df.empty:
                        phase_df[metric_cols] = phase_df[metric_cols].fillna(0.0).round(4)
                        phase_df['success_rate_perc'] = phase_df['success_rate_perc'].fillna(0.0).round(2)
                        phase_df['iterations_count'] = phase_df['iterations_count'].astype(int)
                        
                        file_path = os.path.join(temp_dir, f"final_analysis_INTER_DEVICE_{phase.lower()}.xlsx")
                        phase_df[base_cols + metric_cols].sort_values(by='cluster_size').to_excel(file_path, index=False, engine='openpyxl')

            if intra_device_reports:
                for phase_type, df_intra in intra_device_reports.items():
                    if not df_intra.empty:
                        file_path_intra = os.path.join(temp_dir, f"final_analysis_INTRA_DEVICE_{phase_type.lower()}.xlsx")
                        df_intra.to_excel(file_path_intra, index=False, engine='openpyxl')
            
            if not os.listdir(temp_dir):
                raise HTTPException(status_code=404, detail="No data found for any analysis.")

            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        zip_file.write(os.path.join(root, file), arcname=file)
                        
            zip_buffer.seek(0)
            return StreamingResponse(
                zip_buffer, 
                media_type='application/zip', 
                headers={'Content-Disposition': 'attachment; filename="report_final_analysis.zip"'}
            )

        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                
    except Exception as e:
        logger.error(f"Failed to generate final analysis report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

def run_api_server():
    """Starts the Uvicorn server for the HTTP API."""
    uvicorn.run(api_app, host=HOST, port=API_PORT_HTTP, log_level="warning")

def export_database_to_excel():
    """Exports all database tables to separate .xlsx files."""
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db_exported")
    logger.info(f"Starting database export to directory '{output_dir}'...")
    try:
        os.makedirs(output_dir, exist_ok=True)
        table_names = Base.metadata.tables.keys()
        for table_name in table_names:
            logger.info(f"Exporting table: '{table_name}'...")
            try:
                df = pd.read_sql_table(table_name, engine)
                for col in df.columns:
                    if pd.api.types.is_datetime64_any_dtype(df[col]) and df[col].dt.tz is not None:
                        df[col] = df[col].dt.tz_localize(None)
                        
                if df.empty:
                    logger.warning(f"Table '{table_name}' is empty, a file with only headers will be created.")
                file_path = os.path.join(output_dir, f"{table_name}.xlsx")
                df.to_excel(file_path, index=False, engine='openpyxl')
                logger.success(f"Table '{table_name}' exported successfully to '{file_path}'.")
            except Exception as e:
                logger.error(f"Could not export table '{table_name}': {e}")
        logger.success("Database export completed.")
    except Exception as e:
        logger.error(f"Critical error during the database export process: {e}")

def export_database_with_pg_dump():
    """Exports the entire PostgreSQL database using the pg_dump utility."""
    logger.info("Preparing database export using global DATABASE_URL...")
    try:
        url = make_url(DATABASE_URL)
        db_host, db_port, db_name, db_user, db_pass = url.host, str(url.port or 5432), url.database, url.username, url.password
        if not all([db_host, db_name, db_user, db_pass]):
            logger.error("DATABASE_URL is missing one or more required components.")
            return
        
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db_backups")
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(output_dir, f"backup_{db_name}_{timestamp}.dump")

        logger.info(f"Exporting PostgreSQL database '{db_name}' using pg_dump to '{file_path}'...")
        env = os.environ.copy()
        env["PGPASSWORD"] = db_pass
        command = ['pg_dump', '-U', db_user, '-h', db_host, '-p', db_port, '-d', db_name, '-F', 'c', '--no-owner', '--no-privileges', '-f', file_path]
        
        process = subprocess.run(command, capture_output=True, text=True, env=env)
        if process.returncode == 0:
            logger.success(f"Database exported successfully. pg_dump output:\n{process.stderr}")
        else:
            logger.error(f"pg_dump failed with exit code {process.returncode}.\nStderr: {process.stderr}")
    except FileNotFoundError:
        logger.error("pg_dump command not found. Is PostgreSQL client installed on this system?")
    except Exception as e:
        logger.error(f"An unexpected error occurred during database export: {e}")


if __name__ == '__main__':
    logger.remove()
    logger.add(sys.stderr, level="INFO")

    init_db()

    tcp_listener_thread = threading.Thread(target=run_tcp_server, daemon=True)
    tcp_listener_thread.start()

    reaper = threading.Thread(target=reaper_thread, daemon=True)
    reaper.start()
    
    retry_worker = threading.Thread(target=retry_worker_thread, daemon=True)
    retry_worker.start()

    try:
        run_api_server()
    except KeyboardInterrupt:
        logger.info("\nServer shutting down...")
        shutdown_event.set()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dummy_socket:
                dummy_socket.connect(('127.0.0.1', LOG_PORT_TCP))
        except Exception as e:
            logger.warning(f"Could not self-connect to unblock TCP server; it may take one more connection to shut down: {e}")
    finally:
        logger.info("Shutdown initiated. Exporting data...")
        
        _wait_for_pending_jobs()
        
        logger.info("Proceeding with final data export (dumping DB)...")
        export_database_with_pg_dump()
        
        logger.info("Disposing database engine connections...")
        engine.dispose()

        SessionLocal.remove()
        logger.info("Server stopped")