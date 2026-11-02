import asyncio
import glob
import os
import shutil
import subprocess
import sys
import json
import httpx
import serial
import multiprocessing
import threading
import uuid
import time
import uvicorn
from queue import Queue, Empty
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, as_completed

FIRMWARE_DIR = "/home/pi/firmware"
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

COMMAND_QUEUE = Queue()
RESULTS_DICT: Dict[str, Any] = {}
RESULTS_LOCK = threading.Lock()
SERIAL_LOGGERS: Dict[str, tuple[multiprocessing.Process, multiprocessing.Event]] = {}

ESP32_OFFSET = None
ESP32_COUNT = None

def serial_logger_process(device_port: str, log_file_path: str, shutdown_event: multiprocessing.Event):
    """
    Continuously reads from a serial port and writes to a log file until a shutdown event is set.
    """
    port_name = os.path.basename(device_port)
    baud_rate = 115200
    try:
        with serial.Serial(device_port, baud_rate, timeout=0.2) as ser, open(log_file_path, 'a', encoding='utf-8', errors='ignore') as log_file:
            while not shutdown_event.is_set():
                try:
                    data = ser.read(ser.in_waiting or 1)
                    if data:
                        text = data.decode('utf-8', errors='ignore')
                        filtered_text = "".join(c for c in text if c.isprintable() or c in '\n\r\t')
                        if filtered_text:
                            log_file.write(filtered_text)
                            log_file.flush()
                except serial.SerialException:
                    break
    except Exception:
        pass


def find_esp32_devices(offset: int = 0, count: Optional[int] = None) -> List[str]:
    """
    Finds and returns a sorted list of connected ESP32 devices based on an offset and count.
    """
    all_devices = glob.glob('/dev/ttyUSB*')
    # all_devices.sort()
    if count is None:
        return all_devices[offset:]
    return all_devices[offset : offset + count]


def hardware_controller_thread():
    """
    A dedicated thread that serializes all hardware operations by consuming jobs from a command queue.
    """
    logger.info("[Controller] Hardware Controller Thread started.")
    while True:
        try:
            job = COMMAND_QUEUE.get()
            if job is None:
                break
            job_id = job["job_id"]
            job_type = job["type"]
            logger.info(f"[Controller] Starting job {job_id} of type '{job_type}'.")
            
            job_result = {}
            try:
                if job_type == "reset":
                    job_result = _perform_reset(job["params"])
                elif job_type == "deploy":
                    stop_all_loggers()
                    time.sleep(1)
                    job_result = _perform_deploy(job["params"])
                    logger.info("[Controller] Restarting all loggers post-deploy.")
                    start_all_loggers()
            except Exception as e:
                logger.error(f"[Controller] Unhandled exception during job {job_id}: {e}")
                job_result = {"status": "controller_error", "detail": str(e)}
                if job_type == "deploy":
                    logger.info("[Controller] Restarting all loggers after error.")
                    start_all_loggers()
            
            with RESULTS_LOCK:
                RESULTS_DICT[job_id] = job_result
        except Exception as e:
            logger.error(f"[Controller] Critical error in main loop: {e}")
    logger.info("[Controller] Hardware Controller Thread stopped.")


def stop_all_loggers():
    """
    Gracefully stops all running serial logger processes.
    """
    logger.info("[Controller] Stopping all logger processes...")
    running_loggers = list(SERIAL_LOGGERS.items())
    for device, (process, event) in running_loggers:
        event.set()
    time.sleep(0.5)
    for device, (process, event) in running_loggers:
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
    SERIAL_LOGGERS.clear()
    logger.info("[Controller] All loggers stopped.")


def stop_loggers_for_devices(devices_to_stop: List[str]):
    """
    Stops and removes logger processes for a specific list of devices.
    """
    if not devices_to_stop:
        return
    logger.info(f"[Controller] Stopping loggers for specific devices: {devices_to_stop}")
    
    with RESULTS_LOCK:
        for device in devices_to_stop:
            if device in SERIAL_LOGGERS:
                process, event = SERIAL_LOGGERS.pop(device)
                event.set()
                time.sleep(0.1)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=1)
    logger.info(f"[Controller] Stopped {len(devices_to_stop)} loggers.")


def start_all_loggers():
    """
    Starts a serial logger process for the entire SUPERSET of deployed devices.
    """
    global ESP32_OFFSET, ESP32_COUNT
    os.makedirs(LOG_DIR, exist_ok=True)
    
    offset = ESP32_OFFSET if ESP32_OFFSET is not None else 0
    count = ESP32_COUNT if ESP32_COUNT is not None else 0
    
    devices_to_log = find_esp32_devices(offset, count)
    
    logger.info(f"[Controller] Starting loggers for {len(devices_to_log)} devices in range offset={offset}, count={count}...")
    for device in devices_to_log:
        if device not in SERIAL_LOGGERS:
            log_filepath = os.path.join(LOG_DIR, f"{os.path.basename(device)}.log")
            shutdown_event = multiprocessing.Event()
            process = multiprocessing.Process(
                target=serial_logger_process,
                args=(device, log_filepath, shutdown_event),
                daemon=True
            )
            process.start()
            SERIAL_LOGGERS[device] = (process, shutdown_event)
    logger.info("[Controller] Logger startup complete.")


def _update_global_device_range(request: "DeployRequest"):
    """
    Expands the global device window to include the range from the current request.
    """
    global ESP32_OFFSET, ESP32_COUNT

    if ESP32_OFFSET is None or ESP32_COUNT is None:
        ESP32_OFFSET = request.offset
        ESP32_COUNT = request.count
        return

    current_upper_bound = ESP32_OFFSET + ESP32_COUNT
    new_upper_bound = request.offset + (request.count if request.count is not None else 1)
    
    final_offset = min(ESP32_OFFSET, request.offset)
    final_upper_bound = max(current_upper_bound, new_upper_bound)
    
    ESP32_OFFSET = final_offset
    ESP32_COUNT = final_upper_bound - final_offset


def _perform_reset(params: dict):
    """
    Orchestrates the parallel reset operation and stops loggers for the targeted devices.
    """
    request = DeployRequest(**params)
    
    devices_to_reset = find_esp32_devices(request.offset, request.count)
    if not devices_to_reset:
        return {"status": "no_devices_found_for_this_reset_operation"}
        
    stop_loggers_for_devices(devices_to_reset)
    
    results = {}
    with ThreadPoolExecutor() as executor:
        future_to_device = {executor.submit(_reset_device, device): device for device in devices_to_reset}
        for future in as_completed(future_to_device):
            device = future_to_device[future]
            try:
                success, detail = future.result()
                results[device] = {"status": "success" if success else "failure", "detail": detail}
            except Exception as exc:
                results[device] = {"status": "failure", "detail": str(exc)}
    
    return {"status": "completed", "results": results}


def _perform_deploy(params: dict):
    """
    Orchestrates the parallel firmware deployment for a subset of devices.
    """
    request = DeployRequest(**params)
    _update_global_device_range(request)
    
    project_dir = ""
    try:
        zip_files = glob.glob(os.path.join(FIRMWARE_DIR, "*.zip"))
        if not zip_files: return {"status": "error", "detail": "No firmware zip file found."}
        
        project_dir_zip = zip_files[0]
        project_dir = os.path.splitext(project_dir_zip)[0]
        if os.path.exists(project_dir): shutil.rmtree(project_dir)
        subprocess.run(["unzip", "-o", project_dir_zip, "-d", FIRMWARE_DIR], check=True, capture_output=True)
        os.remove(project_dir_zip)
        
        devices_to_flash = find_esp32_devices(request.offset, request.count)
        if not devices_to_flash: return {"status": "no_devices_targeted_for_this_operation"}
        
        logger.info(f"Deploying to {len(devices_to_flash)} devices: {devices_to_flash}")
        results = {}
        with ThreadPoolExecutor() as executor:
            future_to_device = {executor.submit(_deploy_firmware, device, project_dir): device for device in devices_to_flash}
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    success, detail = future.result()
                    results[device] = {"status": "success" if success else "failure", "detail": detail}
                except Exception as exc:
                    results[device] = {"status": "failure", "detail": str(exc)}
        return {"status": "completed", "results": results}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
    finally:
        if project_dir and os.path.exists(project_dir):
            shutil.rmtree(project_dir)


def _execute_esptool_command(device: str, command: List[str], cwd: Optional[str] = None):
    """
    Executes an esptool command as a subprocess and streams its output in real-time.
    """
    port_name = os.path.basename(device)
    logger.info(f"[{port_name}] Executing esptool command: {' '.join(command)}")
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', cwd=cwd)
        stdout_output, stderr_output = [], []
        if process.stdout:
            for line in process.stdout:
                line = line.strip()
                if line:
                    logger.info(f"[{port_name}] {line}")
                    stdout_output.append(line)
        if process.stderr:
            for line in process.stderr:
                line = line.strip()
                if line:
                    logger.error(f"[{port_name}] {line}")
                    stderr_output.append(line)
        process.wait()
        if process.returncode == 0:
            return True, "\n".join(stdout_output)
        else:
            return False, "\n".join(stderr_output)
    except Exception as e:
        logger.error(f"[{port_name}] Subprocess execution failed: {e}")
        return False, str(e)


def _reset_device(device: str):
    """
    Constructs and executes the 'erase_flash' esptool command for a single device.
    """
    cmd = [sys.executable, "-m", "esptool", "--port", device, "erase-flash"]
    return _execute_esptool_command(device, cmd)


def _deploy_firmware(device: str, project_dir: str):
    """
    Constructs and executes the 'write_flash' esptool command for a single device.
    """
    try:
        with open(os.path.join(project_dir, "flasher_args.json"), "r") as f: 
            flasher_args = json.load(f)
        
        before_action = flasher_args["extra_esptool_args"]["before"].replace('_', '-')
        after_action = flasher_args["extra_esptool_args"]["after"].replace('_', '-')
        cmd = [
            sys.executable, "-m", "esptool", "--chip", "esp32", "--port", device, "--baud", "460800",
            "--before", before_action, "--after", after_action, "write_flash",
            "--flash-mode", flasher_args["flash_settings"]["flash_mode"], "--flash-size", flasher_args["flash_settings"]["flash_size"],
            "--flash-freq", flasher_args["flash_settings"]["flash_freq"],
            flasher_args["bootloader"]["offset"], os.path.join(project_dir, flasher_args["bootloader"]["file"]),
            flasher_args["partition-table"]["offset"], os.path.join(project_dir, flasher_args["partition-table"]["file"]),
            flasher_args["app"]["offset"], os.path.join(project_dir, flasher_args["app"]["file"])
        ]
        return _execute_esptool_command(device, cmd, cwd=project_dir)
    except Exception as e:
        return False, str(e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    An async context manager to handle server startup and shutdown events.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(FIRMWARE_DIR, exist_ok=True)
    controller_thread = threading.Thread(target=hardware_controller_thread, daemon=True)
    controller_thread.start()
    yield
    logger.info("--- Server shutting down ---")
    COMMAND_QUEUE.put(None)
    controller_thread.join(timeout=5)
    stop_all_loggers()


app = FastAPI(title="ESP32 Deployment Server", lifespan=lifespan)

class DeployRequest(BaseModel):
    offset: int = 0
    count: Optional[int] = None

class BroadcastCommandRequest(BaseModel):
    ips: List[str]
    path: str
    method: str = "GET"
    port: int = 80
    protocol: str = "http"
    payload: Optional[Dict[str, Any]] = None

class SendCommandRequest(BaseModel):
    ip: str
    path: str
    method: str = "GET"
    port: int = 80
    protocol: str = "http"
    payload: Optional[Dict[str, Any]] = None


@app.post("/deploy")
async def deploy(request: DeployRequest):
    """
    API endpoint to queue a firmware deployment job.
    This endpoint IS BLOCKING and will wait for the hardware job to complete.
    """
    job_id = str(uuid.uuid4())
    job = {"type": "deploy", "job_id": job_id, "params": request.model_dump()}
    COMMAND_QUEUE.put(job)
    while job_id not in RESULTS_DICT:
        await asyncio.sleep(1)
    with RESULTS_LOCK:
        result = RESULTS_DICT.pop(job_id)
    return JSONResponse(content=result)


@app.post("/reset")
async def reset(request: DeployRequest):
    """
    API endpoint to queue a reset job for all devices.
    This endpoint IS BLOCKING and will wait for the hardware job to complete.
    """
    job_id = str(uuid.uuid4())
    job = {"type": "reset", "job_id": job_id, "params": request.model_dump()}
    COMMAND_QUEUE.put(job)
    while job_id not in RESULTS_DICT:
        await asyncio.sleep(1)
    with RESULTS_LOCK:
        result = RESULTS_DICT.pop(job_id)
    return JSONResponse(content=result)


@app.post("/nodes/broadcast_command")
async def broadcast_node_command(request: BroadcastCommandRequest):
    """
    API endpoint to proxy the same command to multiple ESP32 nodes.
    This is NON-BLOCKING. It returns after sending the requests.
    """
    async def _proxy(ip):
        url = f"{request.protocol}://{ip}:{request.port}{request.path}"
        try:
            async with httpx.AsyncClient(verify=False) as client:
                if request.method.upper() == "GET": response = await client.get(url)
                else: response = await client.post(url, json=request.payload)
                response.raise_for_status()
                return ip, {"status": "success", "http_status_code": response.status_code}
        except Exception as e:
            return ip, {"status": "failure", "detail": str(e)}
    tasks = [_proxy(ip) for ip in request.ips]
    results = await asyncio.gather(*tasks)
    return JSONResponse(content={"status": "completed", "results": {ip: res for ip, res in results}})


@app.post("/nodes/send_command")
async def send_node_command(request: SendCommandRequest):
    """
    API endpoint to proxy a specific command to a single ESP32 node.
    Returns the full response from the target node.
    """
    timeout = httpx.Timeout(95.0, connect=10.0)
    url = f"{request.protocol}://{request.ip}:{request.port}{request.path}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:        
            if request.method.upper() == "GET":
                response = await client.get(url)
            else:
                response = await client.post(url, json=request.payload)
            
            response.raise_for_status()
            response_body = response.json()
            result = {"status": "success", "http_status_code": response.status_code, "response_body": response_body}
    except Exception as e:
        result = {"status": "failure", "detail": str(e)}
        
    return JSONResponse(content={"status": "completed", "ip": request.ip, "result": result})


if __name__ == "__main__":
    logger.info("Starting FastAPI Server with Dedicated Hardware Controller on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_config=None)