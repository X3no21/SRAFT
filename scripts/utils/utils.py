import subprocess
from rich import print
import json
import shutil
import os

RASPBERRY_USER = "pi"
RASPBERRY_IP = "raspberrypi.local"
# Build folder of the firmware to deploy: "build" (debug profile) or "build_release" (release profile).
BUILD_DIR = os.environ.get("SRAFT_BUILD_DIR", "build")
# Build folder of the tampered test image (failed-attestation scenario), same profile as BUILD_DIR.
TAMPERED_BUILD_DIR = os.environ.get("SRAFT_TAMPERED_BUILD_DIR", BUILD_DIR + "_tampered")
RASPBERRY_DIR = "/home/pi/firmware"
TMP_FOLDER = "tmp_firmware"

def copy_firmware_to_raspberry(build_dir: str = None):
    """Copy firmware to Raspberry Pi using SCP (build_dir defaults to BUILD_DIR)."""
    try:            
        build_dir_abs = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), build_dir or BUILD_DIR)
        with open(os.path.join(build_dir_abs, "flasher_args.json"), "r") as f:
            flasher_args = json.load(f)
            
        if os.path.exists(TMP_FOLDER):
            shutil.rmtree(TMP_FOLDER)
        os.makedirs(TMP_FOLDER, exist_ok=True)
        
        bootloader_path = TMP_FOLDER
        for subfolder in flasher_args["bootloader"]["file"].split("/")[:-1]:
            bootloader_path = os.path.join(bootloader_path, subfolder)
        os.makedirs(bootloader_path, exist_ok=True)
        
        partition_table_path = TMP_FOLDER
        for subfolder in flasher_args["partition-table"]["file"].split("/")[:-1]:
            partition_table_path = os.path.join(partition_table_path, subfolder)
        os.makedirs(partition_table_path, exist_ok=True)
        
        app_path = TMP_FOLDER
        for subfolder in flasher_args["app"]["file"].split("/")[:-1]:
            app_path = os.path.join(app_path, subfolder)
        os.makedirs(app_path, exist_ok=True)
        
        shutil.copy2(os.path.join(build_dir_abs, "flasher_args.json"), TMP_FOLDER)
        shutil.copy2(os.path.join(build_dir_abs, "bootloader", flasher_args["bootloader"]["file"].split("/")[-1]), bootloader_path)
        shutil.copy2(os.path.join(build_dir_abs, "partition_table", flasher_args["partition-table"]["file"].split("/")[-1]), partition_table_path)
        shutil.copy2(os.path.join(build_dir_abs, flasher_args["app"]["file"]), app_path)
        
        subprocess.run(["zip", "-r", f"{TMP_FOLDER}.zip", TMP_FOLDER])
        if os.environ.get("SRAFT_LOCAL_DEPLOY"):
            # The orchestrator runs on the server itself: the firmware is copied locally.
            destination = f"{RASPBERRY_DIR}/"
            os.makedirs(RASPBERRY_DIR, exist_ok=True)
            shutil.copy2(f"{TMP_FOLDER}.zip", destination)
        else:
            destination = f"{RASPBERRY_USER}@{RASPBERRY_IP}:{RASPBERRY_DIR}/"
            subprocess.run(["scp", "-r", f"{TMP_FOLDER}.zip", destination])
        print(f"Firmware copied to Raspberry Pi at {destination}")
    finally:
        if os.path.exists(TMP_FOLDER):
            shutil.rmtree(TMP_FOLDER)
        
        if os.path.exists(f"{TMP_FOLDER}.zip"):
            os.remove(f"{TMP_FOLDER}.zip")