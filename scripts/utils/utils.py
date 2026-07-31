import subprocess
from rich import print
import json
import shutil
import os

RASPBERRY_USER = "raspberrypi5"
RASPBERRY_IP = "iotlabvr.ddns.net"
BUILD_DIR = "build"
RASPBERRY_DIR = "/home/raspberrypi5/firmware"
TMP_FOLDER = "tmp_firmware"

def copy_firmware_to_raspberry():
    """Copy firmware to Raspberry Pi using SCP."""
    try:            
        build_dir_abs = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), BUILD_DIR)
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
        
        destination = f"{RASPBERRY_USER}@{RASPBERRY_IP}:{RASPBERRY_DIR}/"
        subprocess.run(["zip", "-r", f"{TMP_FOLDER}.zip", TMP_FOLDER])
        subprocess.run(["scp", "-r", f"{TMP_FOLDER}.zip", destination])
        print(f"Firmware copied to Raspberry Pi at {destination}")
    finally:
        if os.path.exists(TMP_FOLDER):
            shutil.rmtree(TMP_FOLDER)
        
        if os.path.exists(f"{TMP_FOLDER}.zip"):
            os.remove(f"{TMP_FOLDER}.zip")