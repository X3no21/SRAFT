import subprocess
import requests
import argparse
from rich import print
import os
import sys

scripts_path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
if scripts_path not in sys.path:
    sys.path.insert(0, scripts_path)

from utils.utils import copy_firmware_to_raspberry

RASPBERRY_USER = "pi"
RASPBERRY_PI_IP  = "raspberrypi.local"
DEPLOY_SERVER_URL = f"http://{RASPBERRY_PI_IP}:8000"
BUILD_DIR = "build"
RASPBERRY_DIR = "/home/pi/firmware"
TMP_FOLDER = "tmp_firmware"

def build_firmware():
    """Build firmware using ESP-IDF."""
    subprocess.run(["idf.py", "build"], check=True)


def trigger_deployment(offset: int, count: int):
    """Makes a POST request to deploy firmware to a slice of devices."""
    url = f"{DEPLOY_SERVER_URL}/deploy"
    payload = {"offset": offset, "count": count}
    print(f"Triggering deployment with offset={offset}, count={count}...")
    try:
        response = requests.post(url, json=payload)
        print("Deployment triggered. Server response:")
        print(response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error triggering deployment: {e}")
    
    
def reset_firmwares(offset: int, count: int):
    """Reset firmwares by calling REST API on Raspberry."""
    url = f"{DEPLOY_SERVER_URL}/reset"
    payload = {"offset": offset, "count": count}
    print(f"Triggering reset with offset={offset}, count={count}...")
    try:
        response = requests.post(url, json=payload)
        print("Reset triggered. Server response:")
        print(response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error triggering reset: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--build", action='store_true')
    parser.add_argument("-r", "--reset", action='store_true')
    args = parser.parse_args()
    
    if args.build:
        build_firmware()
    
    if not args.reset:
        copy_firmware_to_raspberry()
        trigger_deployment(offset=0, count=5)
    else:
        reset_firmwares(offset=0, count=5)
