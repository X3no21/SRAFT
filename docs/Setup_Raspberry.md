# Setup Raspberry Pi 

This document describes how to set up a Raspberry Pi to be used as a proxy server and access point for a set of ESP32 devices. In this project, the Raspberry Pi is used as the main hub to power the ESP32 devices and to deliver the firmware file to all of them. The Raspberry can also be used to monitor the execution status of each ESP32 devices and to query them asking thm runtime information.

## Setup Raspberry Pi as Access Point
## Setup External Wireless dongle

### 1. Install packets

```bash
sudo apt install build-essential dkms git linux-headers-$(uname -r)
```

### 2. Download the driver

```bash
git clone https://github.com/morrownr/88x2bu-20210702.git
cd 88x2bu-20210702
```

### 3. Compile and install the driver

```bash
sudo ./install-driver.sh
```

### 4. Load the driver

```bash
sudo modprobe 88x2bu
```

### 5. Check if the driver is loaded

```bash
sudo dkms status
```

### 6. Install NTP Server

```bash
sudo apt install chrony
```

### 7. Configure NTP Server
Edit the configuration file `/etc/chrony/chrony.conf` and add the following line at the top of the file:

```
allow 192.168.1.0/24
```

Then restart the chrony service:

```bash
sudo systemctl restart chrony
```