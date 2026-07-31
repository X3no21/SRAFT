# DistributedAuthenticationPUF

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21724794.svg)](https://doi.org/10.5281/zenodo.21724794)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)


Research project on distributed authentication for a cluster of **ESP32** nodes, based on a **SRAM-PUF** (Physical Unclonable Function). The firmware implements a Raft-style consensus protocol (node join / remove / self-healing) together with a device integrity verification protocol (**HAtt**) and **SRAFT**, a PUF-based authentication protocol that is the main contribution of this work.

For the experimental evaluation in the paper, two additional authentication schemes are implemented purely as **baseline comparisons against SRAFT**: mutual TLS (mTLS) and MQTTS (mTLS over an MQTT broker). They are not core to the system, they only exist so the paper can show SRAFT performing better.

## System overview

The project spans three machines:

```
                existing WiFi network (router / AP already in place)
      ┌───────────────────────────────────────────────────────────┐
      │                                                             │
 ESP32 nodes (N)                                     Raspberry Pi (static IP)
 main/ firmware  ───────── REST API :80 / :443 ─────────►  deploy server, monitor, DB
      │                                                             │
      └──────────────── USB (flashing + raw serial/debug log) ─────┘

 Local dev machine ── SSH/SCP + HTTP (iotlabvr.ddns.net) ──►  Raspberry Pi
   (build firmware, orchestrate deploy & test campaigns, generate plots)
```

- **ESP32 nodes**: run the firmware in [main/](main/). They join the same WiFi network as the Raspberry Pi and talk to it over REST API for authentication/telemetry, and are physically wired to it over USB for flashing.
- **Raspberry Pi**: a regular client on the WiFi network (it does **not** act as an access point), configured with a static/reserved IP. Its job is purely operational: flash firmware onto the ESP32 nodes over USB, capture their raw serial/debug output, and collect execution logs and test metrics (join/remove/election/auth events, CPU/memory/power stats) into PostgreSQL for later reporting.
- **Local dev machine**: where the firmware is built (ESP-IDF) and where deploy/test orchestration scripts are launched, reaching the Raspberry Pi over the network.

## Repository layout

```
main/                     ESP-IDF firmware (C)
  auth/                   SRAFT (PUF-based) auth + join/remove; TLS and MQTTS baselines
  device_integrity_verification/  HAtt protocol
  raft/                   Raft consensus
  rest_api/               Node REST API (ports 80/443)
  esp32_config/           WiFi + peer discovery
  certs/                  ca.crt / device.crt / device.key (embedded in the firmware)
scripts/
  client/                 Scripts run from the local dev machine (build/deploy/sync)
  server/                 Scripts run on the Raspberry Pi (deploy server, monitor, DB)
  mqtts/, tls/            MQTTS broker setup and certificate generation (TLS/MQTTS baselines only)
  tests/                  Experiment orchestration + plot generation
docs/Setup_Raspberry.md   NTP (chrony) setup notes for the Raspberry Pi
experimental_results/     Test campaign output, per cluster size
```

## 1. Network addresses and constants to adapt

Some values are hardcoded both in the firmware and in the scripts. If your Raspberry Pi / network differ from the project defaults, update these **before building the firmware** (they get compiled into the binary).

> **Credentials and key material are not shipped.** This repository is publicly archived, so WiFi credentials, database passwords and TLS keys are placeholders. The entries marked ⚠️ below **must** be set to real values before anything will run, and `main/certs/` must be regenerated (see section 1.1).

| File | Constant | Default | Meaning |
|---|---|---|---|
| ⚠️ `main/esp32_config/wifi.h` | `WIFI_SSID`, `WIFI_PASS` | `YOUR_WIFI_SSID` / `YOUR_WIFI_PASSWORD` | WiFi network that both the ESP32 nodes and the Raspberry Pi join |
| `main/utils/utility.h` | `MONITORING_SERVER_IP`, `MONITORING_PORT` | `192.168.1.125` / `9001` | Static IP of the Raspberry Pi on that WiFi network (execution log/heartbeat TCP endpoint) |
| `main/rest_api/rest_api.h` | `MQTT_BROKER_IP`, `MQTT_BROKER_PORT` | `192.168.1.125` / `8883` | IP of the MQTTS broker (same Raspberry Pi) — only relevant for the MQTTS baseline |
| `scripts/client/client_deploy.py`, `scripts/tests/experimental_campaign.py`, `scripts/utils/utils.py` | `RASPBERRY_USER`, `RASPBERRY_PI_IP` | `raspberrypi5` / `iotlabvr.ddns.net` | Host/user the local dev machine uses for SSH/SCP and to reach the deploy server (`:8000`) and monitor API (`:9002`) |
| `scripts/server/server_deploy.py` | `FIRMWARE_DIR` | `/home/raspberrypi5/firmware` | Directory on the Raspberry Pi where firmware is uploaded before flashing |
| `scripts/client/sync_raspberry.sh` | `SOURCE_DIR`, `DESTINATION` | local checkout path / `raspberrypi5@iotlabvr.ddns.net:...` | Local/remote paths for the live sync loop |

Note: `RASPBERRY_PI_IP` (the DDNS hostname) is the address the *local dev machine* uses to reach the Raspberry Pi's deploy/monitor services, while `MONITORING_SERVER_IP`/`MQTT_BROKER_IP` (`192.168.1.125`) is the Pi's *internal* static IP on the WiFi network shared with the ESP32 nodes — they can be two different addresses of the same Raspberry Pi (e.g. a LAN IP vs. a DDNS name resolving through port forwarding).

Database credentials are read from the environment, with no usable default:

| Variable | Used by | Meaning |
|---|---|---|
| ⚠️ `POSTGRES_PASSWORD` | `scripts/server/start_postgres.sh` | Password for the PostgreSQL logging database. The script aborts if it is unset. |
| `POSTGRES_USER` | `scripts/server/start_postgres.sh` | Database user (default `raft`) |
| ⚠️ `DATABASE_URL` | `scripts/server/monitoring_server.py` | Full connection string, e.g. `postgresql://raft:<password>@localhost/logger_db`. Must match the credentials the container was started with. |

### 1.1 TLS/MQTTS baseline certificates

`main/certs/{ca.crt,device.crt,device.key}` ship as **placeholders** — no real key material is distributed. These three files are embedded into the firmware binary at build time (`EMBED_TXTFILES` in [main/CMakeLists.txt](main/CMakeLists.txt)) and are also installed on the MQTTS broker by [scripts/mqtts/setup_mqtts_broker.sh](scripts/mqtts/setup_mqtts_broker.sh), so they must be generated before the first build:

```bash
./scripts/tls/generate_certs.sh
```

That single command creates a test CA and writes exactly the three files the build expects, in place:

| File | Content |
|---|---|
| `main/certs/ca.crt` | Test CA certificate |
| `main/certs/device.crt` | Device/broker certificate signed by that CA (`CN=192.168.1.125`, with a matching `subjectAltName`) |
| `main/certs/device.key` | Matching 2048-bit RSA private key |

The CA private key stays in `scripts/tls/ca/` and is never copied into the firmware tree. Re-running the script reuses an existing CA, so certificates issued for nodes already flashed stay valid.

Useful overrides:

```bash
CN=my-broker.local ./scripts/tls/generate_certs.sh   # different subject (hostname or IP)
LEAF_DAYS=90 ./scripts/tls/generate_certs.sh         # shorter validity
./scripts/tls/generate_certs.sh --per-node           # also one cert per host in the subnet
```

`--per-node` populates `scripts/tls/certs/node_<IP>/` and is only useful if you re-enable hostname verification. By default the firmware sets `skip_common_name` ([main/auth/tls_auth.c](main/auth/tls_auth.c)) and `skip_cert_common_name_check` ([main/auth/mqtts_auth.c](main/auth/mqtts_auth.c)), so a single certificate shared by every node and by the broker is sufficient — only the chain to the CA is validated.

These certificates are used exclusively by the mTLS and MQTTS **baselines**; the SRAFT protocol itself does not depend on them.

> ⚠️ Everything generated under `scripts/tls/` is gitignored, but the three files in `main/certs/` stay **tracked** — the build fails if they are missing. After running the script they hold real key material: check `git status` and restore the placeholders before committing.

## 2. Prerequisites — local dev machine (build firmware + orchestrate tests)

1. **ESP-IDF v6.0.2** (or newer 6.0.x), target `esp32`:
   ```bash
   git clone -b v6.0.2 --recursive https://github.com/espressif/esp-idf.git ~/esp/esp-idf-v6.0.2
   cd ~/esp/esp-idf-v6.0.2 && ./install.sh esp32
   source ~/esp/esp-idf-v6.0.2/export.sh
   ```
   A Dev Container is also available ([.devcontainer/Dockerfile](.devcontainer/Dockerfile), based on the `espressif/idf` image) usable with VS Code Dev Containers (see also [VS_CODE_ESP_IDF_SETUP.md](VS_CODE_ESP_IDF_SETUP.md)).

   > **Note — ESP-IDF version note (2026-07):** this project previously targeted ESP-IDF v5.4.1; the build has been migrated to v6.0.x. ESP-IDF v6.0 removed the built-in `json` and `mqtt` components (now fetched via the IDF Component Manager, declared in [main/idf_component.yml](main/idf_component.yml)) and replaced most legacy `mbedtls_*` crypto calls with the PSA Crypto API (`psa/crypto.h`) — the SHA-256/HMAC-SHA256/AES-CBC helpers in `hatt_protocol.c` and `utility.c` were updated accordingly. If you still need to build against v5.4.1, you'd have to revert these two changes (re-add `json`/`mqtt` to `main/CMakeLists.txt` `REQUIRES` and drop `main/idf_component.yml`, restore the `mbedtls_sha256_*`/`mbedtls_md_hmac_*`/`mbedtls_aes_*` calls) — this is not tested/supported going forward.
2. **Python 3** with the packages used by the local scripts:
   ```bash
   python3 -m venv venv && source venv/bin/activate
   pip install -r scripts/client/requirements.txt
   pip install -r scripts/tests/requirements.txt
   ```
3. **System utilities**: `zip` (used to package the firmware before sending it to the Pi), `ssh`/`scp` (a passphrase-less key for `raspberrypi5@iotlabvr.ddns.net` is recommended), and optionally `inotify-tools` + `rsync` if you use `sync_raspberry.sh`.

## 3. Prerequisites and startup — Raspberry Pi (connected to the ESP32 nodes)

### 3.1 Network and clock

Join the Raspberry Pi to the same WiFi network as the ESP32 nodes (as a normal client) and give it a static or DHCP-reserved IP matching `MONITORING_SERVER_IP`/`MQTT_BROKER_IP` (section 1). [docs/Setup_Raspberry.md](docs/Setup_Raspberry.md) also contains legacy instructions for turning the Pi into a WiFi access point with an external dongle — that part is **not** part of the current setup; only its NTP (`chrony`) section is still relevant, to keep timestamps in the logs consistent across nodes.

### 3.2 PostgreSQL (Docker)

```bash
cd scripts/server/db
docker build -t postgres-monitoring .
cd ..
./start_postgres.sh            # fresh, empty DB (volume pg_data_fresh)
# or restore from a backup saved under scripts/server/db_backups/:
./start_postgres.sh <backup_file_name>
```

To stop and clean up the container (**this also deletes the `pg_data_fresh` volume**, so unsaved data is lost):
```bash
./stop_postgres.sh
```

You also need the `pg_dump` client installed on the host (`postgresql-client` package, version compatible with Postgres 15): `monitoring_server.py` uses it to take an automatic dump on shutdown (Ctrl+C).

### 3.3 Python environment

```bash
cd scripts/server
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 3.4 Deploy server — flashing + serial/debug log capture (port 8000)

Connect all the ESP32 boards to the Raspberry Pi over USB (they show up as `/dev/ttyUSB0..N`; the user running the script needs access to the serial ports, e.g. via the `dialout` group). Then:

```bash
python3 scripts/server/server_deploy.py
```

This exposes a FastAPI service on `:8000` (`/deploy`, `/reset`, `/nodes/send_command`, `/nodes/broadcast_command`) used by the local dev machine to flash/reset nodes and to proxy calls to each ESP32's REST API. It also continuously captures the raw serial output (classic `ESP_LOGx` debug logs) of every connected device into `scripts/server/logs/<device>.log`, restarting the capture automatically around each deploy/reset. `/home/raspberrypi5/firmware` (must match `FIRMWARE_DIR`/`RASPBERRY_DIR` used by the local scripts) is created automatically.

### 3.5 Monitoring server — execution logs and test metrics (ports 9001/9002)

Requires PostgreSQL to already be running (3.2):

```bash
python3 scripts/server/monitoring_server.py
```

Starts a raw TCP listener on `:9001` (structured events/heartbeats sent by the ESP32 nodes: join/remove/election/heal/auth events, etc.) and a FastAPI service on `:9002` (`/query/online_nodes`, `/query/latest_leader`, `/campaign/export_one/{id}`, `/campaign/export_final_analysis`, ...) used by the test-orchestration scripts to know which nodes are online, who the current leader is, and to download Excel reports/metrics at the end of a campaign.

### 3.6 Optional — MQTTS broker (port 8883, mTLS baseline only)

Only needed if you want to reproduce the TLS/MQTTS baseline comparisons from the paper (SRAFT itself does not need it). The certificates used by the firmware (shared by all nodes) are already committed in [main/certs/](main/certs/) (`ca.crt`, `device.crt`, `device.key`). On the Raspberry Pi:

```bash
sudo scripts/mqtts/setup_mqtts_broker.sh -r   # first-time install: installs mosquitto, copies the certs, configures mTLS
sudo scripts/mqtts/setup_mqtts_broker.sh      # subsequent restarts (no -r)
```

If you regenerate certificates with [scripts/tls/generate_certs.sh](scripts/tls/generate_certs.sh), replace the files under `main/certs/`, **rebuild and reflash the firmware** (the certs are embedded in the binary, see `EMBED_TXTFILES` in [main/CMakeLists.txt](main/CMakeLists.txt)), and rerun `setup_mqtts_broker.sh -r` on the broker.

## 4. Build, deploy and test from the local dev machine

Make sure PostgreSQL, `monitoring_server.py` and `server_deploy.py` are already running on the Raspberry Pi (section 3).

### 4.1 Build the firmware

```bash
source ~/esp/esp-idf-v6.0.2/export.sh
idf.py set-target esp32   # first time only
idf.py build
```

### 4.2 Quick deploy (5 nodes by default)

```bash
python scripts/client/client_deploy.py -b     # build + SCP copy + flash the first 5 nodes (offset 0)
python scripts/client/client_deploy.py        # copy + deploy only (no rebuild)
python scripts/client/client_deploy.py -r     # reset/erase-flash the first 5 nodes
```

### 4.3 Live sync to the Pi (for developing the server-side scripts)

```bash
bash scripts/client/sync_raspberry.sh
```
Watches local changes (`inotifywait`) and syncs them to the Raspberry Pi via `rsync` (excluding `build/`, `.git/`, `venv/`). Update `SOURCE_DIR`/`DESTINATION` in the script if your local checkout or the remote host differ from the defaults.

### 4.4 Automated test campaigns

⚠️ These scripts do **not** build the firmware: run `idf.py build` (4.1) before launching them.

```bash
cd scripts/tests
pip install -r requirements.txt   # if not already installed

# Single run with N nodes (default 5): reset, deploy, bootstrap the cluster,
# run SRAFT/TLS/MQTTS auth checks, node removal, then generate a report
python experimental_campaign.py -n 5

# Full campaign: cluster sizes from 3 to 32 nodes (step 2), 10 iterations each (default),
# plus a final integrity-failure test at 32 nodes and an aggregated final report
python experimental_campaign.py --full-experiment -i 10
```

Per-campaign reports (`.xlsx`) are saved under `experiment_results/<campaign_id>/`; the aggregated final report is saved in the root of `experiment_results/`.

### 4.5 Generate plots

```bash
cd scripts/tests
python generate_plots.py
```
Reads the aggregated results from `experimental_results/` (see the data already present under `experimental_results/{sraft,tls,mqtts}/size_*`) and writes plots to `experimental_results/plots/`.

## 5. Quick reference — ports and services

| Service | Host | Port | Notes |
|---|---|---|---|
| Deploy server (`server_deploy.py`) | Raspberry Pi | 8000/TCP (HTTP) | Flash/reset ESP32 nodes, proxy to each node's REST API |
| Monitor — log/heartbeat ingest | Raspberry Pi | 9001/TCP (raw socket) | Structured execution events sent by the ESP32 nodes |
| Monitor — query/report API | Raspberry Pi | 9002/TCP (HTTP) | Cluster state queries, report generation |
| PostgreSQL | Raspberry Pi (Docker) | 5432/TCP | Execution logs/metrics DB (`logger_db`, user `raft`) |
| MQTTS broker (Mosquitto) | Raspberry Pi | 8883/TCP (mTLS) | Used only by the MQTTS baseline comparison scheme |
| Node REST API | ESP32 | 80/TCP (HTTP), 443/TCP (HTTPS/mTLS) | See the endpoint table below |

Raw serial/debug logs (`ESP_LOGx`) are captured directly over USB by `server_deploy.py`, not over the network — see section 3.4.

## 6. Quick reference — ESP32 node REST endpoints (port 80)

| Endpoint | Method | Purpose |
|---|---|---|
| `/raft/state` | GET | Current Raft state of the node |
| `/system/stats` | GET | CPU/memory/power statistics |
| `/system/stats/start_phase` | POST | Start statistics sampling for a phase |
| `/start` | POST | Start the node in `normal` / `join` / `bootstrap` mode |
| `/join` | POST | Request to join the cluster |
| `/request_authentication` | POST | **SRAFT** (PUF-based) authentication |
| `/request_auth_from_verifier` | POST | SRAFT authentication, verifier side |
| `/request_authentication_tls` | POST | mTLS authentication (baseline comparison) |
| `/request_authentication_mqtts` | POST | MQTTS authentication (baseline comparison) |
| `/remove_node` | POST | Request removal of a node from the cluster |
| `/cluster/heal` | POST | Trigger cluster self-healing |
| `/reboot` | POST | Reboot the node |
| `/test/tamper_secret` | POST | Corrupt the PUF secret (for integrity-failure tests) |

## 7. Troubleshooting

- **Deploy fails / no devices found**: check that the ESP32 boards show up as `/dev/ttyUSB*` on the Raspberry Pi and that the user running `server_deploy.py` has permission to access them (e.g. `dialout` group).
- **`monitoring_server.py` exits immediately**: almost always means PostgreSQL isn't reachable on `localhost:5432` (start it first, section 3.2).
- **ESP32 nodes never show up online**: check that `WIFI_SSID`/`WIFI_PASS` in the firmware match the network the Raspberry Pi is on, and that `MONITORING_SERVER_IP` matches the Pi's static IP on that network (section 1), then rebuild and reflash.
- **MQTTS authentication fails**: check that the broker is running (`systemctl status mosquitto` on the Pi) and that the certificates in `/etc/mosquitto/certs` match the ones embedded in the firmware (`main/certs/`).
- **TLS handshake always fails**: `main/certs/` still contains the shipped placeholders. Generate real certificates (section 1.1) and rebuild.
- **`start_postgres.sh` aborts immediately**: `POSTGRES_PASSWORD` is not exported in your shell (section 1).

## 8. License

Released under the MIT License — see [LICENSE](LICENSE).

## 9. Citing this work

Each tagged release of this repository is archived on Zenodo with its own DOI. If you use the code or the experimental data, please cite the archived release:

```bibtex
@misc{sraft_artifact,
  author       = {Pagano, Francesco and Ceccato, Mariano},
  title        = {{SRAFT}: Lightweight Distributed Device Authentication and
                  Software Attestation for {IoT} Devices Based on Physical
                  Unclonable Functions},
  howpublished = {Zenodo},
  version      = {v1.0.0},
  year         = {2026},
  doi          = {10.5281/zenodo.21724795},
  url          = {https://doi.org/10.5281/zenodo.21724795}
}
```

Zenodo mints two DOIs for this artifact:

| DOI | Resolves to | Use it for |
|---|---|---|
| [10.5281/zenodo.21724794](https://doi.org/10.5281/zenodo.21724794) | Always the latest release (concept DOI) | Linking to the project in general — this is the badge above |
| [10.5281/zenodo.21724795](https://doi.org/10.5281/zenodo.21724795) | `v1.0.0` specifically (version DOI) | Citing in a paper, where reproducibility requires a frozen snapshot |

GitHub also renders a ready-made citation from [CITATION.cff](CITATION.cff) via the *Cite this repository* button.
