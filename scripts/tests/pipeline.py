"""
Test pipeline for the SRAFT test bench.

It drives the whole cycle from the local machine:

    python pipeline.py sync                  copy scripts/ to the server
    python pipeline.py services <action>     up | down | restart | status | rotate-logs | reset-db  [db|monitor|deploy|all]
    python pipeline.py build [--clean] [--profile debug|release] [--tampered]
    python pipeline.py run -n 5 [--profile debug|release] [--sraft-only] [--integrity-test] [--detection-test [--runs N]]
                                [--attestation-test [-i N]]
                                             sync, restart the services, run experimental_campaign.py, fetch and analyze the logs

The tampered test images are not compiled: they are copies of the reference image in which part of the
attestation test region is overwritten with random bytes (make_tampered_image.py). The failed-attestation
scenario uses 4 KB; the detection test uses 1, 4, 64 bytes and 4 KB and compares the measured detection
rate with the one predicted from the HAtt parameters.

Two firmware profiles are available. "debug" (default, folder build/) keeps the serial logs and the
heap/stack diagnostics used to analyze test runs. "release" (folder build_release/) compiles the logs
out, for the measurements; the protocol events still reach the monitoring server over the network.
    python pipeline.py fetch <dest>          download the serial logs of the devices and the output of the services
    python pipeline.py analyze <dir>         summarize the serial logs found under <dir>

The serial logs are the ones captured by server_deploy.py, one file per device.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.dirname(TESTS_DIR)
PROJECT_DIR = os.path.dirname(SCRIPTS_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from utils.utils import RASPBERRY_USER, RASPBERRY_IP  # noqa: E402
import make_tampered_image  # noqa: E402

# Bytes of the test region overwritten in the images of the detection test, and in the tampered
# device of the failed-attestation scenario.
DETECTION_SIZES = [1, 4, 64, 4096]
INTEGRITY_TAMPER_SIZE = 4096
DEFAULT_DETECTION_RUNS = 200
DETECTION_BATCH = 20

REMOTE = f"{RASPBERRY_USER}@{RASPBERRY_IP}"
REMOTE_PROJECT = f"/home/{RASPBERRY_USER}/Documents/git/SRAFT"
REMOTE_SERVER_DIR = f"{REMOTE_PROJECT}/scripts/server"
IDF_ACTIVATE = os.path.expanduser("~/.espressif/tools/activate_idf_v6.0.2.sh")
RESULTS_DIR = os.path.join(TESTS_DIR, "experiment_results")
BUILD_DIRS = {"debug": "build", "release": "build_release"}
DEFAULT_RUN_TIMEOUT_S = 3600


# --------------------------------------------------------------------------- helpers

def ssh_env() -> dict:
    """Environment with the SSH agent started by keychain, so that no passphrase is asked."""
    env = dict(os.environ)
    if not env.get("SSH_AUTH_SOCK"):
        for path in glob.glob(os.path.expanduser("~/.keychain/*-sh")):
            with open(path) as f:
                for key, value in re.findall(r"(SSH_AUTH_SOCK|SSH_AGENT_PID)=([^;]+);", f.read()):
                    env[key] = value
    return env


def run(cmd, check=True, **kwargs):
    print(f"$ {cmd if isinstance(cmd, str) else ' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, check=check, env=ssh_env(), **kwargs)


def ssh(command: str, check=True, capture=False):
    return run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", REMOTE, command],
               check=check, capture_output=capture, text=True)


# --------------------------------------------------------------------------- steps

def cmd_sync(_args=None):
    """Copies the scripts to the server (virtual environments, logs and results excluded)."""
    run(["rsync", "-az",
         "--exclude", "venv/", "--exclude", "__pycache__/", "--exclude", "logs/", "--exclude", "run/",
         "--exclude", "db_backups/", "--exclude", "experiment_results/", "--exclude", "experimental_results/",
         f"{SCRIPTS_DIR}/", f"{REMOTE}:{REMOTE_PROJECT}/scripts/"])


def cmd_services(args):
    ssh(f"cd {REMOTE_SERVER_DIR} && ./services.sh {args.action} {args.target}", check=False)


def build_dir_name(profile: str, tampered: bool = False) -> str:
    return BUILD_DIRS[profile] + ("_tampered" if tampered else "")


def make_tampered(profile: str, size: int, out_name: str) -> dict:
    """Writes in out_name the build of profile with size bytes of the test region tampered."""
    info = make_tampered_image.make_tampered_build(os.path.join(PROJECT_DIR, BUILD_DIRS[profile]),
                                                   os.path.join(PROJECT_DIR, out_name), size)
    print(f"Tampered image {out_name}: {size} bytes, {info['changed_words']} words and {info['changed_bits']} bits "
          f"changed, predicted detection {info['predicted_detection']:.4f}")
    return info


def cmd_build(args):
    profile = getattr(args, "profile", "debug")
    tampered = getattr(args, "tampered", False)
    build_name = BUILD_DIRS[profile]
    build_dir = os.path.join(PROJECT_DIR, build_name)
    cache = os.path.join(build_dir, "CMakeCache.txt")
    stale = False
    if os.path.exists(cache):
        with open(cache, errors="ignore") as f:
            m = re.search(r"CMAKE_HOME_DIRECTORY:INTERNAL=(.*)", f.read())
        stale = bool(m) and os.path.realpath(m.group(1).strip()) != os.path.realpath(PROJECT_DIR)
    if getattr(args, "clean", False) or stale:
        print(f"Removing {'stale ' if stale else ''}build directory {build_dir}")
        subprocess.run(["rm", "-rf", build_dir], check=True)

    if profile == "debug":
        idf_cmd = f"idf.py -B {build_name} build"
    else:
        # The release configuration is regenerated from the project sdkconfig at every build, so that
        # it differs from the debug one only in the settings of sdkconfig.release.defaults.
        for name in ("sdkconfig.release", "sdkconfig.release.old"):
            path = os.path.join(PROJECT_DIR, name)
            if os.path.exists(path):
                os.remove(path)
        idf_cmd = (f"idf.py -B {build_name} -D SDKCONFIG=sdkconfig.release "
                   f"-D 'SDKCONFIG_DEFAULTS=sdkconfig;sdkconfig.release.defaults' build")
    run(["bash", "-c", f". '{IDF_ACTIVATE}' >/dev/null && cd '{PROJECT_DIR}' && {idf_cmd}"])
    if tampered:
        make_tampered(profile, INTEGRITY_TAMPER_SIZE, build_dir_name(profile, tampered=True))


def cmd_fetch(args):
    dest = os.path.abspath(args.dest)
    serial_dir = os.path.join(dest, "serial_logs")
    server_dir = os.path.join(dest, "server_output")
    os.makedirs(serial_dir, exist_ok=True)
    os.makedirs(server_dir, exist_ok=True)
    run(["rsync", "-az", f"{REMOTE}:{REMOTE_SERVER_DIR}/logs/*.log", f"{serial_dir}/"], check=False)
    run(["rsync", "-az", f"{REMOTE}:{REMOTE_SERVER_DIR}/run/*.out", f"{server_dir}/"], check=False)
    print(f"Logs saved under {dest}")
    return dest


def cmd_run(args):
    tag = args.tag or datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(RESULTS_DIR, f"pipeline_{args.nodes}_nodes_{tag}")
    campaign_env = ssh_env()
    campaign_env["SRAFT_BUILD_DIR"] = build_dir_name(args.profile)
    campaign_env["SRAFT_TAMPERED_BUILD_DIR"] = build_dir_name(args.profile, tampered=True)
    os.makedirs(run_dir, exist_ok=True)

    if args.build:
        cmd_build(argparse.Namespace(clean=False, profile=args.profile, tampered=False))
    if not os.path.exists(os.path.join(PROJECT_DIR, BUILD_DIRS[args.profile], "flasher_args.json")):
        sys.exit(f"Firmware build missing: run 'pipeline.py build --profile {args.profile}' first (or pass --build).")
    # The tampered images are always derived from the current reference build.
    if args.integrity_test:
        make_tampered(args.profile, INTEGRITY_TAMPER_SIZE, build_dir_name(args.profile, tampered=True))
    if args.detection_test:
        with open(os.path.join(PROJECT_DIR, BUILD_DIRS[args.profile], "raft_esp32.bin"), "rb") as f:
            reference_id = make_tampered_image.image_id(f.read())
        cases = []
        for size in (args.detection_sizes or DETECTION_SIZES):
            name = f"{BUILD_DIRS[args.profile]}_tamper{size}"
            info = make_tampered(args.profile, size, name)
            cases.append({"name": f"{size} tampered bytes", "size": size, "build_dir": name, "image_id": info["image_id"],
                          "changed_words": info["changed_words"], "changed_bits": info["changed_bits"],
                          "predicted": info["predicted_detection"]})
        cases_file = os.path.join(run_dir, "detection_cases.json")
        with open(cases_file, "w") as f:
            json.dump({"runs": args.runs, "batch": DETECTION_BATCH,
                       "reference": {"build_dir": BUILD_DIRS[args.profile], "image_id": reference_id},
                       "cases": cases}, f, indent=2)
        campaign_env["SRAFT_DETECTION_CASES"] = cases_file

    cmd_sync()
    # A fresh start of the services clears the state left by previous runs (pending waits, loggers).
    ssh(f"cd {REMOTE_SERVER_DIR} && ./services.sh down deploy && ./services.sh down monitor && "
        f"./services.sh rotate-logs && ./services.sh up all")

    campaign_log = os.path.join(run_dir, "campaign.log")
    cmd = [sys.executable, "-u", "experimental_campaign.py", "-n", str(args.nodes), "--tag", tag]
    if args.sraft_only:
        cmd.append("--sraft-only")
    if args.integrity_test:
        cmd.append("--integrity-test")
    if args.detection_test:
        cmd.append("--detection-test")
    if args.attestation_test:
        cmd += ["--attestation-test", "-i", str(args.iterations)]
    if args.loop:
        cmd += ["--loop", "-i", str(args.iterations)]
    if args.out:
        cmd += ["--out", os.path.abspath(args.out)]
    if args.fault:
        cmd += ["--fault", args.fault, "--fault-count", str(args.fault_count)]
        if args.fault_coordinator:
            cmd.append("--fault-coordinator")
    print(f"$ {' '.join(cmd)}  (timeout {args.timeout}s, output in {campaign_log})", flush=True)
    start = time.time()
    status = "completed"
    with open(campaign_log, "w") as log:
        proc = subprocess.Popen(cmd, cwd=TESTS_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=campaign_env)
        try:
            for line in proc.stdout:
                sys.stdout.write(line)
                log.write(line)
                if time.time() - start > args.timeout:
                    raise TimeoutError
            proc.wait()
            if proc.returncode != 0:
                status = f"exit code {proc.returncode}"
        except (TimeoutError, KeyboardInterrupt) as e:
            proc.kill()
            status = "timeout" if isinstance(e, TimeoutError) else "interrupted"
    elapsed = time.time() - start
    print(f"Campaign {status} after {elapsed:.0f}s")

    cmd_fetch(argparse.Namespace(dest=run_dir))
    summary = analyze_dir(run_dir, header=f"Run {tag}: {args.nodes} nodes, {args.profile} firmware, campaign {status} after {elapsed:.0f}s")
    print(summary)


def cmd_analyze(args):
    print(analyze_dir(os.path.abspath(args.dir)))


# --------------------------------------------------------------------------- log analysis

ANSI = re.compile(r"\x1b?\[[0-9;]*m")
LINE = re.compile(r"^([IWE]) \((\d+)\) ([^:]+): (.*)$")
PANIC_PATTERNS = {
    "panic": re.compile(r"Guru Meditation Error|abort\(\) was called|assert failed|CORRUPT HEAP|Stack canary|stack overflow", re.I),
    "watchdog": re.compile(r"Task watchdog got triggered|Interrupt wdt timeout", re.I),
}
BOOT = re.compile(r"rst:0x[0-9a-f]+ \(")
IP_LINE = re.compile(r"(?:sta ip|got ip)[: ]+(\d+\.\d+\.\d+\.\d+)", re.I)
HATT_VERIFIER = re.compile(r"HATT_STAT verifier prover=(\S+) result=(\S+) total_ms=(\d+)")
HATT_MEASURE = re.compile(r"HATT_STAT measure blocks=(\d+) wait_ms=(\d+) measure_ms=(\d+)")
IMAGE = re.compile(r"Attested memory: firmware image of (\d+) bytes")
SENT = re.compile(r"RPC SENT from \S+ to \S+: ([A-Za-z_]+)(.*)$")
STORAGE = re.compile(r"STORAGE: nvs used (\d+) of (\d+) entries, network state and shards (\d+) entries \((\d+) bytes\), members (\d+), crps (\d+), cnodes (\d+)")
EVENTS = {
    "elected_leader": re.compile(r"became LEADER|Became leader|I am the new leader|elected as leader", re.I),
    "vote_denied": re.compile(r"Vote DENIED", re.I),
    "integrity_failed": re.compile(r"Integrity check FAILED", re.I),
    "blacklisted": re.compile(r"added to the blacklist", re.I),
    "removal_confirmed": re.compile(r"Removal of \S+ confirmed", re.I),
    "removal_not_confirmed": re.compile(r"was not confirmed by its verifiers", re.I),
    "join_rejected": re.compile(r"Rejecting join|JOIN_FAILED", re.I),
    "auth_fail": re.compile(r"authentication (failed|FAILED)|Auth FAILED", re.I),
    "heal_unprotected": re.compile(r"HEAL_UNPROTECTED", re.I),
}


def normalize(msg: str) -> str:
    msg = re.sub(r"\d+\.\d+\.\d+\.\d+", "<ip>", msg)
    msg = re.sub(r"\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}\b", "<mac>", msg)
    msg = re.sub(r"0x[0-9a-fA-F]+", "<hex>", msg)
    return re.sub(r"\d+", "#", msg)[:140]


def analyze_file(path: str) -> dict:
    info = {"device": os.path.basename(path).replace(".log", ""), "ip": "?", "boots": 0, "lines": 0,
            "errors": Counter(), "warnings": 0, "panics": [], "events": Counter(),
            "attest": [], "measure": [], "image": None, "sent": Counter(), "sent_bytes": Counter(), "storage": None}
    with open(path, errors="ignore") as f:
        for raw in f:
            line = ANSI.sub("", raw).strip()
            if not line:
                continue
            info["lines"] += 1
            if BOOT.search(line):
                info["boots"] += 1
            m = IP_LINE.search(line)
            if m:
                info["ip"] = m.group(1)
            for kind, pattern in PANIC_PATTERNS.items():
                if pattern.search(line):
                    info["panics"].append(f"{kind}: {line[:160]}")
            for name, pattern in EVENTS.items():
                if pattern.search(line):
                    info["events"][name] += 1
            m = HATT_VERIFIER.search(line)
            if m:
                info["attest"].append((m.group(1), m.group(2), int(m.group(3))))
            m = HATT_MEASURE.search(line)
            if m:
                info["measure"].append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
            m = IMAGE.search(line)
            if m:
                info["image"] = int(m.group(1))
            m = SENT.search(line)
            if m:
                info["sent"][m.group(1)] += 1
                info["sent_bytes"][m.group(1)] += len(m.group(1)) + len(m.group(2))
            m = STORAGE.search(line)
            if m:
                info["storage"] = tuple(int(x) for x in m.groups())
            m = LINE.match(line)
            if m:
                level, _ts, tag, msg = m.groups()
                if level == "E":
                    info["errors"][f"{tag.strip()}: {normalize(msg)}"] += 1
                elif level == "W":
                    info["warnings"] += 1
    return info


def stats(values):
    if not values:
        return "-"
    values = sorted(values)
    mean = sum(values) / len(values)
    return f"n={len(values)} mean={mean:.0f} min={values[0]} max={values[-1]}"


def analyze_dir(directory: str, header: str = "") -> str:
    files = sorted(glob.glob(os.path.join(directory, "**", "ttyUSB*.log"), recursive=True))
    out = [f"# Log analysis{(' - ' + header) if header else ''}", ""]
    if not files:
        out.append(f"No serial logs found under {directory}")
        return "\n".join(out)

    infos = [analyze_file(p) for p in files]
    infos = [i for i in infos if i["lines"] > 0]
    out.append("| device | ip | boots | errors | warnings | panics | attestations (pass/fail/none) | measures |")
    out.append("|---|---|---|---|---|---|---|---|")
    for i in infos:
        res = Counter(r for _, r, _ in i["attest"])
        out.append(f"| {i['device']} | {i['ip']} | {i['boots']} | {sum(i['errors'].values())} | {i['warnings']} | "
                   f"{len(i['panics'])} | {res['PASSED']}/{res['FAILED']}/{res['NO_ANSWER']} | {len(i['measure'])} |")

    all_attest = [a for i in infos for a in i["attest"]]
    all_measure = [m for i in infos for m in i["measure"]]
    images = {i["image"] for i in infos if i["image"]}
    out += ["", "## Attestation (HAtt)", ""]
    out.append(f"- firmware image size(s): {sorted(images) if images else 'not logged'}")
    out.append(f"- verifier total time, PASSED [ms]: {stats([t for _, r, t in all_attest if r == 'PASSED'])}")
    out.append(f"- verifier total time, FAILED [ms]: {stats([t for _, r, t in all_attest if r == 'FAILED'])}")
    out.append(f"- verifier total time, NO_ANSWER [ms]: {stats([t for _, r, t in all_attest if r == 'NO_ANSWER'])}")
    out.append(f"- single measurement [ms]: {stats([m for _, _, m in all_measure])}")
    out.append(f"- wait for a free core [ms]: {stats([w for _, w, _ in all_measure])}")

    events = Counter()
    for i in infos:
        events.update(i["events"])
    out += ["", "## Protocol events (all devices)", ""]
    out += [f"- {k}: {v}" for k, v in sorted(events.items())] or ["- none"]

    sent, sent_bytes = Counter(), Counter()
    for i in infos:
        sent.update(i["sent"])
        sent_bytes.update(i["sent_bytes"])
    out += ["", "## Protocol messages sent (all devices; the log may truncate long messages)", ""]
    out += [f"- {k}: {v} messages, {sent_bytes[k]} bytes" for k, v in sent.most_common()] or ["- none"]

    out += ["", "## Storage (last report of each device)", ""]
    for i in infos:
        if i["storage"]:
            used, total, db_entries, db_bytes, members, crps, cnodes = i["storage"]
            out.append(f"- {i['device']}: NVS {used}/{total} entries; network state and shards {db_entries} entries "
                       f"({db_bytes} bytes) for {members} members, {crps} CRPs, {cnodes} network-state entries")

    panics = [(i["device"], p) for i in infos for p in i["panics"]]
    out += ["", "## Crashes and watchdogs", ""]
    out += [f"- {d}: {p}" for d, p in panics[:30]] or ["- none"]

    errors = Counter()
    for i in infos:
        errors.update(i["errors"])
    out += ["", "## Most frequent errors (all devices)", ""]
    out += [f"- {n}x {msg}" for msg, n in errors.most_common(25)] or ["- none"]

    report = "\n".join(out)
    with open(os.path.join(directory, "log_summary.md"), "w") as f:
        f.write(report + "\n")
    return report


# --------------------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description="SRAFT test pipeline")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("sync")
    p = sub.add_parser("services")
    p.add_argument("action", choices=["up", "down", "restart", "status", "rotate-logs", "reset-db"])
    p.add_argument("target", nargs="?", default="all", choices=["db", "monitor", "deploy", "all"])
    p = sub.add_parser("build")
    p.add_argument("--clean", action="store_true")
    p.add_argument("--profile", choices=list(BUILD_DIRS), default="debug")
    p.add_argument("--tampered", action="store_true",
                   help="also write the tampered test image (4 KB of the test region overwritten with random bytes)")
    p = sub.add_parser("run")
    p.add_argument("-n", "--nodes", type=int, default=5)
    p.add_argument("--tag", default="")
    p.add_argument("--build", action="store_true", help="build the firmware before the run")
    p.add_argument("--profile", choices=list(BUILD_DIRS), default="debug",
                   help="debug: serial logs and diagnostics; release: no serial logs, for the measurements")
    p.add_argument("--timeout", type=int, default=DEFAULT_RUN_TIMEOUT_S)
    p.add_argument("--sraft-only", action="store_true", help="skip the TLS and MQTTS baselines")
    p.add_argument("--integrity-test", action="store_true",
                   help="run only the failed-attestation scenario (last device tampered)")
    p.add_argument("--detection-test", action="store_true",
                   help="run only the measurement of the detection rate of the attestation")
    p.add_argument("--attestation-test", action="store_true",
                   help="run only the cost of a successful attestation (each device attested once per iteration)")
    p.add_argument("-i", "--iterations", type=int, default=10, help="iterations of the attestation test and of --loop")
    p.add_argument("--loop", action="store_true",
                   help="run the standard scenarios (join, authentication with the baselines, removal) -i times")
    p.add_argument("--out", default="", help="base folder of the results of the campaign")
    p.add_argument("--fault", choices=["crash", "tamper"],
                   help="run only the resilience scenario: devices crash or are altered while they run")
    p.add_argument("--fault-count", type=int, default=1, help="devices hit by the fault at the same time")
    p.add_argument("--fault-coordinator", action="store_true", help="include the Coordinator among them")
    p.add_argument("--runs", type=int, default=DEFAULT_DETECTION_RUNS,
                   help="attestations of each image in the detection test")
    p.add_argument("--detection-sizes", type=int, nargs="+",
                   help=f"tampered bytes of the images of the detection test (default {DETECTION_SIZES})")
    p = sub.add_parser("fetch")
    p.add_argument("dest")
    p = sub.add_parser("analyze")
    p.add_argument("dir")
    args = parser.parse_args()

    {"sync": cmd_sync, "services": cmd_services, "build": cmd_build, "run": cmd_run,
     "fetch": cmd_fetch, "analyze": cmd_analyze}[args.command](args)


if __name__ == "__main__":
    main()
