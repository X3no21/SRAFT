"""
Builds, from the raw output of the campaigns run on the server (run_campaign_server.sh), a results folder
with the layout of the archived experimental_results/ folder. Logs are not copied: they stay in the raw folders.

  <out>/experimental_results/sraft/size_<N>/iter_<i>/
      report_scenario_{authentication,election,join,removal}.xlsx, report_global_summary.xlsx,
      report_per_device.xlsx       reports exported by the monitoring server for the standard scenarios
      devices.json                 address, MAC and Raft state of each device after the bootstrap
      report_scenario_attestation.xlsx   report of the attestation scenario
      attestation/                 reports of the attestation scenario (report_scenario_attestation,
                                   report_attestation_per_device, report_global_summary, attestation_outcomes)
      intra_device/device_<k>/report_scenario_{authentication,election,join,removal,attestation}.xlsx
  <out>/experimental_results/{tls,tls_resumed,mqtts}/size_<N>/iter_<i>/
      report_scenario_authentication.xlsx, intra_device/device_<k>/report_scenario_authentication.xlsx
  <out>/experiment_results/<fault>_<N>_nodes_r<k>/   fault_result.json and the reports of the run
  <out>/experiment_results/below_minimum/...          fault runs on fewer than 2f+1 devices, not analyzed
  <out>/statistics/, <out>/plots/                     with --analyze

Every per-device file holds, for each phase, the mean duration of the operations of that phase and the mean
and standard deviation of the samples of that device over them. In each run device_0 is the Coordinator
after its bootstrap, the other devices follow in the order of their MAC address; the attestation runs
bootstrap their own network, so their Coordinator may differ from the one of the standard scenarios.

Only the output of real runs is converted: the script never writes values that were not measured.

Usage: python aggregate_campaign.py <out> <raw_campaign_dir> [<raw_campaign_dir> ...] [--analyze]
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys

import pandas as pd

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
COLUMNS = ["avg_duration_s", "avg_cluster_cpu_perc", "std_cluster_cpu_perc", "avg_cluster_mem_perc",
           "std_cluster_mem_perc", "avg_cluster_power_mW", "std_cluster_power_mW", "phase_type"]
# Scenario file -> phases of the monitoring server, with the name used in the file.
SRAFT_FILES = {
    "report_scenario_join.xlsx": [("BOOTSTRAP", "BOOTSTRAP"), ("JOIN", "JOIN")],
    "report_scenario_election.xlsx": [("ELECTION", "ELECTION")],
    "report_scenario_removal.xlsx": [("REMOVE", "REMOVE"), ("HEALING_PHASE", "HEALING"), ("HEAL", "HEAL")],
}
AUTH_FILE = "report_scenario_authentication.xlsx"
AUTH_EXPORTS = {"report_auth_sraft.xlsx": "sraft", "report_auth_tls.xlsx": "tls",
                "report_auth_tls_resumed.xlsx": "tls_resumed", "report_auth_mqtts.xlsx": "mqtts"}
ATTESTATION_FILES = ["report_scenario_attestation.xlsx", "report_attestation_per_device.xlsx",
                     "report_global_summary.xlsx", "attestation_outcomes.json"]
# Name of a scenario in run_campaign_server.sh -> name of its fault folder.
FAULT_SCENARIOS = {"crash2": "crash_2", "crash2coord": "crash_2_coord", "tamper1": "tamper_1", "tamper1coord": "tamper_1_coord"}


def row(samples: pd.DataFrame, phase_name: str) -> dict:
    durations = samples.drop_duplicates("operation_id")["duration_s"]
    std = lambda s: float(s.std(ddof=1)) if len(s) > 1 else 0.0
    return {"avg_duration_s": durations.mean(),
            "avg_cluster_cpu_perc": samples["cpu_usage_percent"].mean(), "std_cluster_cpu_perc": std(samples["cpu_usage_percent"]),
            "avg_cluster_mem_perc": samples["memory_load_percent"].mean(), "std_cluster_mem_perc": std(samples["memory_load_percent"]),
            "avg_cluster_power_mW": samples["estimated_power_mw"].mean(), "std_cluster_power_mW": std(samples["estimated_power_mw"]),
            "phase_type": phase_name}


def write(path: str, rows: list):
    if rows:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        pd.DataFrame(rows, columns=COLUMNS).to_excel(path, index=False)


def copy(src: str, dest: str):
    if os.path.isdir(src):
        shutil.copytree(src, dest, dirs_exist_ok=True)
    elif os.path.exists(src):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)


def system_iter(out: str, system: str, n: int, it: int) -> str:
    return os.path.join(out, "experimental_results", system, f"size_{n}", f"iter_{it}")


def convert_standard(run_dir: str, out: str, n: int, it: int):
    sraft_iter = system_iter(out, "sraft", n, it)
    # Raw exports of the monitoring server, the authentication split by scheme as in the original layout.
    for f in glob.glob(os.path.join(run_dir, "*")):
        name = os.path.basename(f)
        if name in AUTH_EXPORTS:
            copy(f, os.path.join(system_iter(out, AUTH_EXPORTS[name], n, it), AUTH_FILE))
        else:
            copy(f, os.path.join(sraft_iter, name))

    per_device = pd.read_excel(os.path.join(run_dir, "report_per_device.xlsx"))
    with open(os.path.join(run_dir, "devices.json")) as f:
        devices = json.load(f)["devices"]
    leader = [d["mac"] for d in devices if d.get("state") == "leader" and d["mac"] in set(per_device["node_mac"])]
    order = leader + sorted(m for m in set(per_device["node_mac"]) if m not in leader)
    for k, mac in enumerate(order):
        dev = per_device[per_device["node_mac"] == mac]
        for file_name, phases in SRAFT_FILES.items():
            rows = [row(dev[dev["phase_type"] == p], name) for p, name in phases if (dev["phase_type"] == p).any()]
            write(os.path.join(sraft_iter, "intra_device", f"device_{k}", file_name), rows)
        for scheme, system in (("SRAFT", "sraft"), ("TLS", "tls"), ("TLS_RESUMED", "tls_resumed"), ("MQTTS", "mqtts")):
            auth = dev[(dev["phase_type"] == "AUTH") & (dev["auth_type"] == scheme)]
            if not auth.empty:
                write(os.path.join(system_iter(out, system, n, it), "intra_device", f"device_{k}", AUTH_FILE), [row(auth, "AUTH")])


def convert_attestation(run_dir: str, sraft_iter: str):
    """Per-device files of the attestation scenario, from the samples exported by the monitoring server."""
    per_device = pd.read_excel(os.path.join(run_dir, "report_attestation_per_device.xlsx"))
    with open(os.path.join(run_dir, "attestation_outcomes.json")) as f:
        devices = json.load(f)["devices"]
    macs = set(per_device["node_mac"])
    leader = [d["mac"] for d in devices if d.get("state") == "leader" and d["mac"] in macs]
    for k, mac in enumerate(leader + sorted(m for m in macs if m not in leader)):
        dev = per_device[per_device["node_mac"] == mac]
        write(os.path.join(sraft_iter, "intra_device", f"device_{k}", "report_scenario_attestation.xlsx"),
              [row(dev, "INTEGRITY_CHECK")])


def iteration_of(tag: str) -> tuple:
    """Iteration encoded in a run tag by run_campaign_server.sh ("srv_i<k>"), and the suffix of its logs."""
    m = re.search(r"_i(\d+)$", tag)
    return (int(m.group(1)), f"_i{m.group(1)}") if m else (1, "")


def convert_campaign(campaign: str, out: str):
    sizes = set()
    for run_dir in glob.glob(os.path.join(campaign, "standard", "*")):
        m = re.search(r"single_run_(\d+)_nodes_(\w+)$", os.path.basename(run_dir))
        if not m or not os.path.exists(os.path.join(run_dir, "report_per_device.xlsx")):
            continue
        n = int(m.group(1))
        it, suffix = iteration_of(m.group(2))
        sizes.add(n)
        convert_standard(run_dir, out, n, it)
        print(f"standard: {run_dir} -> sraft/size_{n}/iter_{it}")

    for iter_dir in glob.glob(os.path.join(campaign, "attestation_*", "size_*", "iter_*")):
        n = int(re.search(r"size_(\d+)", iter_dir).group(1))
        # The iteration comes from the tag of the run (run_campaign_server.sh runs one iteration per run, tagged
        # "srv_i<k>"), otherwise from the iter_<k> folder of a run with several iterations (-i).
        tag = re.search(r"attestation_(\w+?)/", iter_dir + "/").group(1)
        it = iteration_of(tag)[0] if re.search(r"_i\d+$", tag) else int(re.search(r"iter_(\d+)$", iter_dir).group(1))
        sizes.add(n)
        sraft_iter = system_iter(out, "sraft", n, it)
        for name in ATTESTATION_FILES:
            copy(os.path.join(iter_dir, name), os.path.join(sraft_iter, "attestation", name))
        copy(os.path.join(iter_dir, "report_scenario_attestation.xlsx"), os.path.join(sraft_iter, "report_scenario_attestation.xlsx"))
        convert_attestation(iter_dir, sraft_iter)
        print(f"attestation: {iter_dir} -> sraft/size_{n}/iter_{it}/attestation")


    for fault_dir in glob.glob(os.path.join(campaign, "faults", "fault_*")):
        m = re.match(r"fault_(crash|tamper)_(\d+)(_coord)?_(\d+)_nodes_srv_r(\d+)$", os.path.basename(fault_dir))
        result = os.path.join(fault_dir, "fault_result.json")
        if not m or not os.path.exists(result):
            print(f"fault: {fault_dir} skipped (no result)")
            continue
        count, n, rep = int(m.group(2)), int(m.group(4)), m.group(5)
        name = f"{m.group(1)}_{count}{m.group(3) or ''}_{n}_nodes_r{rep}"
        with open(result) as f:
            skipped = "skipped" in json.load(f)
        # Fault runs on fewer than 2f+1 devices cannot recover by design and are kept apart.
        below = n < 2 * count + 1
        dest = os.path.join(out, "experiment_results", *(["below_minimum"] if below else []), name)
        for f in glob.glob(os.path.join(fault_dir, "*.xlsx")) + [result]:
            copy(f, os.path.join(dest, os.path.basename(f)))
        # Same file name as the authentication reports of the standard scenarios.
        auth = os.path.join(dest, "report_auth_sraft.xlsx")
        if os.path.exists(auth):
            os.replace(auth, os.path.join(dest, AUTH_FILE))
        print(f"fault: {fault_dir} -> experiment_results/{'below_minimum/' if below else ''}{name}{' (not run)' if skipped else ''}")


def analyze(out: str):
    py = sys.executable
    run = lambda *args: subprocess.run([py, *args], cwd=out, check=True, stdout=subprocess.DEVNULL)
    run(os.path.join(TESTS_DIR, "statistics_report.py"), "--root", "experimental_results",
        "--results", "experiment_results", "--fault-runs", "*_nodes_r*", "--out", "statistics")
    run(os.path.join(TESTS_DIR, "generate_plots.py"))
    plots = os.path.join(out, "plots")
    if os.path.exists(plots):
        shutil.rmtree(plots)
    shutil.move(os.path.join(out, "experimental_results", "plots"), plots)
    # The attestation has no per-device files: its plots and tables come from attestation_report.py.
    for f in glob.glob(os.path.join(plots, "*Attestation*")) + glob.glob(os.path.join(plots, "RQ1_Authentication_*")):
        os.remove(f)
    sraft = os.path.join(out, "experimental_results", "sraft")
    for size_dir in glob.glob(os.path.join(sraft, "size_*")):
        if not glob.glob(os.path.join(size_dir, "iter_*", "attestation", "report_attestation_per_device.xlsx")):
            continue
        n = int(re.search(r"size_(\d+)", size_dir).group(1))
        stats_dir = os.path.join(out, "statistics", f"attestation_{n}_nodes")
        subprocess.run([py, os.path.join(TESTS_DIR, "attestation_report.py"), sraft, stats_dir,
                        "-n", str(n)], check=True, stdout=subprocess.DEVNULL)
        plot = os.path.join(stats_dir, f"RQ2_Device_Overhead_{n}Nodes_Attestation.tex")
        if n == 7:
            shutil.move(plot, os.path.join(plots, os.path.basename(plot)))
        else:
            os.remove(plot)
    print(f"statistics and plots written under {out}")


def main():
    args = [a for a in sys.argv[1:] if a != "--analyze"]
    out, campaigns = os.path.abspath(args[0]), [os.path.abspath(c) for c in args[1:]]
    for campaign in campaigns:
        convert_campaign(campaign, out)
    if "--analyze" in sys.argv:
        analyze(out)


if __name__ == "__main__":
    main()
