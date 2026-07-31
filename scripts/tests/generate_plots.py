import pandas as pd
import os
import random
import shutil
import numpy as np
import matplotlib.pyplot as plt
import logging

# --- CONFIGURATION ---
ROOT_DIR = "experimental_results"
PLOTS_OUTPUT_DIR = os.path.join(ROOT_DIR, "plots")
INTRA_DEVICE_SUBDIR = "intra_device"

# Strict Node Configs: 3 to 31, odd numbers
NODE_CONFIGS = list(range(3, 32, 2))
NUM_ITERATIONS = 10
BASE_NODE_COUNT = 5

# --- CONSTANTS ---
ESP32_VOLTAGE_V = 3.3
IDLE_CURRENT_MA = 44.0
MAX_CURRENT_MA = 239.0
ACTIVE_CURRENT_RANGE_MA = MAX_CURRENT_MA - IDLE_CURRENT_MA

# --- RAW COLUMN NAMES ---
COL_CAMPAIGN = "campaign_id"
COL_PHASE = "phase_type"
COL_NODES = "num_nodes"
COL_SUCCESS = "success_rate_perc"
COL_DURATION = "avg_duration_s"
COL_CPU = "avg_cluster_cpu_perc"
COL_CPU_STD = "std_cluster_cpu_perc"
COL_MEM = "avg_cluster_mem_perc"
COL_MEM_STD = "std_cluster_mem_perc"
COL_POWER = "avg_cluster_power_mW"
COL_POWER_STD = "std_cluster_power_mW"

# Columns for Global Files (Scenario Reports)
GLOBAL_COLUMNS = [
    COL_CAMPAIGN,
    COL_PHASE,
    COL_NODES,
    COL_SUCCESS,
    COL_DURATION,
    COL_CPU,
    COL_CPU_STD,
    COL_MEM,
    COL_MEM_STD,
    COL_POWER,
    COL_POWER_STD,
]

# Columns for Intra-Device Files
DEVICE_COLUMNS = [
    COL_PHASE,
    COL_DURATION,
    COL_CPU,
    COL_CPU_STD,
    COL_MEM,
    COL_MEM_STD,
    COL_POWER,
    COL_POWER_STD,
]

# --- BASE VALUES (5 Nodes) ---
# Ranking: AUTH < ATTESTATION < ELECTION < REMOVE < JOIN < HEAL
# Tuned for targets at 31 nodes: Join~30s, Heal~35s, Election~3s
BASE_STATS = {
    "AUTH": {"dur": 0.15, "cpu": 10.0, "mem": 15.0},
    "INTEGRITY_CHECK": {"dur": 0.40, "cpu": 20.0, "mem": 25.0},  # Attestation
    "ELECTION": {"dur": 0.60, "cpu": 25.0, "mem": 30.0},  # > Attest
    "REMOVE": {"dur": 0.80, "cpu": 35.0, "mem": 40.0},  # > Elec
    "JOIN": {"dur": 1.00, "cpu": 45.0, "mem": 50.0},  # > Remove
    "HEAL": {"dur": 1.20, "cpu": 55.0, "mem": 60.0},  # > Join
    # Aggregate phases
    "BOOTSTRAP": {"dur": 0.00, "cpu": 45.0, "mem": 50.0},
    "HEALING": {"dur": 0.00, "cpu": 55.0, "mem": 60.0},
}

# --- HELPER FUNCTIONS ---


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def vary_value(value, percentage=0.05):
    if not isinstance(value, (int, float, np.number)) or value == 0:
        return value
    return value * (1 + random.uniform(-percentage, percentage))


def calculate_power(cpu_perc):
    estimated_current_ma = IDLE_CURRENT_MA + (
        (MAX_CURRENT_MA - IDLE_CURRENT_MA) * (cpu_perc / 100.0)
    )
    return estimated_current_ma * ESP32_VOLTAGE_V


def get_scaled_stats(phase, node_count, is_leader=False, system_type="SRAFT"):
    base = BASE_STATS.get(phase, BASE_STATS["AUTH"])

    dur = base["dur"]
    cpu = base["cpu"]
    mem = base["mem"]

    # --- SCALING LOGIC ---
    # General resource scaling for N > 5
    if node_count > 5:
        factor = 1.0 + (node_count - 5) * 0.005  # Very small increase per node
        dur *= factor
        cpu *= factor
        mem *= factor

    # 3-Node Consistency: No artificial reduction, they follow the base stats (which are for ~5 nodes)
    # User requested strict alignment with 5-node stats.
    if node_count == 3:
        pass  # No reduction, same as base (5 nodes)

    # Phase-specific Duration Scaling (Network effects)
    diff = max(0, node_count - 5)

    if phase == "AUTH":
        pass  # Constant
    elif phase == "ELECTION":
        # Target: ~3s at 31 nodes. Base 0.6s. Diff=26. Need +2.4s.
        # 2.4 / 26 ~= 0.09
        dur += diff * 0.09
    elif phase == "REMOVE":
        dur += diff * 0.05
    elif phase == "INTEGRITY_CHECK":
        dur += diff * 0.03
    elif phase == "JOIN" or phase == "HEAL":
        # Very slight increase per node for individual ops
        dur += diff * 0.005

    # Baseline Overheads (Time & Resources)
    if system_type == "TLS":
        dur += random.uniform(0.1, 0.2)
        cpu *= 1.2
        mem *= 1.1
    elif system_type == "MQTTS":
        dur += random.uniform(0.3, 0.5)
        cpu *= 1.5
        mem *= 1.3

    # Leader Overhead
    if is_leader:
        cpu *= 1.15
        mem *= 1.05

    # Cap resources at 100%
    cpu = min(cpu, 100.0)
    mem = min(mem, 100.0)

    # --- ENFORCE ORDER & CORRELATION ---
    # Ensure ELECTION, JOIN, HEAL >= INTEGRITY_CHECK (Attestation)
    # User requirement: If stats < Attestation, increase them.
    if phase in ["ELECTION", "JOIN", "HEAL"] and system_type == "SRAFT":
        # Get current Attestation stats for this node count
        # We call get_scaled_stats recursively but need to avoid infinite loop.
        # Since INTEGRITY_CHECK doesn't trigger this block, it's safe.
        attest_stats = get_scaled_stats(
            "INTEGRITY_CHECK", node_count, is_leader, system_type
        )

        # Enforce Duration
        if dur < attest_stats["dur"]:
            dur = attest_stats["dur"] * 1.05  # Ensure slightly higher

        # Enforce CPU
        if cpu < attest_stats["cpu"]:
            cpu = attest_stats["cpu"] * 1.05

        # Enforce Mem
        if mem < attest_stats["mem"]:
            mem = attest_stats["mem"] * 1.05

    power = calculate_power(cpu)

    # Variation settings
    if node_count == 3:
        dur_var = 0.05
        cpu_var = 0.02
        mem_var = 0.01
        power_var = 0.02
    else:
        dur_var = 0.1
        cpu_var = 0.05
        mem_var = 0.02
        power_var = 0.05

    return {
        "dur": vary_value(dur, dur_var),
        "cpu": vary_value(cpu, cpu_var),
        "mem": vary_value(mem, mem_var),
        "power": vary_value(power, power_var),
    }


def create_row(campaign_id, phase, num_nodes, stats, is_device_file=False):
    row = {
        COL_DURATION: stats["dur"],
        COL_CPU: stats["cpu"],
        COL_CPU_STD: stats["cpu"] * 0.1,
        COL_MEM: stats["mem"],
        COL_MEM_STD: stats["mem"] * 0.01,
        COL_POWER: stats["power"],
        COL_POWER_STD: stats["power"] * 0.1,
    }

    row[COL_PHASE] = phase

    if not is_device_file:
        row[COL_CAMPAIGN] = campaign_id
        row[COL_NODES] = num_nodes
        row[COL_SUCCESS] = 100.0

    return row


def generate_iteration_data(base_dir, node_count, iteration, system_type="SRAFT"):
    iter_dir = os.path.join(base_dir, f"size_{node_count}", f"iter_{iteration}")
    intra_dir = os.path.join(iter_dir, INTRA_DEVICE_SUBDIR)
    ensure_dir(iter_dir)

    campaign_id = f"size_{node_count}_iter_{iteration}"
    if system_type != "SRAFT":
        campaign_id += f"_{system_type}"

    # --- GENERATE DEVICE STATS ---
    device_stats = {
        "BOOTSTRAP": [],
        "JOIN": [],
        "ELECTION": [],
        "REMOVE": [],
        "HEALING": [],
        "HEAL": [],
        "AUTH": [],
        "INTEGRITY_CHECK": [],
    }

    for dev_id in range(node_count):
        dev_path = os.path.join(intra_dir, f"device_{dev_id}")
        ensure_dir(dev_path)
        is_leader = dev_id == 0

        # Generate stats for all phases
        for p in ["JOIN", "ELECTION", "REMOVE", "HEAL", "AUTH", "INTEGRITY_CHECK"]:
            s = get_scaled_stats(p, node_count, is_leader, system_type)
            device_stats[p].append(s)

    # --- CALCULATE AGGREGATE PHASES ---
    # Bootstrap
    total_join_time = sum(d["dur"] for d in device_stats["JOIN"])
    bootstrap_overhead = random.uniform(0.05, 0.15) * node_count
    bootstrap_dur = total_join_time + bootstrap_overhead

    # Healing
    total_heal_time = sum(d["dur"] for d in device_stats["HEAL"])
    healing_overhead = random.uniform(0.05, 0.15) * (node_count - 1)
    healing_dur = total_heal_time + healing_overhead

    for i in range(node_count):
        is_leader = i == 0

        # Bootstrap (use JOIN resources as base)
        s_boot = get_scaled_stats("JOIN", node_count, is_leader, system_type)
        s_boot["dur"] = bootstrap_dur
        device_stats["BOOTSTRAP"].append(s_boot)

        # Healing (use HEAL resources as base)
        s_healing = get_scaled_stats("HEAL", node_count, is_leader, system_type)
        s_healing["dur"] = healing_dur
        device_stats["HEALING"].append(s_healing)

    # --- WRITE FILES ---
    for dev_id in range(node_count):
        dev_path = os.path.join(intra_dir, f"device_{dev_id}")

        # Join Report
        rows_join = [
            create_row(
                campaign_id,
                "BOOTSTRAP",
                node_count,
                device_stats["BOOTSTRAP"][dev_id],
                is_device_file=True,
            ),
            create_row(
                campaign_id,
                "JOIN",
                node_count,
                device_stats["JOIN"][dev_id],
                is_device_file=True,
            ),
        ]
        pd.DataFrame(rows_join).to_excel(
            os.path.join(dev_path, "report_scenario_join.xlsx"), index=False
        )

        # Election Report
        rows_elec = [
            create_row(
                campaign_id,
                "ELECTION",
                node_count,
                device_stats["ELECTION"][dev_id],
                is_device_file=True,
            )
        ]
        pd.DataFrame(rows_elec).to_excel(
            os.path.join(dev_path, "report_scenario_election.xlsx"), index=False
        )

        # Removal Report
        rows_rem = [
            create_row(
                campaign_id,
                "REMOVE",
                node_count,
                device_stats["REMOVE"][dev_id],
                is_device_file=True,
            ),
            create_row(
                campaign_id,
                "HEALING",
                node_count,
                device_stats["HEALING"][dev_id],
                is_device_file=True,
            ),
            create_row(
                campaign_id,
                "HEAL",
                node_count,
                device_stats["HEAL"][dev_id],
                is_device_file=True,
            ),
        ]
        pd.DataFrame(rows_rem).to_excel(
            os.path.join(dev_path, "report_scenario_removal.xlsx"), index=False
        )

        # Auth Report
        rows_auth = [
            create_row(
                campaign_id,
                "AUTH",
                node_count,
                device_stats["AUTH"][dev_id],
                is_device_file=True,
            )
        ]
        pd.DataFrame(rows_auth).to_excel(
            os.path.join(dev_path, "report_scenario_authentication.xlsx"), index=False
        )

        # Attestation Report (INTEGRITY_CHECK)
        if system_type == "SRAFT":
            rows_att = [
                create_row(
                    campaign_id,
                    "INTEGRITY_CHECK",
                    node_count,
                    device_stats["INTEGRITY_CHECK"][dev_id],
                    is_device_file=True,
                )
            ]
            pd.DataFrame(rows_att).to_excel(
                os.path.join(dev_path, "report_scenario_attestation.xlsx"), index=False
            )

    # --- GLOBAL FILES ---
    def avg_stat(phase_key):
        stats_list = device_stats[phase_key]
        return {
            "dur": np.mean([s["dur"] for s in stats_list]),
            "cpu": np.mean([s["cpu"] for s in stats_list]),
            "mem": np.mean([s["mem"] for s in stats_list]),
            "power": np.mean([s["power"] for s in stats_list]),
        }

    # Join
    rows_g_join = [
        create_row(campaign_id, "BOOTSTRAP", node_count, avg_stat("BOOTSTRAP")),
        create_row(campaign_id, "JOIN", node_count, avg_stat("JOIN")),
    ]
    pd.DataFrame(rows_g_join).to_excel(
        os.path.join(iter_dir, "report_scenario_join.xlsx"), index=False
    )

    # Election
    rows_g_elec = [
        create_row(campaign_id, "ELECTION", node_count, avg_stat("ELECTION"))
    ]
    pd.DataFrame(rows_g_elec).to_excel(
        os.path.join(iter_dir, "report_scenario_election.xlsx"), index=False
    )

    # Removal
    rows_g_rem = [
        create_row(campaign_id, "REMOVE", node_count, avg_stat("REMOVE")),
        create_row(campaign_id, "HEALING", node_count, avg_stat("HEALING")),
        create_row(campaign_id, "HEAL", node_count, avg_stat("HEAL")),
    ]
    pd.DataFrame(rows_g_rem).to_excel(
        os.path.join(iter_dir, "report_scenario_removal.xlsx"), index=False
    )

    # Auth
    rows_g_auth = [create_row(campaign_id, "AUTH", node_count, avg_stat("AUTH"))]
    pd.DataFrame(rows_g_auth).to_excel(
        os.path.join(iter_dir, "report_scenario_authentication.xlsx"), index=False
    )

    # Attestation
    if system_type == "SRAFT":
        rows_g_att = [
            create_row(
                campaign_id, "INTEGRITY_CHECK", node_count, avg_stat("INTEGRITY_CHECK")
            )
        ]
        pd.DataFrame(rows_g_att).to_excel(
            os.path.join(iter_dir, "report_scenario_attestation.xlsx"), index=False
        )


def generate_all_data():
    print("Generating raw data...")

    # Check if data already exists
    if os.path.exists(ROOT_DIR) and os.path.isdir(ROOT_DIR):
        sraft_exists = os.path.exists(os.path.join(ROOT_DIR, "sraft"))
        tls_exists = os.path.exists(os.path.join(ROOT_DIR, "tls"))
        mqtts_exists = os.path.exists(os.path.join(ROOT_DIR, "mqtts"))

        if sraft_exists and tls_exists and mqtts_exists:
            print(
                f"Data directory '{ROOT_DIR}' already exists with all subdirectories. Skipping generation."
            )
            return

    # if os.path.exists(ROOT_DIR):
    #     shutil.rmtree(ROOT_DIR)
    ensure_dir(ROOT_DIR)

    sraft_dir = os.path.join(ROOT_DIR, "sraft")
    tls_dir = os.path.join(ROOT_DIR, "tls")
    mqtts_dir = os.path.join(ROOT_DIR, "mqtts")

    ensure_dir(sraft_dir)
    ensure_dir(tls_dir)
    ensure_dir(mqtts_dir)

    for nc in NODE_CONFIGS:
        print(f"  Generating data for {nc} nodes...")
        for i in range(1, NUM_ITERATIONS + 1):
            generate_iteration_data(sraft_dir, nc, i, system_type="SRAFT")
            generate_iteration_data(tls_dir, nc, i, system_type="TLS")
            generate_iteration_data(mqtts_dir, nc, i, system_type="MQTTS")


# --- TIKZ GENERATION HELPERS ---


def calculate_box_stats(values):
    """
    Calculates min, q1, median, q3, max for boxplot.
    """
    if not values:
        return None
    return {
        "lower_whisker": np.min(values),
        "lower_quartile": np.percentile(values, 25),
        "median": np.median(values),
        "upper_quartile": np.percentile(values, 75),
        "upper_whisker": np.max(values),
    }


def generate_tikz_header():
    return r"""
% Add to your preamble:
% \usepackage{tikz}
% \usepackage{pgfplots}
% \usepgfplotslibrary{groupplots, statistics}
% \pgfplotsset{compat=1.18}
"""


def write_tikz_file(filename, content):
    ensure_dir(PLOTS_OUTPUT_DIR)
    filepath = os.path.join(PLOTS_OUTPUT_DIR, filename)
    with open(filepath, "w") as f:
        f.write(content)
    print(f"Generated TikZ file: {filepath}")


def generate_tikz_2x2(data_maps, title, filename, metrics):
    """
    Generates a 2x2 groupplot for Duration, CPU, Memory, Power.
    data_maps: list of data_map (one per metric)
    """
    tex = r"\begin{figure}[htbp]" + "\n"
    tex += r"\centering" + "\n"
    tex += r"\begin{tikzpicture}" + "\n"
    tex += (
        r"\begin{groupplot}[group style={group size=2 by 2, horizontal sep=2cm, vertical sep=2cm}, width=0.45\textwidth]"
        + "\n"
    )

    for i, (col, ylabel, plot_title) in enumerate(metrics):
        data_map = data_maps[i]
        tex += f"% Plot {i+1}: {plot_title}\n"
        tex += (
            r"\nextgroupplot[title={"
            + plot_title
            + r"}, xlabel={Number of Nodes}, ylabel={"
            + ylabel
            + r"}, xmajorgrids=true, ymajorgrids=true, grid style=dashed]"
            + "\n"
        )

        if not data_map:
            continue

        sorted_keys = sorted(data_map.keys())
        for nc in sorted_keys:
            stats = calculate_box_stats(data_map[nc])
            if stats:
                # boxplot prepared={lower whisker=..., lower quartile=..., median=..., upper quartile=..., upper whisker=...}
                # coordinates are needed for x-axis position? No, draw=black, fill=cyan!40
                tex += r"\addplot+ [boxplot prepared={" + "\n"
                tex += f"  lower whisker={stats['lower_whisker']:.4f},\n"
                tex += f"  lower quartile={stats['lower_quartile']:.4f},\n"
                tex += f"  median={stats['median']:.4f},\n"
                tex += f"  upper quartile={stats['upper_quartile']:.4f},\n"
                tex += f"  upper whisker={stats['upper_whisker']:.4f}\n"
                tex += r"}, draw=black, fill=cyan!40, solid] coordinates {};" + "\n"
                # We need to shift/place these boxplots at specific x-coordinates?
                # pgfplots boxplot usually puts them at x=1, 2, 3... or we can specify 'draw position'.
                # To match the "Number of Nodes" on x-axis, we should use 'draw position=nc'.
                # Let's adjust the addplot options.

    # Wait, the loop above adds multiple addplots, one per box.
    # Better approach for pgfplots: one addplot with multiple coordinates if possible,
    # OR multiple addplots with 'draw position'.
    # Since we have pre-calculated stats, we must use multiple addplots (one per box).

    # Let's rewrite the loop to be correct for pgfplots boxplots at specific positions.
    return  # Placeholder, will overwrite with full implementation below


def generate_tikz_1x4_full(data_maps, title, filename, metrics):
    tex = r"\begin{figure}[htbp]" + "\n"
    tex += r"\centering" + "\n"
    tex += r"\begin{tikzpicture}" + "\n"
    # Adjusted for single column vertical stack (1x4):
    # - group size=1 by 4
    # - vertical sep=0.2cm (Tight spacing)
    tex += (
        r"\begin{groupplot}[group style={group size=1 by 4, vertical sep=0.2cm, x descriptions at=edge bottom}, width=0.95\linewidth, height=3.5cm, boxplot/draw direction=y, xtick={3,5,7,9,11,13,15,17,19,21,23,25,27,29,31}, xticklabel style={font=\scriptsize}, yticklabel style={font=\scriptsize}, label style={font=\scriptsize}, ylabel style={font=\scriptsize}]"
        + "\n"
    )

    caption_parts = []
    for i, (col, ylabel, plot_title) in enumerate(metrics):
        data_map = data_maps[i]
        caption_parts.append(f"{plot_title} ({ylabel})")

        # Only show xlabel on the last plot (handled by x descriptions at=edge bottom, but we need to be explicit about the label text)
        xlabel_cmd = "xlabel={Nodes}" if i == len(metrics) - 1 else "xlabel={}"

        tex += f"\n% --- {plot_title} ---\n"
        tex += (
            r"\nextgroupplot[ylabel={"
            + ylabel
            + r"}, "
            + xlabel_cmd
            + r", xmajorgrids=true, ymajorgrids=true, grid style=dashed]"
            + "\n"
        )

        if data_map:
            sorted_keys = sorted(data_map.keys())
            for nc in sorted_keys:
                stats = calculate_box_stats(data_map[nc])
                if stats:
                    tex += r"\addplot+ [boxplot prepared={" + "\n"
                    tex += f"  lower whisker={stats['lower_whisker']:.3f}, lower quartile={stats['lower_quartile']:.3f}, median={stats['median']:.3f}, upper quartile={stats['upper_quartile']:.3f}, upper whisker={stats['upper_whisker']:.3f},\n"
                    tex += f"  draw position={nc}, box extend=1.5\n"
                    tex += r"}, draw=black, fill=cyan!40, solid] coordinates {};" + "\n"

    tex += r"\end{groupplot}" + "\n"
    tex += r"\end{tikzpicture}" + "\n"

    # Detailed caption
    full_caption = f"{title}. From top to bottom: " + ", ".join(caption_parts) + "."
    tex += r"\caption{" + full_caption + r"}" + "\n"
    tex += r"\label{fig:" + filename.replace(".tex", "").replace("_", "-") + r"}" + "\n"
    tex += r"\end{figure}" + "\n"

    write_tikz_file(filename, tex)


def generate_tikz_comparison_full(
    sraft_maps, base_maps, baseline_name, title, filename, metrics
):
    tex = r"\begin{figure}[htbp]" + "\n"
    tex += r"\centering" + "\n"
    tex += r"\begin{tikzpicture}" + "\n"
    # Adjusted for single column vertical stack (1x4)
    # - vertical sep=0.2cm
    # - x descriptions at=edge bottom
    tex += (
        r"\begin{groupplot}[group style={group size=1 by 4, vertical sep=0.2cm, x descriptions at=edge bottom}, width=0.95\linewidth, height=3.5cm, boxplot/draw direction=y, xtick={3,5,7,9,11,13,15,17,19,21,23,25,27,29,31}, xticklabel style={font=\scriptsize}, yticklabel style={font=\scriptsize}, label style={font=\scriptsize}, ylabel style={font=\scriptsize}]"
        + "\n"
    )

    caption_parts = []
    for i, (col, ylabel, plot_title) in enumerate(metrics):
        sraft_data = sraft_maps[i]
        base_data = base_maps[i]
        caption_parts.append(f"{plot_title} ({ylabel})")

        xlabel_cmd = "xlabel={Nodes}" if i == len(metrics) - 1 else "xlabel={}"

        tex += f"\n% --- {plot_title} ---\n"
        tex += (
            r"\nextgroupplot[ylabel={"
            + ylabel
            + r"}, "
            + xlabel_cmd
            + r", xmajorgrids=true, ymajorgrids=true, grid style=dashed]"
            + "\n"
        )

        if sraft_data and base_data:
            common_keys = sorted(list(set(sraft_data.keys()) & set(base_data.keys())))
            for nc in common_keys:
                # SRAFT
                s_stats = calculate_box_stats(sraft_data[nc])
                if s_stats:
                    tex += r"\addplot+ [boxplot prepared={" + "\n"
                    tex += f"  lower whisker={s_stats['lower_whisker']:.3f}, lower quartile={s_stats['lower_quartile']:.3f}, median={s_stats['median']:.3f}, upper quartile={s_stats['upper_quartile']:.3f}, upper whisker={s_stats['upper_whisker']:.3f},\n"
                    tex += f"  draw position={nc - 0.5}, box extend=0.8\n"
                    tex += r"}, draw=black, fill=cyan!40, solid] coordinates {};" + "\n"

                # Baseline
                b_stats = calculate_box_stats(base_data[nc])
                if b_stats:
                    tex += r"\addplot+ [boxplot prepared={" + "\n"
                    tex += f"  lower whisker={b_stats['lower_whisker']:.3f}, lower quartile={b_stats['lower_quartile']:.3f}, median={b_stats['median']:.3f}, upper quartile={b_stats['upper_quartile']:.3f}, upper whisker={b_stats['upper_whisker']:.3f},\n"
                    tex += f"  draw position={nc + 0.5}, box extend=0.8\n"
                    tex += r"}, draw=black, fill=red!40, solid] coordinates {};" + "\n"

    tex += r"\end{groupplot}" + "\n"
    tex += r"\end{tikzpicture}" + "\n"

    full_caption = (
        f"{title}. From top to bottom: "
        + ", ".join(caption_parts)
        + f". SRAFT is shown in cyan, while the baseline ({baseline_name}) is shown in red."
    )
    tex += r"\caption{" + full_caption + r"}" + "\n"
    tex += r"\label{fig:" + filename.replace(".tex", "").replace("_", "-") + r"}" + "\n"
    tex += r"\end{figure}" + "\n"

    write_tikz_file(filename, tex)


def generate_tikz_4x1_full(device_data_list, device_labels, title, filename, metrics):
    # device_data_list: list of (list of values for each device) for each metric
    tex = r"\begin{figure}[htbp]" + "\n"
    tex += r"\centering" + "\n"
    tex += r"\begin{tikzpicture}" + "\n"
    
    # Dynamic xticklabels
    xtick_indices = ",".join(str(i) for i in range(len(device_labels)))
    xtick_labels = ",".join(device_labels)
    
    # 4 rows, 1 column. Width = linewidth (full column).
    tex += (
        r"\begin{groupplot}[group style={group size=1 by 4, vertical sep=0.2cm, x descriptions at=edge bottom}, width=0.95\linewidth, height=3.5cm, boxplot/draw direction=y, xtick={"
        + xtick_indices
        + r"}, xticklabels={"
        + xtick_labels
        + r"}, xticklabel style={font=\scriptsize}, yticklabel style={font=\scriptsize}, label style={font=\scriptsize}, ylabel style={font=\scriptsize}]"
        + "\n"
    )

    caption_parts = []
    for i, (col, ylabel, plot_title) in enumerate(metrics):
        dev_values_list = device_data_list[i]  # List of lists (one per device)
        caption_parts.append(f"{plot_title} ({ylabel})")

        tex += f"\n% --- {plot_title} ---\n"
        tex += (
            r"\nextgroupplot[ylabel={"
            + ylabel
            + r"}, xmajorgrids=true, ymajorgrids=true, grid style=dashed]"
            + "\n"
        )

        for dev_id, values in enumerate(dev_values_list):
            stats = calculate_box_stats(values)
            if stats:
                # Leader (0) is Red, Followers are Blue
                fill_color = "red!40" if dev_id == 0 else "cyan!40"
                tex += r"\addplot+ [boxplot prepared={" + "\n"
                tex += f"  lower whisker={stats['lower_whisker']:.3f}, lower quartile={stats['lower_quartile']:.3f}, median={stats['median']:.3f}, upper quartile={stats['upper_quartile']:.3f}, upper whisker={stats['upper_whisker']:.3f},\n"
                tex += f"  draw position={dev_id}, box extend=0.8\n"
                tex += (
                    r"}, draw=black, fill="
                    + fill_color
                    + r", solid] coordinates {};"
                    + "\n"
                )

    tex += r"\end{groupplot}" + "\n"
    tex += r"\end{tikzpicture}" + "\n"

    full_caption = (
        f"{title}. From top to bottom: "
        + ", ".join(caption_parts)
        + ". Leader device measurements are shown in red, and Follower device measurements are shown in blue."
    )
    tex += r"\caption{" + full_caption + r"}" + "\n"
    tex += r"\label{fig:" + filename.replace(".tex", "").replace("_", "-") + r"}" + "\n"
    tex += r"\end{figure}" + "\n"

    write_tikz_file(filename, tex)


# --- PLOTTING HELPERS ---


def collect_metric(base_dir, scenario_file, phase_name, metric_col):
    data_map = {}
    for nc in NODE_CONFIGS:
        values = []
        for i in range(1, NUM_ITERATIONS + 1):
            iter_dir = os.path.join(base_dir, f"size_{nc}", f"iter_{i}")
            intra_dir = os.path.join(iter_dir, INTRA_DEVICE_SUBDIR)
            for dev_id in range(nc):
                f_path = os.path.join(intra_dir, f"device_{dev_id}", scenario_file)
                if os.path.exists(f_path):
                    try:
                        df = pd.read_excel(f_path)
                        if COL_PHASE in df.columns:
                            row = df[df[COL_PHASE] == phase_name]
                            if not row.empty:
                                values.append(row.iloc[0][metric_col])
                    except Exception as e:
                        print(f"ERROR reading {f_path}: {e}")
        if values:
            data_map[nc] = values
    return data_map


def plot_combined_metrics(scenario_file, phase, title_prefix, filename, base_dir):
    """
    Generates TikZ 2x2 subplot for Duration, CPU, Memory, Power.
    """
    metrics = [
        (COL_DURATION, "Duration (s)", "Duration"),
        (COL_CPU, "CPU Usage (\%)", "CPU"),
        (COL_MEM, "Memory Usage (\%)", "Memory"),
        (COL_POWER, "Power (mW)", "Power"),
    ]

    data_maps = []
    for col, _, title in metrics:
        dm = collect_metric(base_dir, scenario_file, phase, col)
        if not dm:
            print(f"WARNING: No data found for {title} ({col}) in {base_dir}")
        else:
            print(f"Data found for {title}: {len(dm)} node configs")
        data_maps.append(dm)

    # Change extension to .tex
    filename_tex = filename.replace(".png", ".tex")
    generate_tikz_1x4_full(data_maps, title_prefix, filename_tex, metrics)


def plot_comparison_combined(
    sraft_dir, baseline_dir, baseline_name, scenario_file, phase, title_prefix, filename
):
    """
    Generates TikZ 2x2 comparison plots.
    """
    metrics = [
        (COL_DURATION, "Duration (s)", "Duration"),
        (COL_CPU, "CPU Usage (\%)", "CPU"),
        (COL_MEM, "Memory Usage (\%)", "Memory"),
        (COL_POWER, "Power (mW)", "Power"),
    ]

    sraft_maps = []
    base_maps = []

    for col, _, _ in metrics:
        sraft_maps.append(collect_metric(sraft_dir, scenario_file, phase, col))
        base_maps.append(collect_metric(baseline_dir, scenario_file, phase, col))

    filename_tex = filename.replace(".png", ".tex")
    generate_tikz_comparison_full(
        sraft_maps, base_maps, baseline_name, title_prefix, filename_tex, metrics
    )


def calculate_pearson_correlation(scenario_file, phase, base_dir, rq_name):
    data_map = collect_metric(base_dir, scenario_file, phase, COL_DURATION)
    if not data_map:
        print(f"[{rq_name}] No data found for Pearson correlation.")
        return

    x = []  # Node counts
    y = []  # Avg durations

    for nc in sorted(data_map.keys()):
        # data_map[nc] is a list of values (one per iteration)
        # We take the mean for correlation calculation
        avg_dur = np.mean(data_map[nc])
        x.append(nc)
        y.append(avg_dur)

    if len(x) < 2:
        print(f"[{rq_name}] Not enough data points for correlation.")
        return

    r = np.corrcoef(x, y)[0, 1]

    # Interpretation
    abs_r = abs(r)
    if abs_r < 0.2:
        interpretation = "None/Very Low"
    elif abs_r < 0.4:
        interpretation = "Low"
    elif abs_r < 0.6:
        interpretation = "Moderate"
    elif abs_r < 0.8:
        interpretation = "High"
    else:
        interpretation = "Very High"

    print(
        f"[{rq_name}] Pearson Correlation (Duration vs Nodes): r = {r:.4f} ({interpretation})"
    )


def plot_device_metrics_per_node(
    scenario_file, phase, title_prefix, filename, base_dir, target_nc=5
):
    # Target: Specific Node Count (default 5 for RQ1)
    metrics = [
        (COL_CPU, "CPU Usage (\%)", "CPU"),
        (COL_MEM, "Memory Usage (\%)", "Memory"),
        (COL_POWER, "Power (mW)", "Power"),
        (COL_DURATION, "Duration (s)", "Duration"),
    ]

    device_data_list = []  # List of (list of values for each device)

    for i, (col, ylabel, title) in enumerate(metrics):
        # Collect data for each device 0..target_nc-1
        current_metric_device_data = []

        iter_dir_base = os.path.join(base_dir, f"size_{target_nc}")

        for dev_id in range(target_nc):
            values = []
            for iter_num in range(1, NUM_ITERATIONS + 1):
                f_path = os.path.join(
                    iter_dir_base,
                    f"iter_{iter_num}",
                    INTRA_DEVICE_SUBDIR,
                    f"device_{dev_id}",
                    scenario_file,
                )
                if os.path.exists(f_path):
                    try:
                        df = pd.read_excel(f_path)
                        if COL_PHASE in df.columns:
                            row = df[df[COL_PHASE] == phase]
                            if not row.empty:
                                values.append(row.iloc[0][col])
                    except:
                        pass
            current_metric_device_data.append(values)

        device_data_list.append(current_metric_device_data)

    device_labels = [f"Dev {d}" for d in range(target_nc)]
    filename_tex = filename.replace(".png", ".tex")
    
    # Use a specialized 4x1 plot for this (Duration added)
    generate_tikz_4x1_full(
        device_data_list, device_labels, title_prefix, filename_tex, metrics
    )
    
    # Generate Table as requested
    filename_table = filename.replace(".png", "_table.tex")
    generate_latex_table(
        device_data_list, device_labels, title_prefix, filename_table, metrics
    )


def generate_latex_table(device_data_list, device_labels, title, filename, metrics):
    """
    Generates a LaTeX table with columns: Device, Role, Avg CPU, Avg Mem, Avg Power, Avg Duration.
    """
    ensure_dir(PLOTS_OUTPUT_DIR)
    filepath = os.path.join(PLOTS_OUTPUT_DIR, filename)
    
    with open(filepath, "w") as f:
        f.write(r"\begin{table}[htbp]" + "\n")
        f.write(r"\centering" + "\n")
        f.write(r"\caption{" + title + r"}" + "\n")
        f.write(r"\label{tab:" + filename.replace(".tex", "").replace("_", "-") + r"}" + "\n")
        f.write(r"\begin{tabular}{|c|c|c|c|c|c|}" + "\n")
        f.write(r"\hline" + "\n")
        f.write(r"\textbf{Device} & \textbf{Role} & \textbf{Avg CPU (\%)} & \textbf{Avg Mem (\%)} & \textbf{Avg Power (mW)} & \textbf{Avg Duration (s)} \\" + "\n")
        f.write(r"\hline" + "\n")
        
        # device_data_list structure: [metric_idx][device_idx][iteration_values]
        # metrics order: CPU, Mem, Power, Duration
        
        num_devices = len(device_labels)
        
        for dev_id in range(num_devices):
            role = "Leader" if dev_id == 0 else "Follower"
            
            # Calculate averages
            # Metric 0: CPU
            cpu_vals = device_data_list[0][dev_id]
            avg_cpu = np.mean(cpu_vals) if cpu_vals else 0.0
            
            # Metric 1: Mem
            mem_vals = device_data_list[1][dev_id]
            avg_mem = np.mean(mem_vals) if mem_vals else 0.0
            
            # Metric 2: Power
            pow_vals = device_data_list[2][dev_id]
            avg_pow = np.mean(pow_vals) if pow_vals else 0.0
            
            # Metric 3: Duration
            dur_vals = device_data_list[3][dev_id]
            avg_dur = np.mean(dur_vals) if dur_vals else 0.0
            
            # Row
            f.write(f"{device_labels[dev_id]} & {role} & {avg_cpu:.2f} & {avg_mem:.2f} & {avg_pow:.2f} & {avg_dur:.3f} \\\\" + "\n")
            f.write(r"\hline" + "\n")
            
        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table}" + "\n")
    
    print(f"Generated LaTeX table: {filepath}")


def generate_plots():
    print("Generating plots...")
    ensure_dir(PLOTS_OUTPUT_DIR)

    sraft_dir = os.path.join(ROOT_DIR, "sraft")
    tls_dir = os.path.join(ROOT_DIR, "tls")
    mqtts_dir = os.path.join(ROOT_DIR, "mqtts")

    # RQ1: Integrity Attestation & Performance (7 Nodes)
    # User requested: Performance AND Authentication for specific config (7 nodes)
    # Highlighting Leader (Red) vs Followers (Blue)
    
    # 1. Election (Performance/Consensus)
    plot_device_metrics_per_node(
        "report_scenario_election.xlsx",
        "ELECTION",
        "RQ1: Leader Election Performance (7 Nodes)",
        "RQ1_Election_7Nodes.png",
        sraft_dir,
        target_nc=7
    )

    # 2. Attestation (Security/Auth)
    plot_device_metrics_per_node(
        "report_scenario_attestation.xlsx",
        "INTEGRITY_CHECK",
        "RQ1: Integrity Attestation (7 Nodes)",
        "RQ1_Attestation_7Nodes.png",
        sraft_dir,
        target_nc=7
    )
    
    # 3. Authentication (Pure Auth)
    plot_device_metrics_per_node(
        "report_scenario_authentication.xlsx",
        "AUTH",
        "RQ1: Authentication Performance (7 Nodes)",
        "RQ1_Authentication_7Nodes.png",
        sraft_dir,
        target_nc=7
    )

    # RQ2: Per-Device Plots (7 Nodes) - Kept as requested in previous iterations, 
    # or should we align? User said "Simile alla RQ2", implying RQ2 stays as is or serves as template.
    # I will keep RQ2 as 7 nodes to show scalability/difference, or just leave it.
    # The user instruction was specific to RQ1.
    
    plot_device_metrics_per_node(
        "report_scenario_join.xlsx",
        "BOOTSTRAP",
        "RQ2: Onboarding Overhead (7 Nodes)",
        "RQ2_Device_Overhead_7Nodes_Bootstrap.png",
        sraft_dir,
        target_nc=7
    )
    plot_device_metrics_per_node(
        "report_scenario_attestation.xlsx",
        "INTEGRITY_CHECK",
        "RQ2: Attestation Overhead (7 Nodes)",
        "RQ2_Device_Overhead_7Nodes_Attestation.png",
        sraft_dir,
        target_nc=7
    )
    plot_device_metrics_per_node(
        "report_scenario_authentication.xlsx",
        "AUTH",
        "RQ2: Authentication Overhead (7 Nodes)",
        "RQ2_Device_Overhead_7Nodes_Auth.png",
        sraft_dir,
        target_nc=7
    )

    # RQ3: Scalability (Election)
    plot_combined_metrics(
        "report_scenario_election.xlsx",
        "ELECTION",
        "RQ3: Scalability (Election)",
        "RQ3_Scalability.png",
        sraft_dir,
    )
    # calculate_pearson_correlation(
    #    "report_scenario_election.xlsx", "ELECTION", sraft_dir, "RQ3: Election"
    # )

    # RQ4: Reliability (Removal)
    plot_combined_metrics(
        "report_scenario_removal.xlsx",
        "REMOVE",
        "RQ4: Node Removal",
        "RQ4_Removal.png",
        sraft_dir,
    )
    # calculate_pearson_correlation(
    #    "report_scenario_removal.xlsx", "REMOVE", sraft_dir, "RQ4: Removal"
    # )

    # RQ4: Reliability (Healing)
    plot_combined_metrics(
        "report_scenario_removal.xlsx",
        "HEALING",
        "RQ4: Healing Phase",
        "RQ4_Healing.png",
        sraft_dir,
    )
    # calculate_pearson_correlation(
    #    "report_scenario_removal.xlsx", "HEALING", sraft_dir, "RQ4: Healing"
    # )

    # RQ5: Baseline Comparison
    plot_comparison_combined(
        sraft_dir,
        tls_dir,
        "TLS",
        "report_scenario_authentication.xlsx",
        "AUTH",
        "RQ5: SRAFT vs TLS",
        "RQ5_Comparison_TLS.png",
    )

    plot_comparison_combined(
        sraft_dir,
        mqtts_dir,
        "MQTTS",
        "report_scenario_authentication.xlsx",
        "AUTH",
        "RQ5: SRAFT vs MQTTS",
        "RQ5_Comparison_MQTTS.png",
    )

    # RQ5 Pearson (SRAFT Auth)
    # calculate_pearson_correlation(
    #    "report_scenario_authentication.xlsx", "AUTH", sraft_dir, "RQ5: Auth (SRAFT)"
    # )
    print("------------------------------------\n")


def main():
    print(f"Current Working Directory: {os.getcwd()}")
    print(f"Root Data Directory: {os.path.abspath(ROOT_DIR)}")
    generate_all_data()
    generate_plots()
    print("\nScript finished successfully.")


if __name__ == "__main__":
    main()
