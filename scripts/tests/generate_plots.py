import pandas as pd
import os
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

# --- RAW COLUMN NAMES ---
COL_PHASE = "phase_type"
COL_DURATION = "avg_duration_s"
COL_CPU = "avg_cluster_cpu_perc"
COL_MEM = "avg_cluster_mem_perc"
COL_POWER = "avg_cluster_power_mW"

# --- HELPER FUNCTIONS ---


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


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
            + r"}, xlabel={Number of Devices}, ylabel={"
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
        xlabel_cmd = "xlabel={Devices}" if i == len(metrics) - 1 else "xlabel={}"

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

        xlabel_cmd = "xlabel={Devices}" if i == len(metrics) - 1 else "xlabel={}"

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
        + f". For each network size, the left box represents SRAFT and the right box represents the baseline ({baseline_name})."
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
                # Coordinator (0) is red, the other devices are blue
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
        + ". The leftmost box represents the Coordinator, and the remaining boxes represent the other devices."
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
        (COL_CPU, r"CPU Usage (\%)", "CPU"),
        (COL_MEM, r"Memory Usage (\%)", "Memory"),
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
        (COL_CPU, r"CPU Usage (\%)", "CPU"),
        (COL_MEM, r"Memory Usage (\%)", "Memory"),
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
        (COL_CPU, r"CPU Usage (\%)", "CPU"),
        (COL_MEM, r"Memory Usage (\%)", "Memory"),
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
    Generates a LaTeX table with columns: Device, Role, CPU, Mem, Power, Duration (mean +- standard deviation).
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
        f.write(r"\textbf{Device} & \textbf{Role} & \textbf{CPU (\%)} & \textbf{Mem (\%)} & \textbf{Power (mW)} & \textbf{Duration (s)} \\" + "\n")
        f.write(r"\hline" + "\n")

        # device_data_list structure: [metric_idx][device_idx][iteration_values]
        # metrics order: CPU, Mem, Power, Duration; every cell is mean +- standard deviation over the runs
        def cell(values, digits):
            if not values:
                return "--"
            std = np.std(values, ddof=1) if len(values) > 1 else 0.0
            return f"{np.mean(values):.{digits}f} $\\pm$ {std:.{digits}f}"

        for dev_id in range(len(device_labels)):
            role = "Coordinator" if dev_id == 0 else "Device"
            cpu, mem, pw, dur = (device_data_list[m][dev_id] for m in range(4))
            f.write(f"{device_labels[dev_id]} & {role} & {cell(cpu, 2)} & {cell(mem, 2)} & {cell(pw, 2)} & {cell(dur, 3)} \\\\" + "\n")
            f.write(r"\hline" + "\n")

        f.write(r"\end{tabular}" + "\n")
        f.write(r"\end{table}" + "\n")
    
    print(f"Generated LaTeX table: {filepath}")


def generate_plots():
    print("Generating plots...")
    ensure_dir(PLOTS_OUTPUT_DIR)

    sraft_dir = os.path.join(ROOT_DIR, "sraft")
    tls_dir = os.path.join(ROOT_DIR, "tls")
    tls_resumed_dir = os.path.join(ROOT_DIR, "tls_resumed")
    mqtts_dir = os.path.join(ROOT_DIR, "mqtts")

    # RQ1: Integrity Attestation & Performance (7 Nodes)
    # User requested: Performance AND Authentication for specific config (7 nodes)
    # Highlighting the Coordinator (red) vs the other devices (blue)
    
    # 1. Election (Performance/Consensus)
    plot_device_metrics_per_node(
        "report_scenario_election.xlsx",
        "ELECTION",
        "RQ1: Coordinator Selection Performance (7 Devices)",
        "RQ1_Election_7Nodes.png",
        sraft_dir,
        target_nc=7
    )

    # 2. Attestation (Security/Auth)
    plot_device_metrics_per_node(
        "report_scenario_attestation.xlsx",
        "INTEGRITY_CHECK",
        "RQ1: Integrity Attestation (7 Devices)",
        "RQ1_Attestation_7Nodes.png",
        sraft_dir,
        target_nc=7
    )
    
    # 3. Authentication (Pure Auth)
    plot_device_metrics_per_node(
        "report_scenario_authentication.xlsx",
        "AUTH",
        "RQ1: Authentication Performance (7 Devices)",
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
        "RQ2: Onboarding Overhead (7 Devices)",
        "RQ2_Device_Overhead_7Nodes_Bootstrap.png",
        sraft_dir,
        target_nc=7
    )
    plot_device_metrics_per_node(
        "report_scenario_attestation.xlsx",
        "INTEGRITY_CHECK",
        "RQ2: Attestation Overhead (7 Devices)",
        "RQ2_Device_Overhead_7Nodes_Attestation.png",
        sraft_dir,
        target_nc=7
    )
    plot_device_metrics_per_node(
        "report_scenario_authentication.xlsx",
        "AUTH",
        "RQ2: Authentication Overhead (7 Devices)",
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
        "RQ4: Device Removal",
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

    # TLS with session resumption, measured only by the campaigns that include it.
    if os.path.isdir(tls_resumed_dir):
        plot_comparison_combined(
            sraft_dir,
            tls_resumed_dir,
            "TLS (resumed)",
            "report_scenario_authentication.xlsx",
            "AUTH",
            "RQ5: SRAFT vs TLS with session resumption",
            "RQ5_Comparison_TLS_Resumed.png",
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
    generate_plots()
    print("\nScript finished successfully.")


if __name__ == "__main__":
    main()
