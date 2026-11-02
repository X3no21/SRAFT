"""
Cost of a successful attestation (RQ1), from the reports exported by the monitoring server for the
attestation scenario (experimental_campaign.py --attestation-test).

Input: <run_dir>/size_<N>/iter_<i>/ with report_attestation_per_device.xlsx (samples of every device in every
attestation, with the duration of the attestation) and attestation_outcomes.json (IP, MAC, and Raft state of
every device, and the outcome of each attestation).

Output, in <out_dir>:
  - attestation_per_device.csv   the samples with the role of the device (Coordinator or other device), and
                                 whether it was the Verifier or the attested Prover of the attestation
  - attestation_summary.csv      n, mean, std, 95% CI, median, min, max of each metric, per role
  - RQ2_Device_Overhead_<N>Nodes_Attestation.tex         boxplots per device (Coordinator first)
  - RQ2_Device_Overhead_<N>Nodes_Attestation_table.tex   mean per role, as in the paper

Usage: python attestation_report.py <run_dir> <out_dir> [-n 7]
"""
import argparse
import glob
import json
import os
import re

import numpy as np
import pandas as pd
from scipy import stats

METRICS = [("duration_s", "Duration (s)"), ("cpu_usage_percent", "CPU Load (\\%)"),
           ("memory_load_percent", "Memory Consumption (\\%)"), ("estimated_power_mw", "Power Consumption (mW)")]


def load(run_dir: str, n_nodes: int) -> pd.DataFrame:
    frames = []
    for iter_dir in sorted(glob.glob(os.path.join(run_dir, f"size_{n_nodes}", "iter_*"))):
        # Raw campaign folder (files in iter_<i>) or results layout (files in iter_<i>/attestation).
        if os.path.isdir(os.path.join(iter_dir, "attestation")):
            iter_dir = os.path.join(iter_dir, "attestation")
        per_device = os.path.join(iter_dir, "report_attestation_per_device.xlsx")
        outcomes = os.path.join(iter_dir, "attestation_outcomes.json")
        if not (os.path.exists(per_device) and os.path.exists(outcomes)):
            print(f"Skipping {iter_dir}: report missing")
            continue
        with open(outcomes) as f:
            info = json.load(f)
        leader = {d["mac"] for d in info["devices"] if d.get("state") == "leader"}
        df = pd.read_excel(per_device)
        df["iteration"] = int(re.search(r"iter_(\d+)", iter_dir).group(1))
        df["role"] = np.where(df["node_mac"].isin(leader), "Coordinator", "Other devices")
        frames.append(df)
    if not frames:
        raise SystemExit(f"No attestation reports under {run_dir}")
    return pd.concat(frames, ignore_index=True)


def describe(values: pd.Series) -> dict:
    v = values.dropna().astype(float)
    n = len(v)
    mean, std = v.mean(), v.std(ddof=1)
    half = stats.t.ppf(0.975, n - 1) * std / np.sqrt(n) if n > 1 else 0.0
    return {"n": n, "mean": mean, "std": std, "ci95_low": mean - half, "ci95_high": mean + half,
            "median": v.median(), "min": v.min(), "max": v.max()}


def box(values: pd.Series) -> dict:
    """Quartiles and whiskers at 1.5 IQR, as in generate_plots.py."""
    v = np.sort(values.dropna().astype(float).values)
    q1, med, q3 = np.percentile(v, [25, 50, 75])
    iqr = q3 - q1
    lo = v[v >= q1 - 1.5 * iqr].min()
    hi = v[v <= q3 + 1.5 * iqr].max()
    return {"lw": lo, "lq": q1, "med": med, "uq": q3, "uw": hi}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("run_dir")
    p.add_argument("out_dir")
    p.add_argument("-n", "--nodes", type=int, default=7)
    args = p.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    df = load(args.run_dir, args.nodes)
    df.to_csv(os.path.join(args.out_dir, "attestation_per_device.csv"), index=False)

    # One duration per attestation; the device metrics are one sample per device and attestation.
    attestations = df.drop_duplicates("operation_id")
    rows = [{"role": "All", "metric": "duration_s", **describe(attestations["duration_s"])}]
    for role, g in df.groupby("role"):
        for col, _ in METRICS[1:]:
            rows.append({"role": role, "metric": col, **describe(g[col])})
    summary = pd.DataFrame(rows)
    summary.to_csv(os.path.join(args.out_dir, "attestation_summary.csv"), index=False)
    print(summary.to_string(index=False))
    outcomes = df.drop_duplicates("operation_id")["outcome"].value_counts().to_dict()
    print(f"Attestations: {len(attestations)} over {df['iteration'].nunique()} iterations, outcomes {outcomes}")

    # Boxes: the Coordinator of each iteration, then the other devices ordered by MAC. For the duration, a
    # device's box holds the attestations in which it was the attested Prover (one per iteration).
    others = sorted(df.loc[df["role"] == "Other devices", "node_mac"].unique())
    groups = [("Coord.", df[df["role"] == "Coordinator"])]
    for i, mac in enumerate(others, 1):
        groups.append((f"Dev {i}", df[(df["node_mac"] == mac) & (df["role"] == "Other devices")]))

    n_boxes = len(groups)
    lines = ["\\begin{figure}[htbp]", "\\centering", "\\begin{tikzpicture}",
             "\\begin{groupplot}[group style={group size=1 by 4, vertical sep=0.2cm, x descriptions at=edge bottom}, "
             "width=0.95\\linewidth, height=4.0cm, boxplot/draw direction=y, "
             f"xtick={{{','.join(str(i) for i in range(n_boxes))}}}, "
             f"xticklabels={{{','.join(name for name, _ in groups)}}}, xticklabel style={{font=\\tiny}}, "
             "yticklabel style={font=\\tiny}, label style={font=\\tiny}, ylabel style={font=\\tiny}]", ""]
    for col, label in METRICS:
        lines.append(f"% --- {label} ---")
        lines.append(f"\\nextgroupplot[ylabel={{{label.split(' (')[0].replace('Consumption', '').strip()} "
                     f"({label.split('(')[1]}}}, xmajorgrids=true, ymajorgrids=true, grid style=dashed]")
        for pos, (name, g) in enumerate(groups):
            if col == "duration_s":
                # Attestations of the devices of this box, i.e., in which the attested Prover is one of them.
                attested = g[g["attested_node_mac"] == g["node_mac"]]
                values = attested.drop_duplicates("operation_id")[col]
            else:
                values = g[col]
            b = box(values)
            fill = "red!40" if pos == 0 else "cyan!40"
            lines += ["\\addplot+ [boxplot prepared={",
                      f"  lower whisker={b['lw']:.3f}, lower quartile={b['lq']:.3f}, median={b['med']:.3f}, "
                      f"upper quartile={b['uq']:.3f}, upper whisker={b['uw']:.3f},",
                      f"  draw position={pos}, box extend=0.8",
                      f"}}, draw=black, fill={fill}, solid] coordinates {{}};"]
        lines.append("")
    lines += ["\\end{groupplot}", "\\end{tikzpicture}",
              f"\\caption{{RQ1: Attestation Overhead ({args.nodes} Devices). From top to bottom: Duration (s), CPU Load (\\%), "
              "Memory Consumption (\\%), and Power Consumption (mW). The leftmost box represents the Coordinator, and the "
              "other boxes the other devices.}",
              f"\\label{{fig:RQ2-Device-Overhead-{args.nodes}Nodes-Attestation}}", "\\end{figure}", ""]
    with open(os.path.join(args.out_dir, f"RQ2_Device_Overhead_{args.nodes}Nodes_Attestation.tex"), "w") as f:
        f.write("\n".join(lines))

    dur = attestations["duration_s"].mean()
    table = ["\\begin{tabular}{lcccc}", "\\hline",
             "\\textbf{Role} & \\textbf{Duration (s)} & \\textbf{CPU (\\%)} & \\textbf{Mem (\\%)} & \\textbf{Power (mW)} \\\\",
             "\\hline"]
    for role in ("Coordinator", "Other devices"):
        g = df[df["role"] == role]
        table.append(f"{role} & {dur:.3f} & {g['cpu_usage_percent'].mean():.2f} & {g['memory_load_percent'].mean():.2f} & "
                     f"{g['estimated_power_mw'].mean():.2f} \\\\")
    table += ["\\hline", "\\end{tabular}", ""]
    with open(os.path.join(args.out_dir, f"RQ2_Device_Overhead_{args.nodes}Nodes_Attestation_table.tex"), "w") as f:
        f.write("\n".join(table))
    print(f"Written to {args.out_dir}")


if __name__ == "__main__":
    main()
