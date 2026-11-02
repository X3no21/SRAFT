"""
Statistics of the experimental campaign: dispersion, confidence intervals, tests, and the new metrics.

    python statistics_report.py [--root experimental_results] [--results experiment_results]

It reads the per-device reports of the campaign (the same files as generate_plots.py) and writes, under
<root>/statistics/:
  - raw_<scenario>.csv          every measured value, one row per device, run, and network size
  - summary_<scenario>.csv      per network size: n, mean, standard deviation, 95% confidence interval
                                (Student's t), median, min, max of duration, CPU, memory, and power
  - scaling.csv                 linear fit of the mean duration against the network size (slope, R^2)
  - comparison.csv              SRAFT against each baseline, per network size: Welch's t-test,
                                Mann-Whitney U test, and Cohen's d of the authentication duration
  - detection.tex / .csv        detection rate of the attestation (from <results>/hatt_detection_*)
  - faults.tex / .csv           recovery from faults that the network detects by itself (from <results>/fault_*)
"""
import argparse
import glob
import json
import math
import os

import numpy as np
import pandas as pd
from scipy import stats

from generate_plots import (COL_CPU, COL_DURATION, COL_MEM, COL_PHASE, COL_POWER, INTRA_DEVICE_SUBDIR,
                            NODE_CONFIGS, NUM_ITERATIONS)

METRICS = {"duration_s": COL_DURATION, "cpu_perc": COL_CPU, "memory_perc": COL_MEM, "power_mw": COL_POWER}
# (label, report file, phase, implementation folder)
SCENARIOS = [
    ("authentication_sraft", "report_scenario_authentication.xlsx", "AUTH", "sraft"),
    ("authentication_tls", "report_scenario_authentication.xlsx", "AUTH", "tls"),
    ("authentication_tls_resumed", "report_scenario_authentication.xlsx", "AUTH", "tls_resumed"),
    ("authentication_mqtts", "report_scenario_authentication.xlsx", "AUTH", "mqtts"),
    ("attestation", "report_scenario_attestation.xlsx", "INTEGRITY_CHECK", "sraft"),
    ("election", "report_scenario_election.xlsx", "ELECTION", "sraft"),
    ("join", "report_scenario_join.xlsx", "BOOTSTRAP", "sraft"),
    ("removal", "report_scenario_removal.xlsx", "REMOVE", "sraft"),
    ("healing", "report_scenario_removal.xlsx", "HEALING", "sraft"),
]


def describe(values):
    """n, mean, standard deviation, 95% confidence interval of the mean (Student's t), median, min, max."""
    v = np.asarray([x for x in values if x is not None and not (isinstance(x, float) and math.isnan(x))], dtype=float)
    n = len(v)
    if n == 0:
        return {"n": 0}
    mean = float(v.mean())
    std = float(v.std(ddof=1)) if n > 1 else 0.0
    half = float(stats.t.ppf(0.975, n - 1) * std / math.sqrt(n)) if n > 1 else 0.0
    return {"n": n, "mean": mean, "std": std, "ci95_low": mean - half, "ci95_high": mean + half,
            "median": float(np.median(v)), "min": float(v.min()), "max": float(v.max())}


def collect_raw(root, label, report, phase, impl):
    rows = []
    base = os.path.join(root, impl)
    for nc in NODE_CONFIGS:
        for it in range(1, NUM_ITERATIONS + 1):
            intra = os.path.join(base, f"size_{nc}", f"iter_{it}", INTRA_DEVICE_SUBDIR)
            for dev in range(nc):
                path = os.path.join(intra, f"device_{dev}", report)
                if not os.path.exists(path):
                    continue
                try:
                    df = pd.read_excel(path)
                except Exception as e:
                    print(f"cannot read {path}: {e}")
                    continue
                if COL_PHASE not in df.columns:
                    continue
                for _, r in df[df[COL_PHASE] == phase].iterrows():
                    row = {"scenario": label, "network_size": nc, "run": it, "device": dev,
                           "role": "coordinator" if dev == 0 else "device"}
                    for name, col in METRICS.items():
                        row[name] = r.get(col)
                    rows.append(row)
    return pd.DataFrame(rows)


def summarize(raw):
    out = []
    for nc, group in raw.groupby("network_size"):
        for name in METRICS:
            d = describe(group[name].tolist())
            out.append({"network_size": nc, "metric": name, **d})
    return pd.DataFrame(out)


def scaling(summaries):
    rows = []
    for label, summary in summaries.items():
        s = summary[(summary.metric == "duration_s") & (summary.n > 0)]
        if len(s) < 3:
            continue
        fit = stats.linregress(s.network_size, s["mean"])
        rows.append({"scenario": label, "slope_s_per_device": fit.slope, "intercept_s": fit.intercept,
                     "r_squared": fit.rvalue ** 2, "p_value": fit.pvalue, "sizes": len(s)})
    return pd.DataFrame(rows)


def comparison(raws):
    rows = []
    sraft = raws.get("authentication_sraft")
    for base in ("authentication_tls", "authentication_tls_resumed", "authentication_mqtts"):
        other = raws.get(base)
        if sraft is None or other is None or sraft.empty or other.empty:
            continue
        for nc in sorted(set(sraft.network_size) & set(other.network_size)):
            a = sraft[sraft.network_size == nc].duration_s.dropna().astype(float)
            b = other[other.network_size == nc].duration_s.dropna().astype(float)
            if len(a) < 2 or len(b) < 2:
                continue
            t = stats.ttest_ind(a, b, equal_var=False)
            u = stats.mannwhitneyu(a, b, alternative="two-sided")
            pooled = math.sqrt(((len(a) - 1) * a.var(ddof=1) + (len(b) - 1) * b.var(ddof=1)) / (len(a) + len(b) - 2))
            rows.append({"baseline": base.split("_", 1)[1], "network_size": nc, "n_sraft": len(a), "n_baseline": len(b),
                         "mean_sraft_s": a.mean(), "mean_baseline_s": b.mean(), "ratio": a.mean() / b.mean(),
                         "welch_t": t.statistic, "welch_p": t.pvalue, "mannwhitney_p": u.pvalue,
                         "cohens_d": (a.mean() - b.mean()) / pooled if pooled else float("nan")})
    return pd.DataFrame(rows)


def detection_table(results, out_dir):
    rows = []
    for path in sorted(glob.glob(os.path.join(results, "hatt_detection_*", "detection.csv"))):
        rows.append(pd.read_csv(path))
    if not rows:
        return
    df = pd.concat(rows).drop_duplicates(subset="tampered_bytes", keep="last").sort_values("tampered_bytes")
    df.to_csv(os.path.join(out_dir, "detection.csv"), index=False)
    lines = [r"\begin{tabular}{rrccc}", r"\hline",
             r"\textbf{Modified bytes} & \textbf{Differing bits} & \textbf{Detected} & \textbf{Measured rate (95\% CI)} & \textbf{Predicted} \\",
             r"\hline"]
    for _, r in df.iterrows():
        label = "0 (control)" if r.tampered_bytes == 0 else str(int(r.tampered_bytes))
        lines.append(f"{label} & {int(r.changed_bits)} & {int(r.detected)}/{int(r.attestations)} & "
                     f"{r.measured_rate:.3f} ({r.ci95_low:.3f}--{r.ci95_high:.3f}) & {r.predicted_rate:.3f} \\\\")
    lines += [r"\hline", r"\end{tabular}"]
    with open(os.path.join(out_dir, "detection.tex"), "w") as f:
        f.write("\n".join(lines) + "\n")


def faults_table(results, out_dir, pattern="fault_*"):
    runs = []
    for path in sorted(glob.glob(os.path.join(results, pattern, "fault_result.json"))):
        with open(path) as f:
            r = json.load(f)
        r["campaign"] = os.path.basename(os.path.dirname(path))
        # Scenarios below the minimum network size (2f+1 devices for f faults) are not run.
        if "skipped" not in r:
            runs.append(r)
    if not runs:
        return
    rows = []
    for r in runs:
        rows.append({"campaign": r["campaign"], "fault": r["fault"], "faulty_devices": r["faulty_devices"],
                     "coordinator_included": r["coordinator_included"], "network_size": r["network_size"],
                     "new_coordinator_s": r["times"].get("new_coordinator_s"), "removed_s": r["times"].get("removed_s"),
                     "restored_s": r["times"].get("restored_s"), "authenticated_after": r["authenticated_after"],
                     "survivors": r["survivors"]})
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(out_dir, "faults_raw.csv"), index=False)
    keys = ["fault", "faulty_devices", "coordinator_included", "network_size"]
    summary = []
    for key, g in df.groupby(keys):
        entry = dict(zip(keys, key))
        for col in ("new_coordinator_s", "restored_s"):
            d = describe(g[col].dropna().tolist())
            entry[f"{col}_n"] = d["n"]
            entry[f"{col}_mean"] = d.get("mean")
            entry[f"{col}_std"] = d.get("std")
        entry["recovered"] = int(g.restored_s.notna().sum())
        entry["runs"] = len(g)
        entry["authenticated"] = f"{int(g.authenticated_after.sum())}/{int(g.survivors.sum())}"
        summary.append(entry)
    sdf = pd.DataFrame(summary)
    sdf.to_csv(os.path.join(out_dir, "faults.csv"), index=False)

    def fmt(mean, std, n):
        if mean is None or (isinstance(mean, float) and math.isnan(mean)):
            return "--"
        return f"{mean:.0f}" if n <= 1 else f"{mean:.0f} $\\pm$ {std:.0f}"

    lines = [r"\begin{tabular}{lccccc}", r"\hline",
             r"\textbf{Fault} & \textbf{Coordinator} & \textbf{Runs} & \textbf{New Coordinator (s)} & \textbf{Recovered (s)} & \textbf{Authenticated} \\",
             r"\hline"]
    for _, r in sdf.iterrows():
        fault = f"{int(r.faulty_devices)} crashed" if r.fault == "crash" else f"{int(r.faulty_devices)} altered"
        lines.append(f"{fault} & {'yes' if r.coordinator_included else 'no'} & {int(r.recovered)}/{int(r.runs)} & "
                     f"{fmt(r.new_coordinator_s_mean, r.new_coordinator_s_std, r.new_coordinator_s_n) if r.coordinator_included else '--'} & "
                     f"{fmt(r.restored_s_mean, r.restored_s_std, r.restored_s_n)} & {r.authenticated} \\\\")
    lines += [r"\hline", r"\end{tabular}"]
    with open(os.path.join(out_dir, "faults.tex"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Statistics of the experimental campaign")
    parser.add_argument("--root", default="experimental_results", help="results of the campaign (as generate_plots.py)")
    parser.add_argument("--results", default="experiment_results", help="results of the pipeline runs")
    parser.add_argument("--fault-runs", default="fault_*", help="folders of the fault runs to include (glob)")
    parser.add_argument("--out", default=None, help="output folder (default: <root>/statistics)")
    args = parser.parse_args()
    out_dir = args.out or os.path.join(args.root, "statistics")
    os.makedirs(out_dir, exist_ok=True)

    raws, summaries = {}, {}
    for label, report, phase, impl in SCENARIOS:
        raw = collect_raw(args.root, label, report, phase, impl)
        if raw.empty:
            continue
        raws[label] = raw
        raw.to_csv(os.path.join(out_dir, f"raw_{label}.csv"), index=False)
        summaries[label] = summarize(raw)
        summaries[label].to_csv(os.path.join(out_dir, f"summary_{label}.csv"), index=False)
    if summaries:
        scaling(summaries).to_csv(os.path.join(out_dir, "scaling.csv"), index=False)
        comparison(raws).to_csv(os.path.join(out_dir, "comparison.csv"), index=False)
    detection_table(args.results, out_dir)
    faults_table(args.results, out_dir, args.fault_runs)
    print(f"Statistics written to {out_dir}")


if __name__ == "__main__":
    main()
