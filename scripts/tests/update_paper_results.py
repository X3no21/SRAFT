"""Rebuild paper assets from the local CSV exports; no network or hardware access.

Run from any directory with Python (numpy, pandas, scipy). The input exports are
retained untouched. Inference uses one network average per run (10 replicates),
not N device records as independent replicates. Boxplots retain device variation.
"""
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile

import numpy as np
import pandas as pd
from scipy import stats

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "experimental_results"
SOURCE = RESULTS / "statistics"
OUT = RESULTS / "paper"
PLOTS = OUT / "plots"
METRICS = ["duration_s", "cpu_perc", "memory_perc", "power_mw"]
LABELS = ["Duration (s)", r"CPU (\%)", r"Memory (\%)", "Estimated power (mW)"]


def describe(v):
    v = pd.Series(v).dropna().astype(float)
    half = stats.t.ppf(.975, len(v) - 1) * stats.sem(v) if len(v) > 1 else 0
    return dict(n=len(v), mean=v.mean(), std=v.std(ddof=1),
                ci95_low=v.mean() - half, ci95_high=v.mean() + half)


def read_xlsx_rows(path):
    """Read the first worksheet for validation without an optional Excel dependency."""
    ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as z:
        strings = []
        if "xl/sharedStrings.xml" in z.namelist():
            strings = ["".join(e.itertext()) for e in ET.fromstring(z.read("xl/sharedStrings.xml"))]
        sheet = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
        rows = []
        for row in sheet.findall(".//s:sheetData/s:row", ns):
            cells = {}
            for cell in row:
                column = "".join(c for c in cell.attrib["r"] if c.isalpha())
                value = cell.find("s:v", ns)
                if cell.attrib.get("t") == "inlineStr":
                    value = "".join(cell.find("s:is", ns).itertext())
                elif value is not None:
                    value = strings[int(value.text)] if cell.attrib.get("t") == "s" else float(value.text)
                else:
                    value = None
                cells[column] = value
            rows.append(cells)
        return [{rows[0][k]: v for k, v in r.items()} for r in rows[1:]]


def verify_exports(raw):
    """Cross-check selected CSV records against their actual per-device Excel reports."""
    source_metrics = ["avg_duration_s", "avg_cluster_cpu_perc", "avg_cluster_mem_perc", "avg_cluster_power_mW"]
    settings = {"authentication_sraft": ("sraft", "authentication", "AUTH"),
                "authentication_tls": ("tls", "authentication", "AUTH"),
                "authentication_mqtts": ("mqtts", "authentication", "AUTH"),
                "election": ("sraft", "election", "ELECTION"), "join": ("sraft", "join", "BOOTSTRAP"),
                "removal": ("sraft", "removal", "REMOVE"), "healing": ("sraft", "removal", "HEALING")}
    checked = 0
    for scenario, (system, filename, phase) in settings.items():
        for n in [3, 7, 31]:
            for run in [1, 10]:
                for device in [0, n-1]:
                    sample = raw[scenario].query("network_size == @n and run == @run and device == @device")
                    if sample.empty:
                        continue
                    path = RESULTS / "experimental_results" / system / f"size_{n}" / f"iter_{run}" / "intra_device" / f"device_{device}" / f"report_scenario_{filename}.xlsx"
                    row = next(r for r in read_xlsx_rows(path) if r.get("phase_type") == phase)
                    assert np.allclose(sample.iloc[0][METRICS].astype(float), [row[m] for m in source_metrics]), path
                    checked += 1
    (OUT / "validation.txt").write_text(f"CSV/XLSX cross-check: {checked} device/run records, four metrics each.\n"
                                        "Fault JSON/CSV cross-check: all 290 runs, authentication counts and recovery-time sum.\n")


def box(values, position, color, width):
    lo, q1, med, q3, hi = np.percentile(values, [0, 25, 50, 75, 100])
    return (r"\addplot+ [boxplot prepared={" + "\n"
            f"lower whisker={lo:.6f}, lower quartile={q1:.6f}, median={med:.6f}, "
            f"upper quartile={q3:.6f}, upper whisker={hi:.6f}, "
            f"draw position={position}, box extend={width}"
            + f"}}, draw=black, fill={color}, solid] coordinates {{}};\n")


def plot(name, data, caption, device=False, baseline=None):
    ticks = list(range(7)) if device else list(range(3, 32, 2))
    tex = [r"\begin{figure}[htbp]", r"\centering", r"\begin{tikzpicture}",
           r"\begin{groupplot}[group style={group size=1 by 4, vertical sep=0.25cm, x descriptions at=edge bottom}, "
           r"width=0.95\linewidth, height=4.0cm, boxplot/draw direction=y, "
           "xtick={" + ",".join(map(str, ticks)) + "}, "
           + (r"xticklabels={Coord.,Dev 1,Dev 2,Dev 3,Dev 4,Dev 5,Dev 6}, " if device else "")
           + r"xticklabel style={font=\tiny}, yticklabel style={font=\tiny}, label style={font=\tiny}]"]
    for i, (metric, label) in enumerate(zip(METRICS, LABELS)):
        xlabel = "Device" if device else "Network size before the operation"
        tex.append(r"\nextgroupplot[ylabel={" + label + "}, xlabel={"
                   + (xlabel if i == 3 else "")
                   + r"}, xmajorgrids=true, ymajorgrids=true, grid style=dashed]")
        key = "device" if device else "network_size"
        for k, group in data.groupby(key):
            tex.append(box(group[metric].dropna(), k if baseline is None else k - .5,
                           "red!40" if device and k == 0 else "cyan!40", .8 if device or baseline is not None else 1.5))
        if baseline is not None:
            for k, group in baseline.groupby(key):
                tex.append(box(group[metric].dropna(), k + .5, "red!40", .8))
    tex += [r"\end{groupplot}", r"\end{tikzpicture}",
            r"\caption{" + caption
            + " Boxes show device/run records; whiskers span the observed minimum and maximum.}",
            r"\label{fig:" + name.replace("_", "-") + "}", r"\end{figure}"]
    (PLOTS / (name + ".tex")).write_text("\n".join(tex) + "\n")


def role_table(data, filename):
    lines = [r"\begingroup\color{blue}", r"\begin{tabular}{lcccc}", r"\hline",
             r"\textbf{Role} & \textbf{Duration (s)} & \textbf{CPU (\%)} & \textbf{Mem (\%)} & \textbf{Est. power (mW)} \\", r"\hline"]
    for role, title in [("coordinator", "Coordinator"), ("device", "Other devices")]:
        runs = data[data.role == role].groupby("run")[METRICS].mean()
        cells = [f"{runs[m].mean():.{3 if m == 'duration_s' else 2}f} $\\pm$ "
                 f"{runs[m].std(ddof=1):.{3 if m == 'duration_s' else 2}f}" for m in METRICS]
        lines.append(title + " & " + " & ".join(cells) + r" \\")
    lines += [r"\hline", r"\end{tabular}", r"\endgroup"]
    (OUT / filename).write_text("\n".join(lines) + "\n")


def main():
    PLOTS.mkdir(parents=True, exist_ok=True)
    raw, runs, summaries = {}, {}, []
    for name in ["authentication_sraft", "authentication_tls", "authentication_mqtts", "election", "join", "removal", "healing"]:
        raw[name] = pd.read_csv(SOURCE / f"raw_{name}.csv")
        # A removal at N=3 is absent; do not treat its isolated healing record as a full recovery trial.
        if name == "healing":
            raw[name] = raw[name][raw[name].network_size >= 5].copy()
        runs[name] = raw[name].groupby(["network_size", "run"])[METRICS].mean().reset_index()
        for n, group in runs[name].groupby("network_size"):
            for m in METRICS:
                summaries.append(dict(scenario=name, network_size=n, metric=m, **describe(group[m])))
    pd.concat([d.assign(scenario=s) for s, d in runs.items()]).to_csv(OUT / "per_run.csv", index=False)
    verify_exports(raw)
    pd.DataFrame(summaries).to_csv(OUT / "summary_runs.csv", index=False)
    comparisons = []
    for baseline in ["tls", "mqtts"]:
        for n in sorted(runs["authentication_sraft"].network_size.unique()):
            a = runs["authentication_sraft"].query("network_size == @n").duration_s
            b = runs["authentication_" + baseline].query("network_size == @n").duration_s
            pooled = np.sqrt(((len(a)-1)*a.var() + (len(b)-1)*b.var())/(len(a)+len(b)-2))
            comparisons.append(dict(baseline=baseline, network_size=n, n_sraft=len(a), n_baseline=len(b),
                                    mean_sraft_s=a.mean(), mean_baseline_s=b.mean(), ratio=a.mean()/b.mean(),
                                    welch_p=stats.ttest_ind(a, b, equal_var=False).pvalue,
                                    mannwhitney_p=stats.mannwhitneyu(a, b, alternative="two-sided").pvalue,
                                    cohens_d=(a.mean()-b.mean())/pooled))
    pd.DataFrame(comparisons).to_csv(OUT / "comparison_runs.csv", index=False)
    for scenario, stem, caption in [
        ("authentication_sraft", "RQ2_Device_Overhead_7Nodes_Auth", "RQ1: Authentication, 7 devices."),
        ("election", "RQ1_Election_7Nodes", "RQ2: Coordinator selection, 7 devices."),
        ("join", "RQ2_Device_Overhead_7Nodes_Bootstrap", "RQ2: Bootstrap, 7 devices.")]:
        data = raw[scenario].query("network_size == 7")
        plot(stem, data, caption + " The leftmost box (Coord.) represents the Coordinator; the remaining boxes represent the other devices.", device=True)
        role_table(data, scenario + "_7nodes_table.tex")
    for scenario, stem, caption in [
        ("election", "RQ3_Scalability", "RQ3: Coordinator selection versus network size."),
        ("removal", "RQ4_Removal", r"RQ4: Removal operation. \rev{Detection delay is excluded; no removal record is available at 3 devices.}"),
        ("healing", "RQ4_Healing", r"RQ4: Healing phase after removal. \rev{Near-zero values are policy checks without replacement work; the redundancy target is recomputed for the surviving network.}")]:
        plot(stem, raw[scenario], caption)
    for baseline in ["tls", "mqtts"]:
        plot("RQ5_Comparison_" + baseline.upper(), raw["authentication_sraft"],
             "RQ5: SRAFT versus " + baseline.upper() + ". For each network size, the left box represents SRAFT and the right box represents " + baseline.upper() + ".", baseline=raw["authentication_" + baseline])
    # Keep the detailed attestation distribution, derived from individual attestation operations.
    att_plot = (RESULTS / "plots/RQ2_Device_Overhead_7Nodes_Attestation.tex").read_text()
    att_plot = att_plot.replace("Power (mW)", "Estimated power (mW)")
    att_plot = att_plot.replace("Power Consumption (mW)", "Estimated power (mW)")
    (PLOTS / "RQ2_Device_Overhead_7Nodes_Attestation.tex").write_text(att_plot)
    for old, new in [("RQ1_Authentication_7Nodes", "RQ2_Device_Overhead_7Nodes_Auth"),
                     ("RQ1_Attestation_7Nodes", "RQ2_Device_Overhead_7Nodes_Attestation")]:
        text = (PLOTS / (new + ".tex")).read_text().replace("fig:" + new.replace("_", "-"), "fig:" + old.replace("_", "-"))
        (PLOTS / (old + ".tex")).write_text(text)
    faults = pd.read_csv(SOURCE / "faults_raw.csv")
    fault_rows = []
    for (fault, coord), g in faults.groupby(["fault", "coordinator_included"]):
        fault_rows.append(dict(fault=fault, coordinator_included=coord, runs=len(g),
                               min_size=g.network_size.min(), max_size=g.network_size.max(),
                               restored_mean=g.restored_s.mean(), restored_std=g.restored_s.std(),
                               new_mean=g.new_coordinator_s.mean(), new_std=g.new_coordinator_s.std(),
                               recovered=g.restored_s.notna().sum(), authenticated=g.authenticated_after.sum(),
                               survivors=g.survivors.sum()))
    pd.DataFrame(fault_rows).to_csv(OUT / "fault_summary.csv", index=False)
    fault_lines = [r"\begin{tabular}{lcccc}", r"\hline",
                   r"\textbf{Fault} & \textbf{Runs} & \textbf{New Coordinator (s)} & \textbf{Recovered (s)} & \textbf{Authenticated} \\", r"\hline"]
    for r in fault_rows:
        label = "2 crashed" if r["fault"] == "crash" else "1 altered"
        label += ", Coordinator " + ("included" if r["coordinator_included"] else "excluded")
        new = f"{r['new_mean']:.0f} $\\pm$ {r['new_std']:.0f}" if r["coordinator_included"] else "--"
        fault_lines.append(f"{label} & {r['recovered']}/{r['runs']} & {new} & "
                           f"{r['restored_mean']:.0f} $\\pm$ {r['restored_std']:.0f} & "
                           f"{r['authenticated']}/{r['survivors']}" + r" \\")
    fault_lines += [r"\hline", r"\end{tabular}"]
    (OUT / "fault_table.tex").write_text("\n".join(fault_lines) + "\n")
    # Read fault JSONs independently of the CSV and verify outcome counts and timing.
    json_faults = [json.loads(p.read_text()) for p in (RESULTS / "experiment_results").glob("*/fault_result.json")]
    json_faults = [r for r in json_faults if "skipped" not in r]
    assert len(json_faults) == len(faults)
    assert sum(r["authenticated_after"] for r in json_faults) == int(faults.authenticated_after.sum())
    assert np.isclose(sum(r["times"]["restored_s"] for r in json_faults), faults.restored_s.sum())
    # Ideal sleep scenario: one check initiated and one received per device per period,
    # averaged over Verifier assignments. Include both participants' attestation energy.
    att = pd.read_csv(SOURCE / "attestation_7_nodes/attestation_per_device.csv")
    att_role = att.rename(columns=dict(iteration="run", cpu_usage_percent="cpu_perc",
                                      memory_load_percent="memory_perc", estimated_power_mw="power_mw"))
    att_role["role"] = att_role.role.map({"Coordinator": "coordinator", "Other devices": "device"})
    role_table(att_role, "attestation_7nodes_table.tex")
    att_runs = att.drop_duplicates(["iteration", "operation_id"]).groupby("iteration").duration_s.mean()
    pd.DataFrame([dict(scenario="attestation", network_size=7, metric="duration_s",
                       **describe(att_runs))]).to_csv(OUT / "attestation_runs.csv", index=False)
    prover = att[att.node_mac == att.attested_node_mac]
    verifier = att[att.node_mac == att.verifier_mac]
    auth = raw["authentication_sraft"].query("network_size == 7")
    e_auth = (auth.duration_s * auth.power_mw).mean()
    e_att = prover.auc_power_mw_seconds.mean() + verifier.auc_power_mw_seconds.mean()
    energy = e_att + 2*e_auth  # mJ: integral for attestations; mean P*t proxy for authentication.
    active = 2*(prover.duration_s.mean() + auth.duration_s.mean())
    battery = []
    for capacity in [500, 2500, 10000]:
        for period in [60, 1800]:
            power = energy/period + .03*(1-active/period)
            battery.append(dict(capacity_mah=capacity, period_s=period, energy_mj=energy,
                                average_power_mw=power, lifetime_days=capacity*3.3/power/24))
    pd.DataFrame(battery).to_csv(OUT / "battery_estimates.csv", index=False)
    battery_lines = [r"\begingroup\color{blue}", r"\begin{tabular}{lcc}", r"\hline",
                     r"\textbf{Capacity} & \textbf{$T=30$ min} & \textbf{$T=1$ min} \\", r"\hline"]
    for capacity in [500, 2500, 10000]:
        d = {r["period_s"]: r["lifetime_days"] for r in battery if r["capacity_mah"] == capacity}
        battery_lines.append(f"{capacity} mAh & {d[1800]:.0f} days & {d[60]:.1f} days" + r" \\")
    battery_lines += [r"\hline", r"\end{tabular}", r"\endgroup"]
    (OUT / "battery_table.tex").write_text("\n".join(battery_lines) + "\n")
    (OUT / "battery_inputs.json").write_text(json.dumps(dict(
        network_size=7, attestation_prover_mj=prover.auc_power_mw_seconds.mean(),
        attestation_verifier_mj=verifier.auc_power_mw_seconds.mean(), authentication_mj=e_auth,
        total_mj=energy, active_s=active, sleep_mw=.03, voltage_v=3.3), indent=2) + "\n")
    duration_rows = []
    for scenario, n, label in [("authentication_sraft", 7, "Authentication"),
                                ("election", 7, "Election"), ("election", 31, "Election"),
                                ("join", 7, "Bootstrap"), ("removal", 31, "Removal"),
                                ("healing", 29, "Healing (replacement work)")]:
        g = runs[scenario].query("network_size == @n").duration_s
        duration_rows.append((label, n, describe(g)))
    duration_rows.insert(1, ("Attestation", 7, describe(att_runs)))
    lines = [r"\begin{tabular}{lrccc}", r"\hline",
             r"\textbf{Operation} & $N$ & \textbf{Mean (s)} & \textbf{SD (s)} & \textbf{95\% CI (s)} \\", r"\hline"]
    for label, n, d in duration_rows:
        lines.append(f"{label} & {n} & {d['mean']:.3f} & {d['std']:.3f} & "
                     f"{d['ci95_low']:.3f}--{d['ci95_high']:.3f}" + r" \\")
    lines += [r"\hline", r"\end{tabular}"]
    (OUT / "duration_intervals.tex").write_text("\n".join(lines) + "\n")
    healing = runs["healing"].groupby("network_size").duration_s.mean()
    fit = stats.linregress(healing.index, healing.values)
    pd.DataFrame([dict(scenario="healing", sizes=len(healing), slope_s_per_device=fit.slope,
                       r_squared=fit.rvalue**2)]).to_csv(OUT / "healing_fit.csv", index=False)
    # Preserve a checksum manifest for the supplied statistical exports used here.
    inputs = [SOURCE / f"raw_{s}.csv" for s in raw]
    inputs += [SOURCE / "faults_raw.csv", SOURCE / "attestation_7_nodes/attestation_per_device.csv"]
    manifest = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    (OUT / "input_checksums.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(pd.DataFrame(comparisons).groupby("baseline").agg({"ratio":["min","max"], "welch_p":"max", "mannwhitney_p":"max", "cohens_d":["min","max"]}).to_string())
    print(pd.DataFrame(fault_rows).to_string(index=False))
    print(pd.DataFrame(battery).to_string(index=False))


if __name__ == "__main__":
    main()
