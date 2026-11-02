"""Export per-network details for scenarios already collected by statistics_report.py.

Usage: python scenario_statistics.py <statistics_dir> [--out <destination>]

Each <scenario>_<N>_nodes folder contains the per-device/iteration records, a
summary by role, and a LaTeX table. The input values are iteration averages;
the summary's n counts device/iteration records, not individual operations.
Attestation keeps its separate reports based on individual operations.
"""
import argparse
from pathlib import Path

import pandas as pd

from statistics_report import METRICS, describe


SCENARIOS = (
    "authentication_sraft", "authentication_tls", "authentication_mqtts",
    "election", "join", "removal", "healing",
)
ROLE_NAMES = {"coordinator": "Coordinator", "device": "Other devices"}


def export_details(statistics_dir: Path, destination: Path) -> int:
    count = 0
    for scenario in SCENARIOS:
        source = statistics_dir / f"raw_{scenario}.csv"
        raw = pd.read_csv(source)
        required = {"scenario", "network_size", "run", "device", "role", *METRICS}
        if not required.issubset(raw.columns):
            raise ValueError(f"Missing columns in {source}: {required - set(raw.columns)}")
        if not raw["scenario"].eq(scenario).all():
            raise ValueError(f"Unexpected scenario in {source}")
        if not raw["role"].isin(ROLE_NAMES).all():
            raise ValueError(f"Unexpected role in {source}")

        for network_size, samples in raw.groupby("network_size", sort=True):
            folder = destination / f"{scenario}_{int(network_size)}_nodes"
            folder.mkdir(parents=True, exist_ok=True)
            samples.to_csv(folder / f"{scenario}_per_device.csv", index=False)

            groups = [("All", samples)]
            groups.extend((name, samples[samples["role"] == role])
                          for role, name in ROLE_NAMES.items()
                          if samples["role"].eq(role).any())
            rows = [{"role": role, "metric": metric, **describe(group[metric].tolist())}
                    for role, group in groups for metric in METRICS]
            summary = pd.DataFrame(rows)
            summary.to_csv(folder / f"{scenario}_summary.csv", index=False)

            lines = [r"\begin{tabular}{lcccc}", r"\hline",
                     r"\textbf{Role} & \textbf{Duration (s)} & \textbf{CPU (\%)} & "
                     r"\textbf{Mem (\%)} & \textbf{Power (mW)} \\", r"\hline"]
            for role, _ in groups:
                metrics = summary[summary["role"] == role].set_index("metric")
                cells = [role]
                for metric in METRICS:
                    row = metrics.loc[metric]
                    precision = 3 if metric == "duration_s" else 2
                    cells.append(f"{row['mean']:.{precision}f} $\\pm$ {row['std']:.{precision}f}")
                lines.append(" & ".join(cells) + r" \\")
            lines += [r"\hline", r"\end{tabular}", ""]
            (folder / f"{scenario}_table.tex").write_text("\n".join(lines), encoding="utf-8")
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("statistics_dir", type=Path)
    parser.add_argument("--out", type=Path, help="default: statistics_dir")
    args = parser.parse_args()
    count = export_details(args.statistics_dir, args.out or args.statistics_dir)
    print(f"Generated {count} scenario/network folders")


if __name__ == "__main__":
    main()
