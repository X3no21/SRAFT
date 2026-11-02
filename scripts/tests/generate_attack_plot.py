#!/usr/bin/env python3
"""
Figures for the attack-resilience campaign, from attack_results.json.

  attack_properties.pdf : per-variant rate of the verified security property over the independent
                          runs, with 95% Wilson intervals (a paper-ready bar chart).
  attack_exposure.pdf   : honest verification paths that remain as the number of compromised
                          Verifiers of a Prover grows (credential-exposure bound of Section 5.3).

Usage: python3 generate_attack_plot.py <attack_results_dir>
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return p, max(0.0, c - h), min(1.0, c + h)


def main(out_dir):
    with open(os.path.join(out_dir, "attack_results.json")) as f:
        rep = json.load(f)
    s = rep["scenarios"]

    # (label, successes, trials): one bar per verified property.
    a, b, c = s["A_replay_modification"], s["B_chosen_challenge"], s["C_capture_collusion"]
    d, e = s["D_coordinator_removal"], s["E_forged_messages"]
    d_runs = [r for r in d.get("runs", []) if isinstance(r, dict) and "kept_target" in r]
    d_kept = sum(1 for r in d_runs if r.get("kept_target", 0) > 0)
    bars = [
        ("A: modified request\nrefused (5.1)", a.get("modified_refused", 0), a.get("modified_total", 0)),
        ("A: replayed request\ndropped (5.1)", a.get("replay_dropped", 0), a.get("replay_total", 0)),
        ("B: invalid-proof query\nrefused (5.2)", b.get("invalid_refused", 0), b.get("invalid_total", 0)),
        ("C: impersonation\nrejected (5.3)", c.get("impersonation_rejected", 0), c.get("impersonation_total", 0)),
        ("D: honest shard kept\non forged order (5.4)", d_kept, len(d_runs)),
        ("E: tampered usurpation\nrefused (5.4)", e.get("tampered_claim_refused", 0), e.get("tampered_claim_total", 0)),
        ("E: outsider injection\ndropped (5.4)", e.get("outsider_injection_dropped", 0), e.get("outsider_injection_total", 0)),
    ]
    labels = [x[0] for x in bars]
    rates, los, his = [], [], []
    for _, k, n in bars:
        p, lo, hi = wilson(k, n)
        rates.append(p); los.append(p - lo); his.append(hi - p)

    fig, ax = plt.subplots(figsize=(10, 4.2))
    xs = range(len(bars))
    ax.bar(xs, rates, yerr=[los, his], capsize=4, color="#2b6cb0", edgecolor="black", linewidth=0.5)
    for i, (_, k, n) in enumerate(bars):
        ax.text(i, min(rates[i] + 0.05, 1.0), f"{k}/{n}", ha="center", va="bottom", fontsize=8)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Property holds (fraction of runs)")
    ax.set_xticks(list(xs))
    ax.set_xticklabels(labels, fontsize=8, rotation=0)
    ax.axhline(1.0, color="gray", linestyle=":", linewidth=0.8)
    ax.set_title(f"Attack resilience over independent runs ({rep['nodes']} devices)")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "attack_properties.pdf"))
    fig.savefig(os.path.join(out_dir, "attack_properties.png"), dpi=150)
    plt.close(fig)

    exp = s.get("C_exposure", {})
    if exp.get("rows"):
        ks = [r["compromised_verifiers"] for r in exp["rows"]]
        left = [r["honest_paths_left"] for r in exp["rows"]]
        fig, ax = plt.subplots(figsize=(5.2, 3.6))
        ax.plot(ks, left, marker="o", color="#2b6cb0")
        ax.axhline(1, color="green", linestyle="--", linewidth=0.8, label="still verifiable")
        ax.axhline(0, color="red", linestyle="--", linewidth=0.8, label="no honest path")
        ax.set_xlabel("Compromised Verifiers of the Prover")
        ax.set_ylabel("Honest verification paths left")
        q = exp.get("verifiers_per_prover")
        ax.set_title(f"Credential exposure (q = {q} Verifiers per Prover)")
        ax.set_xticks(ks)
        ax.legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, "attack_exposure.pdf"))
        fig.savefig(os.path.join(out_dir, "attack_exposure.png"), dpi=150)
        plt.close(fig)
    print(f"Wrote figures to {out_dir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "attack_results")
