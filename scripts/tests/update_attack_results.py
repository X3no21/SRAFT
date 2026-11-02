"""Validate supplied attack counts and regenerate the manuscript table."""

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "experimental_results" / "attack"
FOLLOWUP = SOURCE
OUTPUT = ROOT / "experimental_results" / "paper"
TABLES = OUTPUT
data = json.loads((SOURCE / "attack_results.json").read_text())
followup = json.loads((FOLLOWUP / "removal_followup_results.json").read_text())
if data["nodes"] != 7:
    raise ValueError("The manuscript attack configuration requires seven nodes")
if followup["nodes"] != 7:
    raise ValueError("The removal follow-up requires seven nodes")
scenarios = data["scenarios"]
with (SOURCE / "attack_summary.csv").open(newline="") as handle:
    summary = list(csv.DictReader(handle))
reported = {(row["scenario"], row["property"]): row for row in summary}
if len(reported) != 9 or len(summary) != 9:
    raise ValueError("Expected nine distinct supplied property counts")

observations = []


def observation(case, description, successes, trials, csv_property=None):
    if not isinstance(successes, int) or not 0 <= successes <= trials:
        raise ValueError(f"Invalid count for {case}: {description}")
    if csv_property is not None:
        supplied = reported[(case, csv_property)]
        if (int(supplied["successes"]), int(supplied["trials"])) != (
            successes, trials
        ):
            raise ValueError(f"CSV/JSON count mismatch: {csv_property}")
        if abs(float(supplied["rate"]) - successes / trials) > 0.00005:
            raise ValueError(f"CSV rate mismatch: {csv_property}")
    observations.append({
        "case": case, "observation": description,
        "count": successes, "repetitions": trials,
    })


for case, key, fields in [
    ("A", "A_replay_modification", [
        ("modified_refused", "modified_total", "Modified request refused",
         "modified request refused"),
        ("replay_dropped", "replay_total", "Replayed request dropped",
         "replayed request dropped"),
    ]),
    ("B", "B_chosen_challenge", [
        ("invalid_refused", "invalid_total", "Invalid-proof query refused",
         "invalid-proof query refused"),
        ("genuine_answered", "genuine_total", "Genuine request answered (control)",
         "genuine request answered (control)"),
    ]),
    ("C", "C_capture_collusion", [
        ("impersonation_rejected", "impersonation_total",
         "Incorrect-response impersonation rejected", "impersonation rejected"),
        ("genuine_accepted", "genuine_total",
         "Genuine authentication accepted (control)",
         "genuine authentication accepted (control)"),
    ]),
]:
    values = scenarios[key]
    for count, total, description, csv_property in fields:
        if values[total] != 10:
            raise ValueError(f"Unexpected repetition count for {case}")
        observation(case, description, values[count], values[total], csv_property)

# Validate the original CSV's D count without mixing its observations into
# the follow-up results presented for the recipient-side evidence check.
old_removals = scenarios["D_coordinator_removal"]["runs"]
old_d = reported[("D", "honest Verifier kept shard on unconfirmed order")]
if (int(old_d["successes"]), int(old_d["trials"])) != (
    sum(run["kept_target"] == 3 for run in old_removals), len(old_removals)
):
    raise ValueError("Original D CSV/JSON counts disagree")

removals = followup["scenarios"]["D_coordinator_removal"]["runs"]
if len(removals) != 5 or any(run["recipients"] != 5 for run in removals):
    raise ValueError("Expected five D runs with five recipients each")
if any(run["kept_target"] + run["removed_target"] != run["recipients"]
       for run in removals):
    raise ValueError("Follow-up D recipient totals disagree")
retained = sum(run["kept_target"] == run["recipients"] for run in removals)
not_applied = sum(
    run["removed_target"] == 0 and not run["membership_diverged"]
    for run in removals
)
authenticated = sum(run["target_still_authenticates"] for run in removals)
observation("D", "All five recipients retained the target", retained, 5)
observation("D", "No removal applied and no divergent views", not_applied, 5)
observation("D", "Target still authenticated", authenticated, 5)

for count, total, description, csv_property in [
    ("tampered_claim_refused", "tampered_claim_total",
     "Altered member's Coordinator claim refused", "tampered-member usurpation refused"),
    ("outsider_injection_dropped", "outsider_injection_total",
     "Nonmember injection dropped", "outsider injection dropped"),
]:
    values = scenarios["E_forged_messages"]
    if values[total] != 5:
        raise ValueError("Expected five repetitions for E")
    observation("E", description, values[count], values[total], csv_property)

legitimate = followup["scenarios"]["legit_removal"]["runs"]
if len(legitimate) != 3 or any(run["survivors"] != 6 for run in legitimate):
    raise ValueError("Expected three legitimate-removal runs with six survivors")
completed = sum(
    run["healed_to_n_minus_1"] and
    run["victim_removed_from_coordinator_view"] and
    run["members_that_removed_victim"] == run["survivors"]
    for run in legitimate
)
observation("L", "All six survivors removed crashed target and healed", completed, 3)

exposure = scenarios["C_exposure"]
if exposure["verifiers_per_prover"] != 3:
    raise ValueError("Expected three assigned Verifiers")
expected = [
    {"compromised_verifiers": k, "exposed_shards": k,
     "honest_paths_left": 3 - k, "prover_still_verifiable": k < 3}
    for k in range(4)
]
if exposure["rows"] != expected:
    raise ValueError("Structural exposure counts disagree with q=3")

lines = [
    "% Generated by update_attack_results.py from supplied attack counts.",
    "% D and L use the separate recipient-evidence follow-up campaign.",
    r"\begin{tabular}{>{\raggedright\arraybackslash}p{0.09\columnwidth}>{\raggedright\arraybackslash}p{0.69\columnwidth}r}",
    r"\hline",
    r"\textbf{Case} & \textbf{Observation} & \textbf{Count} \\",
    r"\hline",
]
for row in observations:
    lines.append(
        f"{row['case']} & {row['observation']} & "
        f"{row['count']}/{row['repetitions']} " + r"\\"
    )
lines.extend([r"\hline", r"\end{tabular}"])
TABLES.mkdir(parents=True, exist_ok=True)
(TABLES / "attack_table.tex").write_text("\n".join(lines) + "\n")
validation = {
    "inputs_sha256": {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [SOURCE / name for name in (
            "attack_results.json", "attack_summary.csv",
            "attack_campaign.log",
        )] + [FOLLOWUP / name for name in (
            "removal_followup_results.json",
            "removal_followup.log",
        )]
    },
    "nodes": 7,
    "csv_properties_checked": len(summary),
    "observations": observations,
    "structural_exposure": expected,
    "interpretation": {
        "A_B_C": "Ten repetitions per variant; no independent rebootstrap asserted.",
        "D_E": "Five repetitions per variant; D is from the follow-up, E from the original campaign.",
        "D": "Recipient evidence required; all five recipients retain the target without divergence in five follow-up runs.",
        "L": "Three functional controls; six survivors remove a crashed node and heal.",
        "exposure": "Structural accounting, not an empirical prediction attack.",
        "timing": "The attack campaign does not measure removal, recovery, election latency or energy.",
        "scope": "Threshold one requires assigned-Verifier evidence; a Coordinator also assigned as Verifier can confirm. No general Byzantine guarantee inferred.",
    },
}
(OUTPUT / "attack_validation.json").write_text(json.dumps(validation, indent=2) + "\n")
print(f"Validated {len(summary)} original CSV properties, {len(removals)} follow-up D "
      f"and {len(legitimate)} legitimate-removal records; "
      f"wrote {len(observations)} table rows.")
