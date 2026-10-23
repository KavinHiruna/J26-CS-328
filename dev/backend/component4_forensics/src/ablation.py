"""
Ablation: switches off one rule at a time and re-scores, to show what each rule contributes.
Scored on the 4 fixed scenarios and on the random held-out scenarios (fresh seed).

Usage:  python ablation.py [N_PER_TEMPLATE] [SEED]       (default 25, 2027)
Output: output/ablation_results.md and output/ablation_results.json
"""
import json
import os
import shutil
import statistics
import sys
import tempfile

import correlator
import heldout
from pipeline import SCENARIOS, OUTPUT_DIR, load_scenario
from log_loader import load_all_evidence, scope_evidence
from correlator import correlate_seeded
from timeline_rca import build_timeline, classify_stage, classify_stage_legacy, perform_rca, perform_rca_legacy
from evaluate import evaluate_run

CONFIGS = [
    ("Full method (all rules on)", set(), {}),
    ("No reverse-seed rule (C2 address as destination)", {"reverse_seed"}, {}),
    ("No flow-history rule (routine flows of pivoted hosts)", {"flow_history"}, {}),
    ("No policy-alert filter", {"policy_filter"}, {}),
    ("Single failed login counted as evidence", {"auth_fail_rule"}, {}),
    ("Login counted without actor link", {"login_needs_actor"}, {}),
    ("Routine device events counted", {"ignore_routine_device"}, {}),
    ("Chain split by pauses (old group rule)", {"keep_all_groups"}, {}),
    ("No IT-OT corroboration requirement", {"corroboration"}, {}),
    ("Keyword stage classifier (old)", set(), {"legacy_stage": True}),
    ("First-event root cause (old)", set(), {"legacy_rca": True}),
]
KEYS = ["corr_precision", "corr_recall", "corr_f1", "stage_accuracy", "rca_assets_f1"]
BOOLS = ["rca_vector_ok", "rca_entry_ok", "rca_origin_ok"]


def run(scoped, seeds, abl, opts):
    correlator.ABLATE = set(abl)
    clusters = correlate_seeded(scoped, seeds, 5)
    timeline = build_timeline(clusters, classifier=classify_stage_legacy if opts.get("legacy_stage") else classify_stage)
    rca = perform_rca_legacy(timeline, scoped) if opts.get("legacy_rca") else perform_rca(timeline, scoped, seeds)
    correlator.ABLATE = set()
    return {"clusters": clusters, "timeline": timeline, "rca": rca}


def build_sets(n, seed):
    sets = {"fixed": [], "heldout": []}
    for name in SCENARIOS:
        inc, scoped, truth, _ = load_scenario(name)
        sets["fixed"].append((scoped, inc["seed_ips"], truth))
    for ti, (_, fn) in enumerate(heldout.TEMPLATES):
        for k in range(n):
            tmp = tempfile.mkdtemp(prefix="abl_")
            try:
                inc, truth, files = heldout.make(fn, seed * 1000 + ti * 100 + k, tmp)
                scoped = scope_evidence(load_all_evidence(*files), inc["window_start"], inc["window_end"])
                sets["heldout"].append((scoped, inc["seed_ips"], truth))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
    return sets


def score(items, abl, opts):
    res = [evaluate_run(run(sc, seeds, abl, opts), sc, truth) for sc, seeds, truth in items]
    out = {k: statistics.mean(r[k] for r in res) for k in KEYS}
    out.update({k: sum(1 for r in res if r[k]) / len(res) for k in BOOLS})
    return out


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 2027
    sets = build_sets(n, seed)
    rows = []
    for name, abl, opts in CONFIGS:
        rows.append({"config": name, "fixed": score(sets["fixed"], abl, opts), "heldout": score(sets["heldout"], abl, opts)})
    L = [f"# Ablation (4 fixed scenarios and {len(sets['heldout'])} held-out scenarios, seed {seed})", "",
         "Each row switches off one rule. Values are macro averages; RCA columns are the share of scenarios correct.", ""]
    for setname in ("fixed", "heldout"):
        L += [f"## {'4 fixed scenarios' if setname == 'fixed' else 'Held-out scenarios'}", "",
              "| Configuration | Precision | Recall | F1 | Stage acc | Asset F1 | Vector | Entry IP | Origin |",
              "|---|---|---|---|---|---|---|---|---|"]
        for r in rows:
            v = r[setname]
            L.append(f"| {r['config']} | {v['corr_precision']:.2f} | {v['corr_recall']:.2f} | {v['corr_f1']:.2f} | "
                     f"{v['stage_accuracy']:.2f} | {v['rca_assets_f1']:.2f} | {v['rca_vector_ok']:.2f} | "
                     f"{v['rca_entry_ok']:.2f} | {v['rca_origin_ok']:.2f} |")
        L.append("")
    print("\n".join(L))
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    open(os.path.join(OUTPUT_DIR, "ablation_results.md"), "w").write("\n".join(L) + "\n")
    json.dump(rows, open(os.path.join(OUTPUT_DIR, "ablation_results.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
