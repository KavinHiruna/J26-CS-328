"""
Evaluation: scores the baseline and the improved pipeline against ground truth.

Metrics (match the research proposal):
    Correlation precision / recall / F1   record-level, attack vs benign evidence
    Stage accuracy                        predicted stage vs true stage (IDS + device records)
    Sequence similarity                   reconstructed stage order vs true stage order
    RCA                                   initial vector, entry IP, origin type,
                                          compromised-asset precision / recall / F1

Usage:  python evaluate.py
Output: output/evaluation_results.md and output/evaluation_results.json
"""

import json
import os
import re
from difflib import SequenceMatcher

from pipeline import SCENARIOS, OUTPUT_DIR, load_scenario, run_baseline, run_improved
from timeline_rca import canonical_stage

IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def collapse(seq):
    out = []
    for s in seq:
        if not out or out[-1] != s:
            out.append(s)
    return out


def ips_of(items):
    found = set()
    for item in items:
        found.update(IP_RE.findall(item))
    return found


def evaluate_run(result, scoped, truth):
    by_id = {r.record_id: r for r in scoped}
    selected = {r.record_id for c in result["clusters"] for r in c.records}
    attack = {r.record_id for r in scoped if r.raw.get("label") == "ATTACK"}

    tp, fp, fn = len(selected & attack), len(selected - attack), len(attack - selected)
    precision, recall, f1 = prf(tp, fp, fn)

    # stage accuracy on correctly selected stage-bearing records (IDS + device)
    pred_stage = {t.evidence_id: t.stage for t in result["timeline"]}
    correct = total = 0
    for rid in selected & attack:
        rec = by_id[rid]
        if rec.source == "firewall":
            continue
        total += 1
        if canonical_stage(pred_stage.get(rid, "")) == rec.raw.get("true_stage"):
            correct += 1
    stage_acc = correct / total if total else 0.0

    # reconstructed stage order vs true stage order
    truth_seq = collapse([
        r.raw["true_stage"]
        for r in sorted(scoped, key=lambda x: x.timestamp)
        if r.raw.get("label") == "ATTACK" and r.source != "firewall"
    ])
    pred_seq = collapse([canonical_stage(t.stage) for t in result["timeline"] if t.source != "firewall"])
    seq_sim = SequenceMatcher(None, pred_seq, truth_seq).ratio()

    # root cause analysis
    rca = result["rca"]
    pred_assets = ips_of(rca.compromised_energy_assets)
    true_assets = set(truth["compromised_ips"])
    a_tp, a_fp, a_fn = len(pred_assets & true_assets), len(pred_assets - true_assets), len(true_assets - pred_assets)
    a_p, a_r, a_f = prf(a_tp, a_fp, a_fn)

    return {
        "records_selected": len(selected),
        "tp": tp, "fp": fp, "fn": fn,
        "corr_precision": precision, "corr_recall": recall, "corr_f1": f1,
        "stage_accuracy": stage_acc,
        "sequence_similarity": seq_sim,
        "pred_sequence": pred_seq, "true_sequence": truth_seq,
        "rca_vector_ok": canonical_stage(rca.initial_vector) == truth["initial_vector"],
        "rca_entry_ok": rca.entry_point_ip == truth["entry_ip"],
        "rca_origin_ok": rca.origin_type == truth["origin_type"],
        "rca_assets_f1": a_f,
        "rca_assets_pred": sorted(pred_assets),
    }


NUMERIC = [
    ("corr_precision", "Correlation precision"),
    ("corr_recall", "Correlation recall"),
    ("corr_f1", "Correlation F1"),
    ("stage_accuracy", "Stage accuracy"),
    ("sequence_similarity", "Timeline sequence similarity"),
    ("rca_assets_f1", "Compromised-asset F1"),
]
BOOLEAN = [
    ("rca_vector_ok", "RCA initial vector correct"),
    ("rca_entry_ok", "RCA entry IP correct"),
    ("rca_origin_ok", "RCA origin type correct"),
]


def fmt_bool(v):
    return "YES" if v else "NO"


def main():
    results = {}
    for name in SCENARIOS:
        incident, scoped, truth, _ = load_scenario(name)
        n_attack = sum(1 for r in scoped if r.raw.get("label") == "ATTACK")
        results[name] = {
            "records_in_scope": len(scoped),
            "attack_records": n_attack,
            "baseline": evaluate_run(run_baseline(scoped), scoped, truth),
            "improved": evaluate_run(run_improved(scoped, incident["seed_ips"]), scoped, truth),
        }

    # ---- console + markdown output (ASCII only so Windows consoles are happy) ----
    lines_md = ["# Evaluation Results - Baseline (Week 1) vs Improved (Week 2)", ""]
    for name, res in results.items():
        head = (f"{name}  (records in scope: {res['records_in_scope']}, "
                f"attack records: {res['attack_records']})")
        print("\n" + head)
        print(f"  {'metric':<34}{'baseline':>10}{'improved':>10}")
        lines_md += [f"## {name}", f"Records in scope: {res['records_in_scope']} | attack records: {res['attack_records']}", "",
                     "| Metric | Baseline | Improved |", "|---|---|---|"]
        for key, label in NUMERIC:
            b, i = res["baseline"][key], res["improved"][key]
            print(f"  {label:<34}{b:>10.2f}{i:>10.2f}")
            lines_md.append(f"| {label} | {b:.2f} | {i:.2f} |")
        for key, label in BOOLEAN:
            b, i = res["baseline"][key], res["improved"][key]
            print(f"  {label:<34}{fmt_bool(b):>10}{fmt_bool(i):>10}")
            lines_md.append(f"| {label} | {fmt_bool(b)} | {fmt_bool(i)} |")
        print(f"  false positives kept: baseline {res['baseline']['fp']}, improved {res['improved']['fp']}"
              f" | missed attack records: baseline {res['baseline']['fn']}, improved {res['improved']['fn']}")
        lines_md += ["", f"False positives kept: baseline {res['baseline']['fp']}, improved {res['improved']['fp']}. "
                     f"Missed attack records: baseline {res['baseline']['fn']}, improved {res['improved']['fn']}.", ""]

    # macro average
    print("\nMACRO AVERAGE over", len(results), "scenarios")
    print(f"  {'metric':<34}{'baseline':>10}{'improved':>10}")
    lines_md += ["## Macro average", "", "| Metric | Baseline | Improved |", "|---|---|---|"]
    n = len(results)
    for key, label in NUMERIC:
        b = sum(r["baseline"][key] for r in results.values()) / n
        i = sum(r["improved"][key] for r in results.values()) / n
        print(f"  {label:<34}{b:>10.2f}{i:>10.2f}")
        lines_md.append(f"| {label} | {b:.2f} | {i:.2f} |")
    for key, label in BOOLEAN:
        b = sum(1 for r in results.values() if r["baseline"][key])
        i = sum(1 for r in results.values() if r["improved"][key])
        print(f"  {label:<34}{str(b) + '/' + str(n):>10}{str(i) + '/' + str(n):>10}")
        lines_md.append(f"| {label} | {b}/{n} | {i}/{n} |")


    # ---- time-window sensitivity (justifies the correlation window parameter) ----
    windows = [1, 2, 3, 5, 10, 15, 30]
    loaded = {name: load_scenario(name) for name in SCENARIOS}
    sweep_rows = []
    print("\nTIME-WINDOW SENSITIVITY (macro average over scenarios)")
    print(f"  {'window (min)':<14}{'improved P':>11}{'improved R':>11}{'improved F1':>12}{'baseline F1':>12}")
    lines_md += ["## Time-window sensitivity", "",
                 "| Window (min) | Improved precision | Improved recall | Improved F1 | Baseline F1 |", "|---|---|---|---|---|"]
    for w in windows:
        imp = [evaluate_run(run_improved(sc, inc["seed_ips"], window_minutes=w), sc, tr)
               for inc, sc, tr, _ in loaded.values()]
        base = [evaluate_run(run_baseline(sc, window_minutes=w), sc, tr)
                for inc, sc, tr, _ in loaded.values()]
        mp = sum(x["corr_precision"] for x in imp) / len(imp)
        mr = sum(x["corr_recall"] for x in imp) / len(imp)
        mf = sum(x["corr_f1"] for x in imp) / len(imp)
        bf = sum(x["corr_f1"] for x in base) / len(base)
        sweep_rows.append({"window_minutes": w, "improved_precision": mp, "improved_recall": mr,
                           "improved_f1": mf, "baseline_f1": bf})
        print(f"  {w:<14}{mp:>11.2f}{mr:>11.2f}{mf:>12.2f}{bf:>12.2f}")
        lines_md.append(f"| {w} | {mp:.2f} | {mr:.2f} | {mf:.2f} | {bf:.2f} |")
    results["window_sweep"] = sweep_rows

    lines_md += [
        "", "## Important limitations", "",
        "- All three scenarios are synthetic and were written by the same author as the pipeline, "
        "and the improved stage tables were tuned while developing against them. These numbers show that "
        "the pipeline logic works on designed scenarios; they are NOT proof of generalisation.",
        "- Stage mapping tables (IDS category / device event type) cover the vocabulary of these scenarios; "
        "unseen vocabulary falls back to keyword matching.",
        "- Known hard cases are kept on purpose (a legitimate failed login on an attacker-touched host is still "
        "reported as relevant), so precision stays below 1.0.",
        "- A compromised host that also carries legitimate traffic cannot be separated by these rules alone; "
        "baselining known-good flows is future work.",
    ]

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "evaluation_results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines_md) + "\n")
    with open(os.path.join(OUTPUT_DIR, "evaluation_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("\nSaved: output/evaluation_results.md and output/evaluation_results.json")


if __name__ == "__main__":
    main()
