"""
Public dataset test: runs the seeded correlation on real network traffic from the
Edge-IIoTset dataset (the training split used by Component 1, ~126k packet records).

What this tests (and what it does not)
  * Ground truth is the dataset's own Attack_label, written by the dataset authors, not by me.
  * The dataset has network records only: no firewall/IDS/OT device logs and no attack-stage labels.
    So only record-level correlation and the entry point can be scored, and the IT-OT
    corroboration rule is switched off (min_sources=1).
  * The capture date is missing from frame.time (only the time of day survives), so all records
    are placed on one dummy date. Records with no usable time are skipped and counted.
  * The seed IP is the top attacker source in Component 1's alerts, not taken from the labels.

Usage:  python public_dataset_test.py <train_csv> [flagged_alerts_csv] [seed_ip]
Output: output/public_dataset_results.md and output/public_dataset_results.json
"""
import csv
import collections
import json
import os
import re
import sys
import time
from datetime import datetime

from pipeline import OUTPUT_DIR
from log_loader import EvidenceRecord
from correlator import correlate_seeded

TOD = re.compile(r"(\d{2}):(\d{2}):(\d{2})\.?(\d*)")


def parse_tod(text):
    m = TOD.search(text or "")
    if not m or not (text or "").strip().startswith("2021"):
        return None
    h, mi, s, frac = int(m.group(1)), int(m.group(2)), int(m.group(3)), (m.group(4) + "000000")[:6]
    try:
        return datetime(2021, 1, 1, h, mi, s, int(frac))
    except ValueError:
        return None


def load(path):
    recs, skipped, total = [], 0, 0
    with open(path, newline="", errors="replace") as f:
        for row in csv.DictReader(f):
            total += 1
            ts = parse_tod(row["frame.time"])
            if ts is None:
                skipped += 1
                continue
            src, dst = row["ip.src_host"], row["ip.dst_host"]
            recs.append(EvidenceRecord(
                timestamp=ts, source="firewall", event_type="connection",
                src_ip=src if src not in ("0", "") else None,
                dst_ip=dst if dst not in ("0", "") else None,
                asset=dst if dst not in ("0", "") else None,
                description=f"flow {src} -> {dst}:{row['tcp.dstport']} #{row['Incident ID']}",
                raw={"dst_port": row["tcp.dstport"], "label": "ATTACK" if row["Attack_label"] == "1" else "BENIGN",
                     "incident_id": row["Incident ID"]}))
    return recs, skipped, total


def seed_from_alerts(path):
    """Top attacker source address in Component 1's alerts (no labels used)."""
    cnt = collections.Counter()
    with open(path, newline="", errors="replace") as f:
        for r in csv.DictReader(f):
            ip = r.get("source_ip", "")
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and r.get("attack_type") != "Normal":
                cnt[ip] += 1
    return cnt.most_common(1)[0][0], cnt.most_common(3)


def score(selected_ids, recs):
    atk = {r.record_id for r in recs if r.raw["label"] == "ATTACK"}
    tp, fp, fn = len(selected_ids & atk), len(selected_ids - atk), len(atk - selected_ids)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    benign = sum(1 for x in recs if x.raw["label"] == "BENIGN")
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "benign_excluded": 1 - fp / benign if benign else 0.0,
            "f1": 2 * p * r / (p + r) if p + r else 0.0}


def main():
    path = sys.argv[1]
    alerts = sys.argv[2] if len(sys.argv) > 2 else None
    seed, top = seed_from_alerts(alerts) if alerts else ("192.168.0.170", [])
    if len(sys.argv) > 3:
        seed = sys.argv[3]          # seed supplied by the SOC handoff (Component 3), overrides the guess
    t = time.perf_counter()
    recs, skipped, total = load(path)
    t_load = time.perf_counter() - t
    # record_id is a hash of time+source+description; make ids unique per row via the incident id in description
    n_attack = sum(1 for r in recs if r.raw["label"] == "ATTACK")

    t = time.perf_counter()
    clusters = correlate_seeded(recs, [seed], time_window_minutes=5, min_sources=1)
    t_corr = time.perf_counter() - t
    chosen = {r.record_id for c in clusters for r in c.records}
    improved = score(chosen, recs)
    base_ip = score({r.record_id for r in recs if r.src_ip == seed or r.dst_ip == seed}, recs)
    base_all = score({r.record_id for r in recs}, recs)

    missed = [r for r in recs if r.raw["label"] == "ATTACK" and r.record_id not in chosen]
    why = collections.Counter()
    victim = "192.168.0.128"
    for r in missed:
        if not r.src_ip and not r.dst_ip:
            why["no IP address in the record (ARP, ICMP or malformed)"] += 1
        elif r.dst_ip == victim and r.src_ip and r.src_ip != seed:
            why["inbound to the victim from many other source addresses (distributed or spoofed)"] += 1
        elif not r.src_ip or not r.dst_ip:
            why["only one IP address in the record"] += 1
        else:
            why["other"] += 1
    missed_sources = len({r.src_ip for r in missed if r.dst_ip == victim and r.src_ip and r.src_ip != seed})
    fps = collections.Counter(f"{r.src_ip} -> {r.dst_ip}" for r in recs
                              if r.record_id in chosen and r.raw["label"] == "BENIGN")
    res = {"file": os.path.basename(path), "records_total": total, "skipped_no_time": skipped,
           "records_used": len(recs), "attack_records": n_attack, "seed_ip": seed, "seed_candidates": top,
           "improved": improved, "baseline_seed_ip_only": base_ip, "baseline_everything": base_all,
           "missed_reasons": why.most_common(8), "missed_distinct_other_sources": missed_sources, "false_positive_pairs": fps.most_common(5),
           "load_s": round(t_load, 2), "correlate_s": round(t_corr, 2), "clusters": len(clusters)}
    L = ["# Public dataset test (Edge-IIoTset training split)", "",
         f"Records: {total} read, {skipped} skipped (no usable time), {len(recs)} used, {n_attack} labelled attack.",
         f"Seed IP: {seed} (most frequent sources in Component 1 alerts: {top}).", "",
         "| Method | TP | FP | FN | Precision | Recall | F1 | Benign excluded |", "|---|---|---|---|---|---|---|---|"]
    for name, s in (("Everything in the window", base_all), ("Records touching the seed IP", base_ip),
                    ("Seeded correlation (this work)", improved)):
        L.append(f"| {name} | {s['tp']} | {s['fp']} | {s['fn']} | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} | {s['benign_excluded']:.3f} |")
    L += ["", f"Run time: load {res['load_s']} s, correlation {res['correlate_s']} s for {len(recs)} records.",
          "", "Missed attack records by reason: " + "; ".join(f"{k}: {v}" for k, v in why.most_common(8)) + f" ({missed_sources} distinct other source addresses)",
          "", "Benign records kept, by address pair: " + "; ".join(f"{k}: {v}" for k, v in fps.most_common(5))]
    print("\n".join(L))
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    open(os.path.join(OUTPUT_DIR, "public_dataset_results.md"), "w").write("\n".join(L) + "\n")
    json.dump(res, open(os.path.join(OUTPUT_DIR, "public_dataset_results.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
