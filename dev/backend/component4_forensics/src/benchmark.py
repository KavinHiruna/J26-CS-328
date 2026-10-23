"""
Performance benchmark (Stage 1-5): scales scenario 1 with extra benign records and
times each stage. Usage:  python benchmark.py
All extra records fall inside the incident window (worst case: nothing is cut by scoping).
"""
import csv, json, os, random, shutil, statistics, sys, tempfile, time
from datetime import datetime, timedelta

from pipeline import DATA_DIR, OUTPUT_DIR
from log_loader import load_all_evidence, scope_evidence
from pipeline import run_improved

BASE = "scenario1_rdp_to_breaker"
SIZES = [500, 5000, 50000]
REPEATS = 3
INTERNAL = [f"10.10.0.{i}" for i in (10, 20, 30, 50, 60, 70)]
FMT = "%Y-%m-%d %H:%M:%S"


def read(path):
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        return r.fieldnames, list(r)


def build(size, out, seed=1):
    rnd = random.Random(seed)
    src = os.path.join(DATA_DIR, BASE)
    inc = json.load(open(os.path.join(src, "incident.json")))
    t0 = datetime.strptime(inc["window_start"], FMT)
    span = int((datetime.strptime(inc["window_end"], FMT) - t0).total_seconds())
    cols, rows = {}, {}
    for fn in ("firewall.log", "ids_alerts.log", "device.log"):
        cols[fn], rows[fn] = read(os.path.join(src, fn))
    have = sum(len(v) for v in rows.values())
    extra = max(0, size - have)
    ts = lambda: (t0 + timedelta(seconds=rnd.randint(0, span))).strftime(FMT)
    for _ in range(extra):
        k = rnd.random()
        a, b = rnd.sample(INTERNAL, 2)
        if k < 0.6:
            rows["firewall.log"].append({"timestamp": ts(), "action": "ALLOW", "src_ip": a, "dst_ip": b,
                                         "dst_port": rnd.choice(["502", "443", "20000"]), "protocol": "TCP",
                                         "label": "BENIGN", "true_stage": ""})
        elif k < 0.8:
            rows["ids_alerts.log"].append({"timestamp": ts(), "signature": "ET POLICY Modbus Read Burst (Periodic Polling)",
                                           "severity": "Low", "src_ip": a, "dst_ip": b, "category": "Policy",
                                           "label": "BENIGN", "true_stage": ""})
        else:
            rows["device.log"].append({"timestamp": ts(), "device": f"PLC-{b}", "event_type": "READ_REGISTER",
                                       "user": "HMI-01", "description": "Periodic poll of status register",
                                       "label": "BENIGN", "true_stage": ""})
    os.makedirs(out, exist_ok=True)
    for fn in rows:
        with open(os.path.join(out, fn), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols[fn]); w.writeheader(); w.writerows(rows[fn])
    return inc, sum(len(v) for v in rows.values()), [os.path.join(out, fn) for fn in rows]


def one_run(inc, files):
    t = {}
    s = time.perf_counter()
    ev = load_all_evidence(*files)
    scoped = scope_evidence(ev, inc["window_start"], inc["window_end"])
    t["load"] = time.perf_counter() - s
    s = time.perf_counter()
    res = run_improved(scoped, inc["seed_ips"])
    t["analyse"] = time.perf_counter() - s
    t["total"] = t["load"] + t["analyse"]
    recs = [r for c in res["clusters"] for r in c.records]
    kept = len(recs)
    atk = sum(1 for r in scoped if r.raw.get("label") == "ATTACK")
    tp = sum(1 for r in recs if r.raw.get("label") == "ATTACK")
    t["precision"] = tp / kept if kept else 0.0
    t["recall"] = tp / atk if atk else 0.0
    return t, len(scoped), kept, res["rca"]


def main():
    out = []
    for size in SIZES:
        tmp = tempfile.mkdtemp(prefix="bench_")
        try:
            inc, n, files = build(size, tmp)
            runs = [one_run(inc, files) for _ in range(REPEATS)]
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        med = lambda k: statistics.median(r[0][k] for r in runs)
        _, scoped_n, kept, rca = runs[0]
        out.append({"records": n, "in_scope": scoped_n, "kept": kept,
                    "load_s": round(med("load"), 3), "analyse_s": round(med("analyse"), 3),
                    "total_s": round(med("total"), 3), "precision": round(runs[0][0]["precision"], 3), "recall": round(runs[0][0]["recall"], 3), "origin": rca.origin_type, "entry_ip": rca.entry_point_ip})
        print(out[-1], flush=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "benchmark_results.json"), "w") as f:
        json.dump(out, f, indent=2)
    lines = ["# Performance benchmark (scenario 1 scaled with benign records)", "",
             "| Records | In scope | Kept as relevant | Load + scope (s) | Correlate + timeline + RCA (s) | Total (s) | Precision | Recall | RCA origin / entry IP |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in out:
        lines.append(f"| {r['records']} | {r['in_scope']} | {r['kept']} | {r['load_s']} | {r['analyse_s']} | {r['total_s']} | {r['precision']} | {r['recall']} | {r['origin']} / {r['entry_ip']} |")
    open(os.path.join(OUTPUT_DIR, "benchmark_results.md"), "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
