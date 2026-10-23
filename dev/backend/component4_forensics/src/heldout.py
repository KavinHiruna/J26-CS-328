"""
Held-out randomized test.

Generates many attack scenarios from random seeds (random attacker address, hosts, ports,
number of steps, timing gaps and noise level), runs the baseline and the improved pipeline
on each, and scores both against the ground truth that the generator wrote.

The four fixed scenarios in generate_scenarios.py were written while the rules were being
developed. These randomized scenarios were NOT used to tune the rules.  They are still
written by the same author, so this is a robustness test, not an independent one.

Usage:  python heldout.py [N_PER_TEMPLATE] [SEED]      (default 10 per template, seed 2026)
Output: output/heldout_results.md and output/heldout_results.json
"""

import csv
import json
import os
import random
import statistics
import sys
import tempfile
import shutil
from datetime import datetime, timedelta

from pipeline import OUTPUT_DIR, run_baseline, run_improved
from log_loader import load_all_evidence, scope_evidence
from evaluate import evaluate_run

FMT = "%Y-%m-%d %H:%M:%S"
A, B = "ATTACK", "BENIGN"
NC = "Network Connection"
HOSTS = {"EWS": "SCADA-EWS-10.10.0.10", "HIST": "HISTORIAN-10.10.0.30", "EMS": "EMS-SERVER-10.10.0.60",
         "PLC": "Substation-Breaker-PLC-10.10.0.50", "RTU": "Protection-Relay-RTU-10.10.0.70",
         "VPN": "VPN-GW-10.10.0.2", "HMI": "HMI-10.10.0.20"}
IPS = {k: v.rsplit("-", 1)[1] for k, v in HOSTS.items()}
OT_PORTS = [("502", "Modbus Write Function Code Anomaly"), ("20000", "DNP3 Direct Operate Anomaly"),
            ("2404", "IEC-104 Setpoint Command Anomaly")]


def ext_ip(r):
    return r.choice([f"203.0.113.{r.randint(2, 250)}", f"198.51.100.{r.randint(2, 250)}",
                     f"{r.choice([45, 91, 103, 185])}.{r.randint(1, 250)}.{r.randint(1, 250)}.{r.randint(2, 250)}"])


class Build:
    def __init__(self, rnd, start):
        self.r, self.fw, self.ids, self.dev = rnd, [], [], []
        self.t0 = start
        self.cur = start + timedelta(seconds=rnd.randint(60, 240))
        self.attack_times = []

    def step(self, lo=10, hi=200):
        gap = self.r.randint(lo, hi)
        if self.r.random() < 0.08:
            gap = self.r.randint(300, 420)          # occasional long pause (5-7 min)
        self.cur += timedelta(seconds=gap)
        self.attack_times.append(self.cur)
        return self.cur.strftime(FMT)

    def at(self, off):
        return (self.cur + timedelta(seconds=off)).strftime(FMT)

    def f(self, ts, src, dst, port, lab=A, st=NC):
        self.fw.append((ts, "ALLOW", src, dst, port, "TCP", lab, st if lab == A else ""))

    def i(self, ts, sig, sev, src, dst, cat, lab=A, st=""):
        self.ids.append((ts, sig, sev, src, dst, cat, lab, st))

    def d(self, ts, host, ev, user, desc, lab=A, st=""):
        self.dev.append((ts, HOSTS[host] if host in HOSTS else host, ev, user, desc, lab, st))


def ot_step(b, src_ip, target, src_name):
    port, sig = b.r.choice(OT_PORTS)
    ts = b.step()
    b.f(ts, src_ip, IPS[target], port)
    b.i(b.at(3), "ET SCADA " + sig, "Critical", src_ip, IPS[target], "ICS-Attack", A, "Impact")
    b.d(b.at(0), target, "LOGIC_CHANGE" if b.r.random() < .5 else "SETPOINT_CHANGE", src_name,
        f"Control value altered via {port}", A, "Impact")
    b.d(b.at(5), target, "STATE_CHANGE", src_name, "Output forced - risk of unplanned trip", A, "Impact")


def t_remote_access(r, start):
    """External remote access to the EWS, optional brute force / malware, then an OT write."""
    b, atk = Build(r, start), ext_ip(r)
    ews, target = "EWS", r.choice(["PLC", "RTU"])
    if r.random() < .6:
        for k in range(r.randint(1, 3)):
            b.f(b.step(), atk, f"10.10.0.{r.choice([10, 11, 12, 30])}", r.choice(["22", "3389", "445"]))
        b.i(b.at(2), "ET SCAN Nmap Scripting Engine User-Agent Detected", "Medium", atk, "10.10.0.0/24", "Reconnaissance", A, "Reconnaissance")
    ts = b.step()
    b.f(ts, atk, IPS[ews], r.choice(["3389", "22"]))
    b.d(b.at(3), ews, "LOGIN", "unknown_admin", f"Remote desktop login succeeded from {atk}", A, "Initial Access")
    comp = [ews]
    if r.random() < .6:
        b.i(b.step(), "ET POLICY SSH Brute Force Login Attempt", "High", atk, IPS[ews], "Credential-Access", A, "Credential Access")
        b.d(b.at(2), ews, "AUTH_FAIL", "root", "SSH authentication failed (4 attempts)", A, "Credential Access")
        b.d(b.at(14), ews, "AUTH_SUCCESS", "root", "SSH authentication succeeded after brute force", A, "Credential Access")
    if r.random() < .6:
        b.i(b.step(), "ET MALWARE Possible Malicious Payload Upload via SMB", "Critical", atk, IPS[ews], "Malware", A, "Malware Delivery")
        b.d(b.at(5), ews, "FILE_WRITE", "root", "New executable written to /tmp/agent.bin", A, "Malware Delivery")
        b.d(b.at(7), ews, "PROCESS_START", "root", "Process agent.bin started", A, "Execution")
    ot_step(b, IPS[ews], target, HOSTS[ews])
    comp.append(target)
    return b, [atk], atk, "external", "Initial Access", comp


def t_vpn_chain(r, start):
    """Stolen VPN account, then 1-3 pivots, then an OT write."""
    b, atk = Build(r, start), ext_ip(r)
    pool = r.sample(["HIST", "EMS", "EWS"], r.randint(1, 3))
    target = r.choice(["RTU", "PLC"])
    ts = b.step()
    b.f(ts, atk, IPS["VPN"], "443")
    b.i(b.at(5), "ET POLICY VPN Login from Unusual Geolocation", "Medium", atk, IPS["VPN"], "Initial-Access", A, "Initial Access")
    b.d(b.at(3), "VPN", "VPN_LOGIN", "svc_vendor", f"VPN login succeeded from {atk} using valid vendor account", A, "Initial Access")
    prev, comp = "VPN", ["VPN"]
    for h in pool:
        ts = b.step()
        b.f(ts, IPS[prev], IPS[h], r.choice(["3389", "445"]))
        b.i(b.at(5), "ET POLICY Remote Session Initiated", "Medium", IPS[prev], IPS[h], "Lateral-Movement", A, "Lateral Movement")
        b.d(b.at(4), h, r.choice(["RDP_SESSION", "REMOTE_LOGIN"]), "svc_vendor", f"Remote session opened from {IPS[prev]}", A, "Lateral Movement")
        if r.random() < .5:
            b.d(b.step(10, 60), h, "CRED_DUMP", "svc_vendor", "Credential dumping utility executed", A, "Credential Access")
        prev = h
        comp.append(h)
    ot_step(b, IPS[prev], target, HOSTS[prev])
    comp.append(target)
    return b, [atk], atk, "external", "Initial Access", comp


def t_insider(r, start):
    """Rogue internal device scans the OT network then writes to a controller."""
    b = Build(r, start)
    rogue, target = f"10.10.0.{r.choice([99, 98, 150, 201])}", r.choice(["PLC", "RTU"])
    for k in range(r.randint(2, 4)):
        b.f(b.step(5, 40), rogue, f"10.10.0.{r.choice([10, 11, 12, 30, 50, 60, 70])}", r.choice(["502", "22", "445"]))
    b.i(b.at(2), "ET SCAN Suspicious Multi-Port Connection Attempt", "Medium", rogue, "10.10.0.0/24", "Reconnaissance", A, "Reconnaissance")
    port, sig = r.choice(OT_PORTS)
    ts = b.step()
    b.f(ts, rogue, IPS[target], port)
    b.i(b.at(3), "ET SCADA " + sig, "Critical", rogue, IPS[target], "ICS-Attack", A, "Impact")
    b.d(b.at(0), target, "LOGIC_CHANGE", "unknown", f"Control value altered via {port} from {rogue}", A, "Impact")
    b.d(b.at(5), target, "STATE_CHANGE", "unknown", f"Output forced by command from {rogue}", A, "Impact")
    return b, [rogue], rogue, "internal", "Reconnaissance", [target]


def t_c2(r, start):
    """Malware on the EWS beacons to a C2 address (destination only), optional spread, OT write."""
    b, c2 = Build(r, start), ext_ip(r)
    ews, target = "EWS", r.choice(["RTU", "PLC"])
    n = r.randint(2, 4)
    for k in range(n):
        ts = b.step(60, 240)
        b.f(ts, IPS[ews], c2, "443")
        if k == 0:
            b.i(b.at(3), "ET MALWARE Known C2 Beacon Pattern", "Critical", IPS[ews], c2, "Command-And-Control", A, "Command and Control")
            b.d(b.at(25), ews, "PROCESS_START", "engineer_a", f"Process officehelper.exe started, outbound connection to {c2}", A, "Execution")
    comp = [ews]
    if r.random() < .6:
        ts = b.step()
        b.f(ts, IPS[ews], IPS["HIST"], "445")
        b.i(b.at(5), "ET EXPLOIT SMB Remote Service Creation Attempt", "High", IPS[ews], IPS["HIST"], "Lateral-Movement", A, "Lateral Movement")
        b.d(b.at(10), "HIST", "FILE_WRITE", "svc_remote", f"Remote service created via SMB from {IPS[ews]}", A, "Malware Delivery")
        comp.append("HIST")
    ot_step(b, IPS[ews], target, HOSTS[ews])
    comp.append(target)
    return b, [c2], c2, "external", "Command and Control", comp


def add_noise(b, rnd, comp_hosts, level):
    """Routine plant traffic. Level 1 = light, 3 = dense. Includes hard negatives."""
    t0 = b.t0
    end = max(b.attack_times) + timedelta(minutes=3)
    secs = int((end - t0).total_seconds())
    ts = lambda: (t0 + timedelta(seconds=rnd.randint(0, secs))).strftime(FMT)
    # periodic polling flows (repeat all through the window, so they also occur before compromise)
    flows = [(IPS["HMI"], IPS["PLC"], "502")]
    for _ in range(level + 1):
        s, d = rnd.sample(list(IPS.values()), 2)
        flows.append((s, d, rnd.choice(["502", "443", "20000", "1433"])))
    for s, d, p in flows:
        period = rnd.choice([30, 45, 60, 90])
        cur = t0
        while cur <= end:
            b.f(cur.strftime(FMT), s, d, p, B)
            cur += timedelta(seconds=period)
    for _ in range(rnd.randint(1, 3)):
        b.i(ts(), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", IPS["HMI"], IPS["PLC"], "Policy", B)
    cur = t0
    while cur <= end:
        b.d(cur.strftime(FMT), "PLC", "READ_REGISTER", "HMI-01", "Periodic poll of status register", B)
        cur += timedelta(seconds=300)
    # hard negatives on hosts the attacker touches
    for h in comp_hosts:
        if rnd.random() < .7:
            b.d(ts(), h, "AUTH_FAIL", "engineer_b", "Mistyped password (1 attempt)", B)
        if rnd.random() < .5:
            b.d(ts(), h, "LOGIN", "engineer_a", "Local login from 10.10.0.31", B)
        if rnd.random() < .5:
            b.d(ts(), h, "BACKUP_JOB", "svc_backup", "Backup job started", B)
    # legitimate remote vendor login from a different external address
    if rnd.random() < .5:
        b.d(ts(), rnd.choice(comp_hosts), "LOGIN", "vendor_support", f"Remote login succeeded from {ext_ip(rnd)}", B)
    # internal vulnerability scanner (benign reconnaissance alerts)
    if rnd.random() < .4:
        b.i(ts(), "ET SCAN Nmap Scripting Engine User-Agent Detected", "Medium", "10.10.0.40", "10.10.0.0/24", "Reconnaissance", B)
    # one-off benign outbound flow from a compromised host (cannot be told apart by history alone)
    ONE_OFF = rnd.random() < .35
    if ONE_OFF:
        b.f(ts(), IPS[rnd.choice([h for h in comp_hosts if h in IPS])], ext_ip(rnd), "443", B)
    # extra random internal flows
    for _ in range(rnd.randint(0, level * 25)):
        s, d = rnd.sample(list(IPS.values()), 2)
        b.f(ts(), s, d, rnd.choice(["502", "443", "20000", "1433", "445"]), B)


TEMPLATES = [("remote_access", t_remote_access), ("vpn_chain", t_vpn_chain),
             ("insider", t_insider), ("c2_beacon", t_c2)]


def make(template_fn, seed, folder):
    rnd = random.Random(seed)
    start = datetime(2026, 9, 1, 8, 0, 0) + timedelta(days=rnd.randint(0, 40), minutes=rnd.randint(0, 600))
    b, seeds, entry, origin, vector, comp = template_fn(rnd, start)
    add_noise(b, rnd, comp, level=rnd.randint(1, 3))
    w0 = min(b.attack_times) - timedelta(minutes=rnd.randint(1, 3))
    w1 = max(b.attack_times) + timedelta(minutes=rnd.randint(1, 3))
    cols = {"firewall.log": ["timestamp", "action", "src_ip", "dst_ip", "dst_port", "protocol", "label", "true_stage"],
            "ids_alerts.log": ["timestamp", "signature", "severity", "src_ip", "dst_ip", "category", "label", "true_stage"],
            "device.log": ["timestamp", "device", "event_type", "user", "description", "label", "true_stage"]}
    data = {"firewall.log": b.fw, "ids_alerts.log": b.ids, "device.log": b.dev}
    for fn, rows in data.items():
        with open(os.path.join(folder, fn), "w", newline="") as f:
            w = csv.writer(f); w.writerow(cols[fn]); w.writerows(sorted(rows, key=lambda x: x[0]))
    incident = {"seed_ips": seeds, "window_start": w0.strftime(FMT), "window_end": w1.strftime(FMT)}
    # earliest stage-bearing attack record defines the initial vector (same definition the RCA uses)
    ev = sorted([(x[0], x[7]) for x in b.ids if x[6] == A] + [(x[0], x[6]) for x in b.dev if x[5] == A])
    vector = ev[0][1]
    truth = {"initial_vector": vector, "entry_ip": entry, "origin_type": origin,
             "compromised_ips": sorted({IPS[h] for h in comp})}
    return incident, truth, [os.path.join(folder, fn) for fn in data]


KEYS = ["corr_precision", "corr_recall", "corr_f1", "stage_accuracy", "sequence_similarity", "rca_assets_f1"]
BOOLS = ["rca_vector_ok", "rca_entry_ok", "rca_origin_ok"]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    base_seed = int(sys.argv[2]) if len(sys.argv) > 2 else 2026
    rows = []
    for ti, (tname, fn) in enumerate(TEMPLATES):
        for k in range(n):
            seed = base_seed * 1000 + ti * 100 + k
            tmp = tempfile.mkdtemp(prefix="heldout_")
            try:
                inc, truth, files = make(fn, seed, tmp)
                scoped = scope_evidence(load_all_evidence(*files), inc["window_start"], inc["window_end"])
                res = {"template": tname, "seed": seed, "in_scope": len(scoped),
                       "attack": sum(1 for r in scoped if r.raw.get("label") == "ATTACK")}
                res["baseline"] = evaluate_run(run_baseline(scoped), scoped, truth)
                res["improved"] = evaluate_run(run_improved(scoped, inc["seed_ips"]), scoped, truth)
                rows.append(res)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    def agg(sel, which):
        out = {k: statistics.mean(r[which][k] for r in sel) for k in KEYS}
        out.update({k: sum(1 for r in sel if r[which][k]) for k in BOOLS})
        return out

    L = [f"# Held-out randomized test ({len(rows)} scenarios, seed {base_seed})", "",
         "Random scenarios (attacker address, hosts, ports, steps, timing, noise). Not used to tune the rules.", ""]
    L += ["| Template | n | Method | Precision | Recall | F1 | Stage acc | Sequence | Asset F1 | Vector | Entry IP | Origin |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    groups = [(t, [r for r in rows if r["template"] == t]) for t, _ in TEMPLATES] + [("ALL", rows)]
    for name, sel in groups:
        for which in ("baseline", "improved"):
            a = agg(sel, which)
            L.append(f"| {name} | {len(sel)} | {which} | {a['corr_precision']:.2f} | {a['corr_recall']:.2f} | {a['corr_f1']:.2f} | "
                     f"{a['stage_accuracy']:.2f} | {a['sequence_similarity']:.2f} | {a['rca_assets_f1']:.2f} | "
                     f"{a['rca_vector_ok']}/{len(sel)} | {a['rca_entry_ok']}/{len(sel)} | {a['rca_origin_ok']}/{len(sel)} |")
    worst = sorted(rows, key=lambda r: r["improved"]["corr_f1"])[:8]
    L += ["", "## Weakest improved-method runs", "", "| Template | Seed | TP | FP | FN | F1 | Vector | Entry | Origin | Assets F1 |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in worst:
        i = r["improved"]
        L.append(f"| {r['template']} | {r['seed']} | {i['tp']} | {i['fp']} | {i['fn']} | {i['corr_f1']:.2f} | "
                 f"{'ok' if i['rca_vector_ok'] else 'WRONG'} | {'ok' if i['rca_entry_ok'] else 'WRONG'} | "
                 f"{'ok' if i['rca_origin_ok'] else 'WRONG'} | {i['rca_assets_f1']:.2f} |")
    print("\n".join(L))
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    open(os.path.join(OUTPUT_DIR, "heldout_results.md"), "w").write("\n".join(L) + "\n")
    json.dump(rows, open(os.path.join(OUTPUT_DIR, "heldout_results.json"), "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
