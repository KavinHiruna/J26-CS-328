"""
evidence_check.py - proves that the numbers written in config.py match the evidence files.

The scoring code uses config.py only. The evidence (CAPEC table, survey-2 medians, Edge-IIoTset paper tables, traffic
counts) lives in data/ (evidence/, survey/). This script compares the two and reports every difference.
Run:  python -m backend.component3_soc.analysis.evidence_check
"""
import pandas as pd

from .. import config
from ..config import (ASSETS, IP_ROLE_FILE, RAW_CAPTURE_FILE, ROLE_CRITICALITY, SEVERITY, SEVERITY_FILE, REPORT_DIR,
                      ASSET_EVIDENCE_FILE)

RAW_DATASET = RAW_CAPTURE_FILE     # shared raw capture, optional: the traffic cross-check is skipped when it is missing


def compare():
    """Return a list of (what, in_config, in_evidence, ok)."""
    results = []
    sev = pd.read_csv(SEVERITY_FILE).set_index("attack_type")["severity_used"]
    for attack in sorted(set(SEVERITY) | set(sev.index)):
        in_code = SEVERITY.get(attack)
        in_file = None if attack not in sev.index else float(sev[attack])
        results.append((f"severity {attack}", in_code, in_file, in_code is not None and in_code == in_file))
    roles = pd.read_csv(ASSET_EVIDENCE_FILE).set_index("role_key")["criticality_used"]
    for role in sorted(set(ROLE_CRITICALITY) | set(roles.index)):
        in_code = ROLE_CRITICALITY.get(role)
        in_file = None if role not in roles.index else float(roles[role])
        results.append((f"criticality {role}", in_code, in_file, in_code is not None and in_code == in_file))
    ip = pd.read_csv(IP_ROLE_FILE).fillna("").set_index("asset_id")
    for asset_id, a in ASSETS.items():
        if asset_id in ip.index:
            row = ip.loc[asset_id]
            results.append((f"IP {asset_id}", a["ip"], row["ip_address"], a["ip"] == row["ip_address"]))
            results.append((f"role {asset_id}", a["role"], row["role_key"], a["role"] == row["role_key"]))
        else:
            results.append((f"{asset_id} (what-if device, no evidence file row)", a["ip"], "-", a["ip"] == ""))
    return results


def traffic_check():
    """Re-count the evidence in the raw capture: Modbus (502) and MQTT (1883) destinations and attack-only hosts."""
    if not RAW_DATASET.exists():
        return ["(raw capture file not found: traffic cross-check skipped)"], None
    df = pd.read_csv(RAW_DATASET, usecols=["ip.src_host", "ip.dst_host", "tcp.dstport", "Attack_label"], low_memory=False)
    lines = [f"Raw capture {RAW_DATASET.name}: {len(df):,} flows"]
    modbus = df[df["tcp.dstport"] == 502]["ip.dst_host"].value_counts()
    mqtt = df[df["tcp.dstport"] == 1883]["ip.dst_host"].value_counts()
    lines.append(f"Modbus/TCP (port 502) destinations: {modbus.to_dict()}")
    lines.append(f"MQTT (port 1883) destinations: {mqtt.head(3).to_dict()}")
    attack_only = {}
    for asset_id, a in ASSETS.items():
        if a["ip"]:
            src = df[df["ip.src_host"] == a["ip"]]
            attack_only[a["ip"]] = (len(src), int((src["Attack_label"] == 0).sum()), int((src["Attack_label"] == 1).sum()))
            lines.append(f"{a['ip']} ({asset_id}) as source: {len(src):,} flows, {attack_only[a['ip']][1]:,} normal, {attack_only[a['ip']][2]:,} attack")
    ok = (modbus.index.tolist() == [ASSETS["OT-001"]["ip"]]) and attack_only[ASSETS["OT-003"]["ip"]][1] == 0
    lines.append("Cross-check: " + ("Modbus only reaches the edge server, and the attacker host sends no normal flow: OK" if ok else "DIFFERENT"))
    return lines, ok


def main():
    results = compare()
    lines = ["EVIDENCE CHECK: numbers in config.py versus evidence files", "",
             f"{'item':<42}{'config.py':>18}{'evidence file':>18}   result"]
    for what, a, b, ok in results:
        lines.append(f"{what:<42}{str(a):>18}{str(b):>18}   {'OK' if ok else 'DIFFERENT'}")
    traffic_lines, traffic_ok = traffic_check()
    lines += ["", *traffic_lines]
    all_ok = all(r[3] for r in results) and traffic_ok is not False
    lines += ["", "ALL MATCH" if all_ok else "MISMATCH: fix config.py or the evidence file"]
    text = "\n".join(lines)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "evidence_check.txt").write_text(text, encoding="utf-8")
    print(text)
    return {"ok": all_ok}


if __name__ == "__main__":
    main()
