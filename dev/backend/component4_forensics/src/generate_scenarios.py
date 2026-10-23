"""
Scenario generator for the energy plant forensic framework (Week 2).

Creates three scripted attack scenarios under data/<scenario>/:
    firewall.log, ids_alerts.log, device.log   - IT + OT evidence (with benign noise)
    incident.json                              - mimics the confirmed-incident handoff
                                                 from Component 3 (SOC prioritization)
    ground_truth.json                          - expected root-cause answers

Every log line carries two extra columns that the pipeline NEVER reads:
    label       ATTACK | BENIGN
    true_stage  the attack stage the line belongs to (ground truth, for evaluation)
They are used only by evaluate.py to score the pipeline.

Scenarios
    1. scenario1_rdp_to_breaker   external attacker, RDP -> brute force -> malware -> breaker PLC
    2. scenario2_vpn_lateral_ems  stolen vendor VPN account -> historian -> EMS -> protection relay
    3. scenario3_insider_modbus   rogue INTERNAL laptop sweeps OT network, writes to breaker PLC
"""

import csv
import json
import os
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

FW_COLS = ["timestamp", "action", "src_ip", "dst_ip", "dst_port", "protocol", "label", "true_stage"]
IDS_COLS = ["timestamp", "signature", "severity", "src_ip", "dst_ip", "category", "label", "true_stage"]
DEV_COLS = ["timestamp", "device", "event_type", "user", "description", "label", "true_stage"]

A, B = "ATTACK", "BENIGN"
NC = "Network Connection"


def dt(date, hms):
    return datetime.strptime(f"{date} {hms}", "%Y-%m-%d %H:%M:%S")


def span(date, start, end, step_seconds):
    cur, stop = dt(date, start), dt(date, end)
    while cur <= stop:
        yield cur.strftime("%Y-%m-%d %H:%M:%S")
        cur += timedelta(seconds=step_seconds)


def write_csv(path, cols, rows):
    rows = sorted(rows, key=lambda r: r[0])
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)


def benign_noise(date, start, end):
    """Routine plant traffic that must NOT end up in the attack timeline."""
    fw, ids, dev = [], [], []
    for ts in span(date, start, end, 60):                      # HMI polls PLC every minute
        fw.append((ts, "ALLOW", "10.10.0.20", "10.10.0.50", 502, "TCP", B, ""))
    for ts in span(date, start, end, 300):                     # PLC register reads
        dev.append((ts, "Substation-Breaker-PLC-10.10.0.50", "READ_REGISTER", "HMI-01",
                    "Periodic poll of breaker status register", B, ""))
    return fw, ids, dev


def save_scenario(name, fw, ids, dev, incident, truth):
    folder = os.path.join(DATA, name)
    os.makedirs(folder, exist_ok=True)
    write_csv(os.path.join(folder, "firewall.log"), FW_COLS, fw)
    write_csv(os.path.join(folder, "ids_alerts.log"), IDS_COLS, ids)
    write_csv(os.path.join(folder, "device.log"), DEV_COLS, dev)
    with open(os.path.join(folder, "incident.json"), "w") as f:
        json.dump(incident, f, indent=2)
    with open(os.path.join(folder, "ground_truth.json"), "w") as f:
        json.dump(truth, f, indent=2)
    print(f"  wrote {name}: {len(fw)} firewall, {len(ids)} ids, {len(dev)} device lines")


# --------------------------------------------------------------------------
def scenario1():
    d = "2026-09-10"
    t = lambda hms: f"{d} {hms}"
    EWS, PLC = "SCADA-EWS-10.10.0.10", "Substation-Breaker-PLC-10.10.0.50"
    atk = "203.0.113.55"
    fw, ids, dev = benign_noise(d, "08:50:00", "09:20:00")

    fw += [
        (t("09:00:12"), "ALLOW", atk, "10.10.0.10", 3389, "TCP", A, NC),
        (t("09:03:40"), "ALLOW", atk, "10.10.0.10", 22, "TCP", A, NC),
        (t("09:03:41"), "ALLOW", atk, "10.10.0.11", 22, "TCP", A, NC),
        (t("09:03:42"), "ALLOW", atk, "10.10.0.12", 22, "TCP", A, NC),
        (t("09:03:43"), "ALLOW", atk, "10.10.0.50", 502, "TCP", A, NC),
        (t("09:05:02"), "ALLOW", atk, "10.10.0.10", 22, "TCP", A, NC),
        (t("09:08:01"), "ALLOW", atk, "10.10.0.10", 445, "TCP", A, NC),
        (t("09:10:00"), "ALLOW", "10.10.0.10", "10.10.0.50", 502, "TCP", A, NC),
    ]
    ids += [
        (t("09:03:45"), "ET SCAN Nmap Scripting Engine User-Agent Detected", "Medium", atk, "10.10.0.0/24", "Reconnaissance", A, "Reconnaissance"),
        (t("09:03:50"), "ET SCAN Suspicious Multi-Port Connection Attempt", "Medium", atk, "10.10.0.0/24", "Reconnaissance", A, "Reconnaissance"),
        (t("09:05:10"), "ET POLICY SSH Brute Force Login Attempt", "High", atk, "10.10.0.10", "Credential-Access", A, "Credential Access"),
        (t("09:08:05"), "ET MALWARE Possible Malicious Payload Upload via SMB", "Critical", atk, "10.10.0.10", "Malware", A, "Malware Delivery"),
        (t("09:10:05"), "ET SCADA Modbus Write Function Code Anomaly - Breaker Control Register", "Critical", "10.10.0.10", "10.10.0.50", "ICS-Attack", A, "Impact"),
        # benign IDS noise
        (t("09:02:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
        (t("09:07:30"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
        (t("09:12:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
    ]
    dev += [
        (t("09:00:15"), EWS, "LOGIN", "unknown_admin", f"Remote desktop login succeeded from {atk}", A, "Initial Access"),
        (t("09:05:12"), EWS, "AUTH_FAIL", "root", "SSH authentication failed (4 attempts)", A, "Credential Access"),
        (t("09:05:28"), EWS, "AUTH_SUCCESS", "root", "SSH authentication succeeded after brute force", A, "Credential Access"),
        (t("09:08:10"), EWS, "FILE_WRITE", "root", "New executable written to /tmp/update_agent.bin", A, "Malware Delivery"),
        (t("09:08:12"), EWS, "PROCESS_START", "root", "Process update_agent.bin started", A, "Execution"),
        (t("09:09:50"), EWS, "CONFIG_ACCESS", "root", "SCADA engineering software opened, substation project file loaded", A, "Discovery"),
        (t("09:10:00"), PLC, "LOGIC_CHANGE", EWS, "Breaker control logic modified via Modbus write, trip setpoint register altered", A, "Impact"),
        (t("09:10:05"), PLC, "STATE_CHANGE", EWS, "Breaker entered unexpected operational state (output override) - risk of unplanned trip", A, "Impact"),
        # benign device noise (one deliberately hard case: a legitimate failed login on a touched host)
        (t("09:02:20"), EWS, "LOGIN", "engineer_a", "Local login from 10.10.0.31", B, ""),
        (t("09:04:00"), "HISTORIAN-10.10.0.30", "BACKUP_JOB", "svc_backup", "Nightly historian backup started", B, ""),
        (t("09:06:40"), EWS, "AUTH_FAIL", "engineer_b", "Mistyped password (1 attempt)", B, ""),
    ]
    incident = {
        "incident_id": "INC-2026-0910-01", "source_component": "SOC Alert Prioritization (Component 3)",
        "priority": "Critical", "seed_ips": [atk],
        "window_start": t("08:58:00"), "window_end": t("09:15:00"), "flagged_assets": ["10.10.0.50"],
        "upstream": {
            "illustrative_sample": True,
            "detection": {"model": "Random Forest (sample)", "predicted_class": "Modbus write anomaly",
                          "confidence": 0.94, "detected_at": t("09:10:06"), "alert_count": 5},
            "explanation": {"method": "SHAP (sample)",
                            "top_features": [
                                {"feature": "modbus_write_rate", "contribution": 0.41, "direction": "raises risk"},
                                {"feature": "src_ip_is_new", "contribution": 0.27, "direction": "raises risk"},
                                {"feature": "packets_per_second", "contribution": 0.09, "direction": "raises risk"}],
                            "summary": "A burst of Modbus writes from a host that had not written to this PLC before."},
            "prioritization": {"priority_score": 0.97, "reason": "Critical asset (breaker PLC) with a control write"},
        },
    }
    truth = {
        "initial_vector": "Initial Access", "entry_ip": atk, "origin_type": "external",
        "compromised_ips": ["10.10.0.10", "10.10.0.50"],
        "description": "External RDP login, SSH brute force, malware upload, unauthorized Modbus write to breaker PLC.",
    }
    save_scenario("scenario1_rdp_to_breaker", fw, ids, dev, incident, truth)


# --------------------------------------------------------------------------
def scenario2():
    d = "2026-09-11"
    t = lambda hms: f"{d} {hms}"
    atk = "198.51.100.23"
    VPN, HIST = "VPN-GW-10.10.0.2", "HISTORIAN-10.10.0.30"
    EMS, RTU = "EMS-SERVER-10.10.0.60", "Protection-Relay-RTU-10.10.0.70"
    fw, ids, dev = benign_noise(d, "14:15:00", "14:40:00")

    fw += [
        (t("14:20:05"), "ALLOW", atk, "10.10.0.2", 443, "TCP", A, NC),
        (t("14:23:30"), "ALLOW", "10.10.0.2", "10.10.0.30", 3389, "TCP", A, NC),
        (t("14:28:10"), "ALLOW", "10.10.0.30", "10.10.0.60", 445, "TCP", A, NC),
        (t("14:33:10"), "ALLOW", "10.10.0.60", "10.10.0.70", 2404, "TCP", A, NC),
    ]
    ids += [
        (t("14:20:10"), "ET POLICY VPN Login from Unusual Geolocation", "Medium", atk, "10.10.0.2", "Initial-Access", A, "Initial Access"),
        (t("14:23:36"), "ET POLICY RDP Session Initiated from VPN Gateway", "Medium", "10.10.0.2", "10.10.0.30", "Lateral-Movement", A, "Lateral Movement"),
        (t("14:28:15"), "ET POLICY SMB Administrative Share Access", "Medium", "10.10.0.30", "10.10.0.60", "Lateral-Movement", A, "Lateral Movement"),
        (t("14:33:05"), "ET SCADA IEC-104 Setpoint Command Anomaly", "Critical", "10.10.0.60", "10.10.0.70", "ICS-Attack", A, "Impact"),
        (t("14:22:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
        (t("14:30:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
    ]
    dev += [
        (t("14:20:08"), VPN, "VPN_LOGIN", "svc_vendor", f"VPN login succeeded from {atk} using valid vendor account", A, "Initial Access"),
        (t("14:23:35"), HIST, "RDP_SESSION", "svc_vendor", "Remote desktop session opened from 10.10.0.2", A, "Lateral Movement"),
        (t("14:26:00"), HIST, "CRED_DUMP", "svc_vendor", "Credential dumping utility executed (lsass memory access)", A, "Credential Access"),
        (t("14:28:20"), EMS, "REMOTE_LOGIN", "svc_vendor", "Administrator login from 10.10.0.30", A, "Lateral Movement"),
        (t("14:31:00"), EMS, "CONFIG_ACCESS", "svc_vendor", "EMS protection-setpoint configuration console opened", A, "Discovery"),
        (t("14:33:00"), EMS, "SETPOINT_CHANGE", "svc_vendor", "Under-frequency protection setpoint changed from 49.5 Hz to 47.0 Hz", A, "Impact"),
        (t("14:33:12"), RTU, "SETPOINT_CHANGE", EMS, "Under-frequency trip threshold modified via IEC 60870-5-104 command", A, "Impact"),
        # benign noise (one hard case: legitimate failed login on the historian during the attack)
        (t("14:24:00"), HIST, "AUTH_FAIL", "engineer_c", "Mistyped password (1 attempt)", B, ""),
        (t("14:25:00"), HIST, "BACKUP_JOB", "svc_backup", "Hourly historian backup started", B, ""),
        (t("14:32:30"), EMS, "LOGIN", "operator_b", "Console login from 10.10.0.31", B, ""),
        (t("14:32:00"), EMS, "SCHEDULED_REPORT", "svc_report", "Hourly generation report exported", B, ""),
    ]
    incident = {
        "incident_id": "INC-2026-0911-02", "source_component": "SOC Alert Prioritization (Component 3)",
        "priority": "Critical", "seed_ips": [atk],
        "window_start": t("14:18:00"), "window_end": t("14:36:00"), "flagged_assets": ["10.10.0.70"],
    }
    truth = {
        "initial_vector": "Initial Access", "entry_ip": atk, "origin_type": "external",
        "compromised_ips": ["10.10.0.2", "10.10.0.30", "10.10.0.60", "10.10.0.70"],
        "description": "Stolen vendor VPN account, lateral movement to historian and EMS, protection setpoints altered on relay RTU.",
    }
    save_scenario("scenario2_vpn_lateral_ems", fw, ids, dev, incident, truth)


# --------------------------------------------------------------------------
def scenario3():
    d = "2026-09-12"
    t = lambda hms: f"{d} {hms}"
    PLC = "Substation-Breaker-PLC-10.10.0.50"
    rogue = "10.10.0.99"
    fw, ids, dev = benign_noise(d, "22:35:00", "22:50:00")

    fw += [
        (t("22:40:02"), "ALLOW", rogue, "10.10.0.20", 502, "TCP", A, NC),
        (t("22:40:03"), "ALLOW", rogue, "10.10.0.30", 502, "TCP", A, NC),
        (t("22:40:04"), "ALLOW", rogue, "10.10.0.50", 502, "TCP", A, NC),
        (t("22:41:30"), "ALLOW", rogue, "10.10.0.50", 502, "TCP", A, NC),
    ]
    ids += [
        (t("22:40:05"), "ET SCAN Internal Host Sweep on Modbus Port", "Medium", rogue, "10.10.0.0/24", "Reconnaissance", A, "Reconnaissance"),
        (t("22:41:35"), "ET SCADA Modbus Write Function Code Anomaly - Unauthorized Source", "Critical", rogue, "10.10.0.50", "ICS-Attack", A, "Impact"),
        (t("22:38:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
        (t("22:44:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
    ]
    dev += [
        (t("22:41:36"), PLC, "LOGIC_CHANGE", rogue, f"Breaker control logic modified via Modbus write from {rogue}, trip setpoint register altered", A, "Impact"),
        (t("22:41:40"), PLC, "STATE_CHANGE", rogue, "Breaker entered unexpected operational state (output override) - risk of unplanned trip", A, "Impact"),
        (t("22:39:00"), "SCADA-EWS-10.10.0.10", "LOGIN", "engineer_a", "Local login from 10.10.0.31", B, ""),
    ]
    incident = {
        "incident_id": "INC-2026-0912-03", "source_component": "SOC Alert Prioritization (Component 3)",
        "priority": "Critical", "seed_ips": [rogue],
        "window_start": t("22:38:00"), "window_end": t("22:45:00"), "flagged_assets": ["10.10.0.50"],
    }
    truth = {
        "initial_vector": "Reconnaissance", "entry_ip": rogue, "origin_type": "internal",
        "compromised_ips": ["10.10.0.50"],
        "description": "Rogue internal laptop sweeps the OT network then writes directly to the breaker PLC (insider / unauthorized device).",
    }
    save_scenario("scenario3_insider_modbus", fw, ids, dev, incident, truth)


# --------------------------------------------------------------------------
def scenario4():
    """Phishing-delivered malware on the EWS beacons to an external C2 server, spreads to the
    historian over SMB and sends a DNP3 write to a protection relay RTU.
    The SOC seed is the C2 address, which only ever appears as a DESTINATION."""
    d = "2026-09-12"
    t = lambda hms: f"{d} {hms}"
    EWS, HIST, RTU = "SCADA-EWS-10.10.0.10", "HISTORIAN-10.10.0.30", "Protection-Relay-RTU-10.10.0.70"
    c2 = "198.51.100.77"
    fw, ids, dev = benign_noise(d, "10:00:00", "10:35:00")

    fw += [
        (t("10:12:05"), "ALLOW", "10.10.0.10", c2, 443, "TCP", A, NC),
        (t("10:17:05"), "ALLOW", "10.10.0.10", c2, 443, "TCP", A, NC),
        (t("10:19:30"), "ALLOW", "10.10.0.10", "10.10.0.30", 445, "TCP", A, NC),
        (t("10:22:05"), "ALLOW", "10.10.0.10", c2, 443, "TCP", A, NC),
        (t("10:24:10"), "ALLOW", "10.10.0.10", "10.10.0.70", 20000, "TCP", A, NC),
        # benign: EWS legitimately reaches a vendor update server (hard case, seen before and after the attack starts)
        (t("10:11:00"), "ALLOW", "10.10.0.10", "203.0.113.200", 443, "TCP", B, ""),
        (t("10:26:00"), "ALLOW", "10.10.0.10", "203.0.113.200", 443, "TCP", B, ""),
        (t("10:14:00"), "ALLOW", "10.10.0.30", "10.10.0.60", 1433, "TCP", B, ""),
    ]
    ids += [
        (t("10:12:08"), "ET MALWARE Known C2 Beacon Pattern", "Critical", "10.10.0.10", c2, "Command-And-Control", A, "Command and Control"),
        (t("10:19:35"), "ET EXPLOIT SMB Remote Service Creation Attempt", "High", "10.10.0.10", "10.10.0.30", "Lateral-Movement", A, "Lateral Movement"),
        (t("10:24:12"), "ET SCADA DNP3 Direct Operate Anomaly - Relay Control Point", "Critical", "10.10.0.10", "10.10.0.70", "ICS-Attack", A, "Impact"),
        (t("10:15:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
        (t("10:21:00"), "ET POLICY Modbus Read Burst (Periodic Polling)", "Low", "10.10.0.20", "10.10.0.50", "Policy", B, ""),
    ]
    dev += [
        (t("10:12:30"), EWS, "PROCESS_START", "engineer_a", f"Process officehelper.exe started, outbound connection to {c2}", A, "Execution"),
        (t("10:19:00"), EWS, "CRED_DUMP", "engineer_a", "Credential store accessed by officehelper.exe", A, "Credential Access"),
        (t("10:19:45"), HIST, "FILE_WRITE", "svc_remote", "Remote service created via SMB from 10.10.0.10", A, "Malware Delivery"),
        (t("10:24:10"), RTU, "SETPOINT_CHANGE", EWS, "Relay trip setpoint altered via DNP3 direct operate", A, "Impact"),
        (t("10:24:15"), RTU, "STATE_CHANGE", EWS, "Protection relay output forced - risk of unplanned trip", A, "Impact"),
        (t("10:15:00"), EWS, "LOGIN", "engineer_b", "Local login from 10.10.0.31", B, ""),
        (t("10:16:10"), EWS, "AUTH_FAIL", "engineer_b", "Mistyped password (1 attempt)", B, ""),
        (t("10:18:00"), HIST, "BACKUP_JOB", "svc_backup", "Historian backup started", B, ""),
    ]
    incident = {
        "incident_id": "INC-2026-0912-01", "source_component": "SOC Alert Prioritization (Component 3)",
        "priority": "Critical", "seed_ips": [c2],
        "window_start": t("10:10:00"), "window_end": t("10:30:00"), "flagged_assets": ["10.10.0.70"],
        "upstream": {
            "illustrative_sample": True,
            "detection": {"model": "Random Forest (sample)", "predicted_class": "C2 beaconing",
                          "confidence": 0.91, "detected_at": t("10:12:09"), "alert_count": 3},
            "explanation": {"method": "SHAP (sample)",
                            "top_features": [
                                {"feature": "periodic_outbound_interval", "contribution": 0.38, "direction": "raises risk"},
                                {"feature": "dst_ip_is_external_rare", "contribution": 0.29, "direction": "raises risk"}],
                            "summary": "Regular outbound connections from an engineering workstation to a rarely seen external address."},
            "prioritization": {"priority_score": 0.95, "reason": "Engineering workstation with a path to protection relays"},
        },
    }
    truth = {
        "initial_vector": "Command and Control", "entry_ip": c2, "origin_type": "external",
        "compromised_ips": ["10.10.0.10", "10.10.0.30", "10.10.0.70"],
        "description": "Malware on the EWS beacons to an external C2 server, spreads to the historian over SMB and sends a DNP3 write to the protection relay RTU.",
    }
    save_scenario("scenario4_c2_beacon_dnp3", fw, ids, dev, incident, truth)


if __name__ == "__main__":
    print("Generating scenarios into", DATA)
    scenario1()
    scenario2()
    scenario3()
    scenario4()
    print("Done.")
