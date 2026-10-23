"""
config.py - every number Component 3 uses, in ONE place, with where it comes from.

Rule of the project: no value without a source. If you change a number here, change its source too.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent          # this folder; all paths start from here (no D:\ paths)
DATA_DIR = HERE / "data"                        # alerts from Component 1, asset registry
EVID_DIR = DATA_DIR                             # evidence/, survey/, expert/ are sub-folders of data/
OUTPUT_DIR = HERE / "outputs"                   # generated files and exported incidents, not committed
# shared, read-only, optional: the raw Edge-IIoTset capture, only for the traffic cross-check in analysis/evidence_check.py
RAW_CAPTURE_FILE = HERE.parents[1] / "data" / "raw" / "EdgeIIoT_train_80_with_incident_id.csv"

# ---- Input files ---------------------------------------------------------------------------------
ALERTS_FILE = DATA_DIR / "c1_alerts_test20.csv"                  # what Component 1 sends (docs/interfaces.md)
# The scoring code does NOT read the evidence files below. The numbers are written in this file (next section);
# these files are the EVIDENCE, and analysis/evidence_check.py + the tests verify that this file matches them.
SEVERITY_FILE = EVID_DIR / "evidence" / "severity_sources.csv"  # evidence for SEVERITY below
IP_ROLE_FILE = EVID_DIR / "evidence" / "ip_role_evidence.csv"   # evidence for ASSETS below (paper tables + traffic)
GROUP_MATRIX_FILE = EVID_DIR / "evidence" / "survey_group_matrix.csv"   # AHP survey group matrix (n = 15)

# ---- Output files --------------------------------------------------------------------------------
SCORED_FILE = OUTPUT_DIR / "scored_alerts.csv"                  # big, regenerated, not committed
LIVE_FILE = OUTPUT_DIR / "live_scored.jsonl"                    # big, regenerated, not committed
REPORT_DIR = HERE / "docs" / "results"                          # small text reports: committed as evidence
CALIBRATION_REPORT = REPORT_DIR / "calibration_report.txt"

# ---- Evidence inputs (the surveys and the expert ratings) ------------------------------------------
SURVEY1_FILE = EVID_DIR / "survey" / "survey1_ahp_responses.csv"      # 15 respondents, free-text comments removed
SURVEY2_FILE = EVID_DIR / "survey" / "survey2_responses.csv"          # 10 respondents
ASSET_EVIDENCE_FILE = EVID_DIR / "evidence" / "asset_sources.csv"
EXPERT_DIR = EVID_DIR / "expert"                                      # one returned rating sheet per human rater
EXPERT_KEY_FILE = EXPERT_DIR / "expert_sample_key.csv"                # sheet number -> flow_id

# ---- Weights of the four factors -----------------------------------------------------------------
# SOURCE: AHP pairwise-comparison survey, 15 respondents, geometric-mean group matrix (Saaty, 1980;
# Forman and Peniwati, 1998), principal eigenvector, group consistency ratio 0.031 (limit 0.10).
# Rounded to 4 decimals; they add up to 1. tests/test_component3.py recomputes them from the matrix.
WEIGHTS = {"severity": 0.3154, "confidence": 0.1718, "asset": 0.4158, "frequency": 0.0970}


# ---- Severity of each attack type (1 = very low ... 5 = very high) --------------------------------------------
# EVIDENCE FILE: data/evidence/severity_sources.csv (reference, URL, note per row).
# Published rating = MITRE CAPEC "Typical Severity", mapped Very Low..Very High -> 1..5 in equal steps (our convention).
# CAPEC gives no rating for SQL injection, Backdoor or Ransomware: those three are the median of survey 2 (n = 10).
SEVERITY = {
    "Fingerprinting":        1,   # CAPEC-224 Fingerprinting: Very Low
    "Port_Scanning":         2,   # CAPEC-300 Port Scanning: Low
    "Vulnerability_scanner": 2,   # CAPEC-310 Scanning for Vulnerable Software: Low (mapping is a judgement)
    "DDoS_UDP":              3,   # CAPEC-486 UDP Flood: inherits CAPEC-125 Flooding: Medium
    "DDoS_ICMP":             3,   # CAPEC-487 ICMP Flood: inherits CAPEC-125 Flooding: Medium
    "DDoS_TCP":              3,   # CAPEC-482 TCP Flood: inherits CAPEC-125 Flooding: Medium
    "DDoS_HTTP":             3,   # CAPEC-488 HTTP Flood: inherits CAPEC-125 Flooding: Medium
    "Password":              4,   # CAPEC-49 Password Brute Forcing: High (mapping is a judgement)
    "Uploading":             4,   # CAPEC-650 Upload a Web Shell to a Web Server: High (mapping is a judgement)
    "SQL_injection":         4,   # survey 2 median (n = 10, IQR 3-4); CAPEC-66 shows no rating
    "MITM":                  5,   # CAPEC-94 Adversary in the Middle: Very High (mapping is a judgement)
    "XSS":                   5,   # CAPEC-63 Cross-Site Scripting: Very High
    "Backdoor":              5,   # survey 2 median (n = 10, IQR 4-5); no matching CAPEC entry
    "Ransomware":            5,   # survey 2 median (n = 10, IQR 3.5-5); ATT&CK T1486 has no severity rating
}

# ---- Asset criticality (1-5) by device role ----------------------------------------------------------------------
# EVIDENCE FILE: evidence/asset_sources.csv. SOURCE: survey 2 median (n = 10, mostly junior respondents) of how much
# the plant suffers if the device is unavailable. Idea from CVSS v3.1 "Environmental: Security Requirements".
# Honest limit: every role was rated 4 or 5, so this factor separates alerts only a little.
ROLE_CRITICALITY = {
    "control_endpoint": 5,   # survey 2 median 5 (IQR 5-5)
    "sensor_client":    4,   # survey 2 median 4 (IQR 3-4.75)
    "unregistered":     4,   # survey 2 median 4 (IQR 3.25-4)
}

# ---- Which device is which IP address ------------------------------------------------------------------------------
# EVIDENCE FILE: evidence/ip_role_evidence.csv. SOURCE of the roles: the Edge-IIoTset paper (Ferrag, Friha, Hamouda,
# Maglaras and Janicke, 2022, TechRxiv, doi 10.36227/techrxiv.18857336.v1):
#   Table VI  192.168.0.128 = Edge server (Raspberry Pi with the Mosquitto MQTT broker; Modbus/TCP server row too)
#             192.168.0.101 = IoT sensor node (DHT11 temperature and humidity sensor; Modbus sensor row too)
#   Table V   192.168.0.170 = attacker address for most attacks (not an inventory device)
# Cross-check on the capture: Modbus port 502 goes to .128 (evidence file has the counts).
# Limit: Table V also lists 192.168.0.101 beside the man-in-the-middle attacks; the paper does not explain why.
# OT-004 and OT-005 are made-up what-if devices for the demo (solar farm); no dataset traffic reaches them.
ASSETS = {
    "OT-001": {"ip": "192.168.0.128", "role": "control_endpoint", "name": "Control endpoint (Modbus/TCP + MQTT + HTTP)"},
    "OT-002": {"ip": "192.168.0.101", "role": "sensor_client",    "name": "Sensor/monitor client (MQTT)"},
    "OT-003": {"ip": "192.168.0.170", "role": "unregistered",     "name": "Attack-source host (sends only attack flows)"},
    "OT-004": {"ip": "",              "role": "control_endpoint", "name": "Renewable Energy Controller (what-if only)"},
    "OT-005": {"ip": "",              "role": "sensor_client",    "name": "Monitoring Server (what-if only)"},
    "OT-000": {"ip": "",              "role": "unregistered",     "name": "Unregistered / unidentified destination"},
}

# ---- Frequency -----------------------------------------------------------------------------------
# SOURCE: the data. 97.4% of gaps between alerts of the same attack on the same target are <= 60 s,
# and the 99th percentile of the 60-second counts is about 467, so a count of 500 scores the maximum.
WINDOW_SECONDS = 60
WINDOW_CAP = 500

# ---- Priority levels -----------------------------------------------------------------------------
# SOURCE: FIRST CVSS v3.1 qualitative severity rating scale (Low < 4.0, Medium 4.0-6.9, High 7.0-8.9,
# Critical >= 9.0) applied to score / 10. A BORROWED scale: designed for vulnerabilities, optional,
# and not a validation of this score. The order of the queue does not depend on these cut-offs.
LEVEL_CUTOFFS = {"Critical": 90, "High": 70, "Medium": 40}      # below 40 = Low
LEVELS = ["Critical", "High", "Medium", "Low"]

# ---- Other ---------------------------------------------------------------------------------------
NOT_AN_ALERT = "Normal"          # flows the detector calls Normal are not alerts
FALLBACK_ASSET_ID = "OT-000"     # target IP not in the registry (rating = survey median, flagged in the output)
CALIBRATION_FOLDS = 5            # cross-fitting folds for the confidence calibration
CALIBRATION_SEED = 42
CALIBRATION_MIN_CLASS_ROWS = 100 # a class with fewer rows uses its plain precision instead of isotonic
