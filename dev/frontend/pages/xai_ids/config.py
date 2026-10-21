"""
XAI-IDS configuration.

Edit DATASETS to point at your CSV files. The path can also be overridden
without editing this file by setting the XAI_IDS_DATASET environment variable.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Datasets shown in the sidebar "Dataset" dropdown  (display name -> CSV path)
# ---------------------------------------------------------------------------
DEFAULT_DATASET = os.environ.get(
    "XAI_IDS_DATASET",
    r"D:\4Y1S\research\J26-CS-328\dev\data\raw\EdgeIIoT_train_80_with_incident_id.csv",
)

DATASETS = {
    "EdgeIIoT Train (80%)": DEFAULT_DATASET,
    # "EdgeIIoT Test (20%)": r"D:\4Y1S\research\J26-CS-328\dev\data\raw\EdgeIIoT_test_20_with_incident_id.csv",
}

# ---------------------------------------------------------------------------
# Column names (auto-detected if these exact names are missing)
# ---------------------------------------------------------------------------
LABEL_COLUMN = "Attack_type"          # multi-class label (Normal, DDoS_UDP, ...)
BINARY_LABEL_COLUMN = "Attack_label"  # 0 = normal, 1 = attack
INCIDENT_ID_CANDIDATES = ["incident_id", "Incident_ID", "IncidentID", "incident ID", "Incident Id"]
TIME_CANDIDATES = ["frame.time", "timestamp", "Timestamp", "time", "datetime"]
SRC_IP_CANDIDATES = ["ip.src_host", "src_ip", "Src IP", "source_ip"]
DST_IP_CANDIDATES = ["ip.dst_host", "dst_ip", "Dst IP", "destination_ip"]

# Columns never used as model features (identifiers, labels, raw payload text)
NON_FEATURE_COLUMNS = {
    "frame.time", "ip.src_host", "ip.dst_host", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "http.file_data", "http.request.full_uri", "icmp.transmit_timestamp",
    "http.request.uri.query", "tcp.options", "tcp.payload", "tcp.srcport",
    "dns.qry.name", "mqtt.msg", "mqtt.topic", "mqtt.conack.flags", "mqtt.protoname",
    "http.request.method", "http.referer", "http.request.version",
    "Attack_label", "Attack_type",
}

# ---------------------------------------------------------------------------
# Timestamps
# Edge-IIoT's frame.time is frequently malformed. If fewer than
# MIN_VALID_TIME_RATIO of rows parse, synthetic timestamps are assigned in
# file order, starting at SYNTHETIC_START and spaced SYNTHETIC_INTERVAL_SEC apart.
# ---------------------------------------------------------------------------
MIN_VALID_TIME_RATIO = 0.9
SYNTHETIC_START = "2026-09-21 08:00:00"
SYNTHETIC_INTERVAL_SEC = 1.0

# ---------------------------------------------------------------------------
# Severity per attack type (anything unlisted falls back to DEFAULT_SEVERITY)
# ---------------------------------------------------------------------------
SEVERITY_MAP = {
    "Normal": "Low",
    "Ransomware": "Critical",
    "Backdoor": "Critical",
    "DDoS_UDP": "High",
    "DDoS_ICMP": "High",
    "DDoS_TCP": "High",
    "DDoS_HTTP": "High",
    "SQL_injection": "High",
    "Password": "High",
    "MITM": "High",
    "Uploading": "High",
    "XSS": "Medium",
    "Port_Scanning": "Medium",
    "Vulnerability_scanner": "Medium",
    "Fingerprinting": "Medium",
}
DEFAULT_SEVERITY = "Medium"

# Friendlier display names for attack types
TYPE_DISPLAY = {
    "Port_Scanning": "Port Scan",
    "Vulnerability_scanner": "Vuln Scan",
    "SQL_injection": "SQL Injection",
    "Password": "Brute Force",
}

# ---------------------------------------------------------------------------
# Model
# If MODEL_PATH exists it is loaded; otherwise a Random Forest is trained on a
# stratified sample of the dataset at first start and saved there.
# ---------------------------------------------------------------------------
MODEL_PATH = BASE_DIR / "models" / "rf_edgeiiot.joblib"
TRAIN_SAMPLE_SIZE = 150_000
RF_PARAMS = dict(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42,
                 class_weight="balanced_subsample")

# Incident statuses changed in the UI are saved here
STATUS_STORE = BASE_DIR / "status_overrides.json"

PAGE_SIZE = 25
