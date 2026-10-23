"""
XAI-IDS backend configuration.

Paths are worked out from this file's location, so the project keeps working if
the dev folder is moved:
    <dev>/backend/common/xai_ids/config.py   <- this file
    <dev>/backend/model/                     <- trained models
    <dev>/data/raw/                          <- datasets
Override with the environment variables XAI_IDS_DATASET and XAI_IDS_MODEL_DIR.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent          # .../backend/common/xai_ids
DEV_ROOT = BASE_DIR.parents[2]                      # .../dev
MODEL_DIR = Path(os.environ.get("XAI_IDS_MODEL_DIR", DEV_ROOT / "backend" / "model"))
DATA_DIR = DEV_ROOT / "data" / "raw"

# ---------------------------------------------------------------------------
# API server
# ---------------------------------------------------------------------------
HOST = os.environ.get("XAI_IDS_BACKEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("XAI_IDS_BACKEND_PORT", 5001))
# Origins allowed to call the API from a browser (the frontend). "*" = any.
CORS_ORIGINS = os.environ.get("XAI_IDS_CORS_ORIGINS", "*")

# ---------------------------------------------------------------------------
# Datasets shown in the sidebar "Dataset" dropdown  (display name -> CSV path)
# ---------------------------------------------------------------------------
DEFAULT_DATASET = os.environ.get(
    "XAI_IDS_DATASET",
    str(DATA_DIR / "EdgeIIoT_train_80_with_incident_id.csv"),
)

DATASETS = {
    "EdgeIIoT Train (80%)": DEFAULT_DATASET,
    # "EdgeIIoT Test (20%)": str(DATA_DIR / "EdgeIIoT_test_20_with_incident_id.csv"),
}

# ---------------------------------------------------------------------------
# Column names (auto-detected if these exact names are missing)
# ---------------------------------------------------------------------------
LABEL_COLUMN = "Attack_type"          # multi-class label (Normal, DDoS_UDP, ...)
BINARY_LABEL_COLUMN = "Attack_label"  # 0 = normal, 1 = attack
# Other names tried if LABEL_COLUMN isn't in the file (case, spaces and _ ignored)
LABEL_CANDIDATES = ["Attack_type", "attack_cat", "attack", "label_name", "class", "category",
                    "label", "type", "target", "y"]
BINARY_LABEL_CANDIDATES = ["Attack_label", "is_attack", "binary_label", "label_binary"]
# If the attack type is label-encoded as numbers, map them to names here, e.g.
# LABEL_NAMES = {"0": "Backdoor", "1": "DDoS_HTTP", ..., "7": "Normal", ...}
LABEL_NAMES = {}
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
    "Attack": "High",          # used when the file only has the 0/1 Attack_label
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

# SQL injection incidents get a link to the SQLi XAI page (component 2).
# Same rule as backend/component2_xai/model/sql_model_card.json: an attack whose
# request URI hits the DVWA SQLi page. A multi-class label in SQLI_TYPES also counts.
SQLI_TYPES = {"sql_injection", "sqli", "sql injection"}
SQLI_URI_CANDIDATES = ["http.request.full_uri", "http.request.uri"]
SQLI_URI_PATTERN = "/vulnerabilities/sqli"

# DDoS HTTP Flood incidents get a link to the DDoS HTTP Flood XAI page (component 2).
# Same rule as backend/component2_xai/DDoS_http/config.py (FLOOD_URI_REGEX): an attack whose
# request is the repeated flood target URL. A multi-class label in DDOS_HTTP_TYPES also counts.
DDOS_HTTP_TYPES = {"ddos_http", "ddos http", "ddos_http_flood", "ddos http flood"}
DDOS_HTTP_URI_REGEX = r"^https?://[^/]+/dvwa/vulnerabilities/?$"

# Web Injection XAI page (SQLi · XSS · Uploading): same rules as
# backend/component2_xai/web_injection_xai.py (web_labels); SQLi incidents are included.
WEB_XSS_REGEX = r"<\s*/?\s*script|%3c\s*script|javascript\s*:|\bon(?:error|load|mouseover)\s*=|/vulnerabilities/xss"
WEB_UPLOAD_REGEX = r"/hackable/uploads/|/vulnerabilities/upload"
WEB_TEXT_COLUMNS = ["http.request.uri.query", "http.file_data"]

# DDoS ICMP Flood XAI page: same rule as backend/component2_xai/DDoS_icmp/config.py - an attack
# packet with ICMP fields that does not involve a scanner host and has a valid timestamp.
ICMP_COLUMNS = ["icmp.checksum", "icmp.seq_le"]
UDP_COLUMNS = ["udp.stream", "udp.port", "udp.time_delta"]   # UDP flood rows (Network Flood page)
ICMP_SCANNER_HOSTS = {"192.168.0.170"}

# DDoS TCP SYN Flood XAI page: same rule as backend/component2_xai/DDoS_tcp/config.py - an attack
# SYN (SYN=1, ACK=0) from a host outside the testbed (SYNs from these are handshakes of other traffic).
TESTBED_HOSTS = {"192.168.0.170", "192.168.0.128"}

# ---------------------------------------------------------------------------
# Model
# If MODEL_PATH exists it is loaded; otherwise a Random Forest is trained on a
# stratified sample of the dataset at first start and saved there.
# Uses the Component 1 V2 feature set (71 features from feature_names_15class_v2.json).
# ---------------------------------------------------------------------------
MODEL_PATH = MODEL_DIR / "rf_edgeiiot.joblib"
TRAIN_SAMPLE_SIZE = 150_000
RF_PARAMS = dict(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42,
                 class_weight="balanced_subsample")
USE_V2_FEATURES = True

# Incident statuses changed in the UI are saved here
STATUS_STORE = BASE_DIR / "status_overrides.json"

PAGE_SIZE = 25
