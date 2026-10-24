"""
Configuration for the DDoS HTTP Flood XAI component (Edge-IIoTset).

All paths are resolved relative to this file so the package works the same on
Windows (D:\\4Y1S\\research\\J26-CS-328\\dev\\backend\\component2_xai\\DDoS_http)
and Linux.
"""
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
PACKAGE_DIR = Path(__file__).resolve().parent
ARTIFACTS_DIR = PACKAGE_DIR / "artifacts"
# Default dataset for the dashboard (dev/data/raw/...); the sidebar can override it.
DATASET_PATH = PACKAGE_DIR.parents[2] / "data" / "raw" / "EdgeIIoT_train_80_with_incident_id.csv"

MODEL_PATH = ARTIFACTS_DIR / "rf_ddos_http.joblib"
ENCODER_PATH = ARTIFACTS_DIR / "feature_encoder.joblib"
SURROGATE_PATH = ARTIFACTS_DIR / "surrogate_tree.joblib"
METRICS_PATH = ARTIFACTS_DIR / "metrics.json"
GLOBAL_XAI_PATH = ARTIFACTS_DIR / "global_explanations.json"
SHAP_SAMPLE_PATH = ARTIFACTS_DIR / "shap_sample.npz"
BACKGROUND_PATH = ARTIFACTS_DIR / "background.parquet"
SAMPLE_TRAFFIC_PATH = ARTIFACTS_DIR / "sample_traffic.csv"
BASELINE_PATH = ARTIFACTS_DIR / "class_baselines.json"

# --------------------------------------------------------------------------- #
# Labels
# --------------------------------------------------------------------------- #
LABEL_COL = "Attack_type"
BINARY_LABEL_COL = "Attack_label"
NORMAL_LABEL = "Normal"
# Edge-IIoTset names the class "DDoS_HTTP"; matched case-insensitively.
ATTACK_LABEL = "DDoS_HTTP"
CLASS_NAMES = ["Normal", "DDoS HTTP Flood"]

# Files with only the binary Attack_label (e.g. EdgeIIoT_train_80_with_incident_id.csv)
# get Attack_type derived the same way as the SQLi model's labels: an attack row
# is DDoS_HTTP when its request hits the flood target. In Edge-IIoTset the flood
# repeats one URL (http://192.168.0.128/dvwa/vulnerabilities/) for ~2 hours,
# unlike the scanner / SQLi / upload / brute-force requests that vary the URL.
FLOOD_URI_COL = "http.request.full_uri"
FLOOD_URI_REGEX = r"^https?://[^/]+/dvwa/vulnerabilities/?$"
OTHER_ATTACK_LABEL = "Other_attack"

# --------------------------------------------------------------------------- #
# Feature selection
# --------------------------------------------------------------------------- #
# Columns dropped by the Edge-IIoTset authors (Ferrag et al., 2022, Sec. V):
# identifiers, IPs, ports, timestamps and raw payloads that would let a model
# memorise the testbed instead of learning attack behaviour.
PAPER_DROP_COLUMNS = [
    "frame.time", "ip.src_host", "ip.dst_host",
    "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "http.file_data", "http.request.full_uri", "icmp.transmit_timestamp",
    "http.request.uri.query", "tcp.options", "tcp.payload",
    "tcp.srcport", "tcp.dstport", "udp.port", "mqtt.msg",
]

# Extra near-identifier columns dropped here: raw sequence numbers and
# checksums are effectively random per packet and leak capture artefacts.
# FIX M1: tcp.seq and tcp.ack are relative sequence/acknowledgement numbers
# that encode session order, not attack behaviour — keeping them lets the
# model memorise capture position instead of learning flood patterns.
EXTRA_DROP_COLUMNS = [
    "tcp.ack_raw", "tcp.checksum", "icmp.checksum",
    "tcp.seq", "tcp.ack",
]
# Row identifiers added by the project's EdgeIIoT_train_80 export.
EXTRA_DROP_COLUMNS += ["Incident ID", "Incident_ID"]

DROP_COLUMNS = PAPER_DROP_COLUMNS + EXTRA_DROP_COLUMNS + [LABEL_COL, BINARY_LABEL_COL, "__source"]

# Human-readable descriptions shown in the dashboard explanations.
FEATURE_DESCRIPTIONS = {
    "http.request.method": "HTTP request method (GET/POST…)",
    "http.request.version": "HTTP protocol version",
    "http.response": "Packet is an HTTP response",
    "http.content_length": "HTTP Content-Length header",
    "http.referer": "HTTP Referer header present/value",
    "http.tls_port": "Plain HTTP seen on a TLS port",
    "tcp.len": "TCP payload length (bytes)",
    "tcp.flags": "TCP flag bits (SYN/ACK/PSH/FIN…)",
    "tcp.flags.ack": "TCP ACK flag set",
    # tcp.ack and tcp.seq dropped (FIX M1 — capture-order leakage)
    "tcp.connection.syn": "Connection-opening SYN packet",
    "tcp.connection.synack": "SYN-ACK handshake reply",
    "tcp.connection.fin": "Connection-closing FIN packet",
    "tcp.connection.rst": "Connection reset (RST)",
    "udp.stream": "UDP stream index",
    "udp.time_delta": "Time since previous UDP packet",
    "mqtt.len": "MQTT message length",
    "mqtt.msgtype": "MQTT message type",
    "mqtt.topic_len": "MQTT topic length",
    "mqtt.ver": "MQTT protocol version",
    "mqtt.hdrflags": "MQTT header flags",
    "mqtt.conflags": "MQTT connect flags",
    "mqtt.protoname": "MQTT protocol name",
    "mqtt.topic": "MQTT topic",
    "dns.qry.name": "DNS query name",
    "dns.qry.name.len": "DNS query name length",
    "dns.qry.type": "DNS query type",
    "arp.opcode": "ARP operation code",
    "arp.hw.size": "ARP hardware size",
    "mbtcp.len": "Modbus/TCP length",
    "mbtcp.trans_id": "Modbus/TCP transaction id",
    "mbtcp.unit_id": "Modbus/TCP unit id",
    # FIX M5: rate-based features
    "_rate_src_pkt_count": "Total packets from this source IP",
    "_rate_src_req_count": "HTTP requests from this source IP",
    "_rate_src_req_per_s": "Requests per second from this source IP",
    "_rate_src_interval_mean": "Mean inter-packet time from this source (s)",
    "_rate_src_interval_std": "Std of inter-packet time from this source (s)",
    "_rate_win_pkt_count": "Packets in this 1-second window",
    "_rate_win_src_count": "Distinct source IPs in this 1-second window",
    "_rate_win_http_frac": "Fraction of HTTP requests in this 1-second window",
}

# --------------------------------------------------------------------------- #
# Training
# --------------------------------------------------------------------------- #
RANDOM_STATE = 42
TEST_SIZE = 0.2
# Normal traffic is ~11M rows in the full dataset; cap per file so attack and
# normal stay roughly balanced and training fits in laptop memory.
MAX_NORMAL_ROWS_PER_FILE = 15_000
MAX_ATTACK_ROWS = 120_000
# Paper preprocessing removes duplicate rows; after identifier columns are
# dropped many packets become identical, so this also prevents train/test
# leakage of identical feature vectors.
DROP_DUPLICATES = True
# FIX M1: de-duplicate ALL rows (including attack) before splitting so the
# same feature vector cannot appear in both train and test.  The original
# 17 unique attack vectors remain — they are just not repeated.
DROP_DUPLICATE_ATTACK_ROWS = True

RF_PARAMS = dict(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=2,
    class_weight="balanced",
    n_jobs=-1,
    random_state=RANDOM_STATE,
)

SURROGATE_MAX_DEPTH = 4          # global, human-readable rule set
SHAP_SAMPLE_SIZE = 600           # rows used for global SHAP / beeswarm
BACKGROUND_SIZE = 200            # background rows for SHAP / LIME
PERMUTATION_REPEATS = 5

# --------------------------------------------------------------------------- #
# NOVELTY: Multi-method XAI consensus
# --------------------------------------------------------------------------- #
# FIX M3: three fixed attribution methods (SHAP, LIME, Occlusion).
# Surrogate is a global rule check reported separately, not part of XCS.
# FIX M4: verdict is reported as pass/fail and excluded from the XCS average.
CONSENSUS_TOP_K = 5
CONSENSUS_TOP_K_VALUES = [3, 5, 10]   # M4: test overlap at several k
CONSENSUS_WEIGHTS = {"rank": 1 / 3, "topk": 1 / 3, "direction": 1 / 3}
CONSENSUS_HIGH = 0.75
CONSENSUS_MEDIUM = 0.50
DIRECTION_EPSILON = 0.01              # M4: ignore features below this magnitude
CONSENSUS_TRIAGE_MAX = 300
CONSENSUS_GLOBAL_SAMPLE = 300

# FIX M2: faithfulness deletion test
FAITHFULNESS_TOP_K = 5
FAITHFULNESS_RANDOM_REPEATS = 10

# FIX M3: LIME stability
LIME_SEED = 42
LIME_REPEATS = 3                      # run LIME this many times; report std

# --------------------------------------------------------------------------- #
# FIX M5: rate-based features (computed before identifier columns are dropped)
# --------------------------------------------------------------------------- #
RATE_WINDOW_S = 1.0                   # time window for per-window features
