"""
Configuration for the DDoS TCP SYN Flood XAI component (network-flood family: TCP SYN · UDP · ICMP) (Edge-IIoTset).

All paths are resolved relative to this file so the package works the same on
Windows (D:\\4Y1S\\research\\J26-CS-328\\dev\\backend\\component2_xai\\DDoS_tcp)
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

MODEL_PATH = ARTIFACTS_DIR / "rf_ddos_tcp.joblib"
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
# Network floods (Edge-IIoTset classes DDoS_TCP, DDoS_UDP, DDoS_ICMP). This package detects the
# floods listed in ATTACK_LABELS; the same code serves DDoS_tcp (TCP SYN) and DDoS_icmp (ICMP).
ATTACK_LABELS = ["DDoS_TCP"]
ATTACK_LABEL = "DDoS_TCP"
CLASS_NAMES = ["Normal", "DDoS TCP SYN Flood"]
FLOOD_PROTOCOLS = ["TCP SYN"]                 # protocol() values of this flood's packets
FLOOD_PROTOCOL = "TCP SYN"                       # protocol() value of this flood's packets
FLOOD_TYPE_NAMES = {"DDoS_TCP": "TCP SYN flood", "DDoS_UDP": "UDP flood", "DDoS_ICMP": "ICMP flood"}

# Files with only the binary Attack_label (e.g. EdgeIIoT_train_80_with_incident_id.csv) get
# Attack_type derived from packet signatures, as for the HTTP-flood / SQLi labels:
#   DDoS_ICMP : attack packet with ICMP fields, not involving the scanner host, valid timestamp
#               (~10k spoofed echo packets to 192.168.0.128, 23:17-23:24, plus its replies)
#   DDoS_UDP  : attack packet with UDP fields, not involving the scanner host
#               (~11.5k spoofed packets to 192.168.0.128; the export lost their frame.time)
#   DDoS_TCP  : attack SYN (SYN=1, ACK=0) from a host outside the testbed
#               (4.8k spoofed one-packet sources to 192.168.0.128:80, 19:02-19:11).
#               SYNs from 192.168.0.170 / .128 are handshakes of other traffic, not the flood.
ICMP_COLS = ["icmp.checksum", "icmp.seq_le"]          # non-zero -> packet is ICMP
UDP_COLS = ["udp.stream", "udp.port", "udp.time_delta"]
SCANNER_HOSTS = {"192.168.0.170"}
TESTBED_HOSTS = {"192.168.0.170", "192.168.0.128"}
TIME_COL = "frame.time"
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
EXTRA_DROP_COLUMNS = ["tcp.ack_raw", "tcp.checksum", "icmp.checksum"]
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
    "icmp.seq_le": "ICMP echo sequence number",
    "udp.port": "UDP port",
    "icmp.unused": "ICMP unused/reserved field",
    "tcp.len": "TCP payload length (bytes)",
    "tcp.flags": "TCP flag bits (SYN/ACK/PSH/FIN…)",
    "tcp.flags.ack": "TCP ACK flag set",
    "tcp.ack": "Relative TCP acknowledgement number",
    "tcp.seq": "Relative TCP sequence number",
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
# Flood packets are near-identical by design; keep their repetition (normal rows are
# still de-duplicated), as in the HTTP-flood component.
DROP_DUPLICATE_ATTACK_ROWS = False

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
CONSENSUS_TOP_K = 5
CONSENSUS_WEIGHTS = {"rank": 0.25, "topk": 0.25, "direction": 0.25, "verdict": 0.25}
CONSENSUS_HIGH = 0.75
CONSENSUS_MEDIUM = 0.50
CONSENSUS_TRIAGE_MAX = 300        # packets scored in the batch consensus triage
CONSENSUS_GLOBAL_SAMPLE = 300     # held-out packets for the global consensus study
