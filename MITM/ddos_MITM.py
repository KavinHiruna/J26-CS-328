import html
import re
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="MITM Attack Analysis — Network Traffic Details",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

UNAVAILABLE = "Not available in dataset"
DEFAULT_FILE = Path(r"D:\4Y1S\research\xai_iiot_prototype\data\EdgeIIoT_train_80.csv")


def normalise_name(value):
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def find_column(columns, candidates):
    lookup = {normalise_name(col): col for col in columns}
    for candidate in candidates:
        actual = lookup.get(normalise_name(candidate))
        if actual is not None:
            return actual
    return None


def value_from(row, candidates, default=UNAVAILABLE):
    col = find_column(row.index, candidates)
    if col is None:
        return default
    value = row[col]
    if pd.isna(value):
        return default
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return default
    # In this dataset, zero often represents a protocol field that was not captured.
    return text


def format_timestamp(value):
    if value == UNAVAILABLE:
        return value
    try:
        return pd.to_datetime(value, errors="raise").strftime("%Y-%m-%d %H:%M:%S.%f")
    except (TypeError, ValueError, OverflowError):
        return value


def format_tcp_flags(value, ack_value=None, syn_value=None, fin_value=None, rst_value=None):
    if value != UNAVAILABLE:
        raw = str(value).strip().lower()
        try:
            number = int(raw, 16) if raw.startswith("0x") else int(raw)
            names = []
            if number & 0x02:
                names.append("SYN")
            if number & 0x10:
                names.append("ACK")
            if number & 0x04:
                names.append("RST")
            if number & 0x01:
                names.append("FIN")
            if number & 0x08:
                names.append("PSH")
            if number & 0x20:
                names.append("URG")
            if names:
                return f"{', '.join(names)} ({value})"
        except (TypeError, ValueError):
            pass
        return value

    names = []
    for label, val in [
        ("SYN", syn_value), ("ACK", ack_value), ("RST", rst_value), ("FIN", fin_value)
    ]:
        if val not in (None, UNAVAILABLE, "", "0", "0.0", "False", "false"):
            names.append(label)
    return ", ".join(names) if names else UNAVAILABLE


st.markdown(
    """
    <style>
    .stApp { background: #0b1119; color: #e7eef7; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    .block-container { max-width: 1450px; padding: 1.25rem 1.25rem 2rem; }
    .traffic-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 11px;
        padding: 18px 20px; box-sizing: border-box;
    }
    .panel-title {
        color: #e7eef7; font-size: 17px; font-weight: 750;
        padding-bottom: 13px; margin-bottom: 8px; border-bottom: 1px solid #2b3e52;
    }
    .panel-icon { color: #53bdf7; margin-right: 9px; }
    .detail-row {
        display: grid; grid-template-columns: minmax(145px, 0.8fr) minmax(0, 1.5fr);
        gap: 14px; padding: 9px 0; border-bottom: 1px solid #1d2b3b;
    }
    .detail-row:last-child { border-bottom: 0; }
    .detail-label { color: #93a8bd; font-size: 13px; }
    .detail-value { color: #e7eef7; font-size: 13px; line-height: 1.45; overflow-wrap: anywhere; }
    .value-chip {
        display: inline-block; background: #132b3e; color: #72d0ff;
        border: 1px solid #245574; border-radius: 5px; padding: 2px 8px;
        font-weight: 700; font-size: 12px;
    }
    .notice {
        color: #b7c7d8; background: #111d2a; border: 1px solid #293b4e;
        border-radius: 8px; padding: 10px 12px; margin: 10px 0 14px; font-size: 12px;
    }
    .metric-card {
        background: #101b28; border: 1px solid #26384c; border-radius: 10px;
        padding: 12px 14px; min-height: 88px;
    }
    .metric-label { color: #93a8bd; font-size: 12px; margin-bottom: 7px; }
    .metric-value { color: #e7eef7; font-size: 19px; font-weight: 750; overflow-wrap: anywhere; }
    .metric-sub { color: #8fa6bc; font-size: 11px; margin-top: 4px; }
    .traffic-layout {
        display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
        gap: 14px; align-items: start;
    }
    .indicator-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 11px;
        padding: 14px 16px; box-sizing: border-box; min-width: 0;
    }
    .indicator-code {
        background: #08121e; border: 1px solid #31506a; border-radius: 7px;
        padding: 9px 10px; font-family: Consolas, "Courier New", monospace;
        font-size: 12px; line-height: 1.55; color: #b9cce0; overflow-wrap: anywhere;
    }
    .indicator-line { white-space: pre-wrap; }
    .indicator-num { color: #8ca6c1; display: inline-block; width: 18px; }
    .token-red { color: #ff465b; background: #451b27; padding: 1px 4px; border-radius: 3px; font-weight: 700; }
    .token-orange { color: #ff9d52; font-weight: 700; }
    .token-yellow { color: #ffd15c; font-weight: 700; }
    .token-blue { color: #47c2ff; background: #123149; padding: 1px 4px; border-radius: 3px; font-weight: 700; }
    .indicator-legend { display: flex; flex-wrap: wrap; gap: 7px 12px; margin-top: 10px; }
    .legend-item { color: #b6c8da; font-size: 10px; display: flex; align-items: center; gap: 5px; }
    .legend-swatch { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
    .right-stack { display: flex; flex-direction: column; gap: 14px; min-width: 0; }
    .shap-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 11px;
        padding: 14px 16px; box-sizing: border-box; min-width: 0;
    }
    .shap-subtitle { color: #a9bed2; font-size: 11px; margin: -3px 0 12px 24px; }
    .shap-row {
        display: grid; grid-template-columns: 125px minmax(0, 1fr) 42px;
        gap: 8px; align-items: center; margin: 8px 0;
    }
    .shap-feature { color: #c3d3e3; font-size: 11px; text-align: right; overflow-wrap: anywhere; }
    .shap-track { height: 10px; background: #08121e; border-radius: 2px; overflow: hidden; }
    .shap-bar { height: 100%; border-radius: 2px; }
    .shap-positive { background: linear-gradient(90deg, #ff7b72, #ff4d65); }
    .shap-negative { background: #29b7f5; }
    .shap-value { color: #dbe7f3; font-size: 11px; text-align: right; }
    .lime-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 11px;
        padding: 14px 16px; box-sizing: border-box; min-width: 0;
    }
    .lime-subtitle { color: #a9bed2; font-size: 11px; margin: -3px 0 12px 24px; }
    .lime-row {
        display: grid; grid-template-columns: 130px minmax(0, 1fr) 38px;
        gap: 8px; align-items: center; margin: 8px 0;
    }
    .lime-feature { color: #c3d3e3; font-size: 11px; text-align: right; overflow-wrap: anywhere; }
    .lime-track { height: 10px; background: #08121e; border-radius: 2px; overflow: hidden; }
    .lime-bar { height: 100%; border-radius: 2px; background: linear-gradient(90deg, #ff626b, #ff4d65); }
    .lime-bar-alt { background: linear-gradient(90deg, #ffcf5a, #f5b83d); }
    .lime-value { color: #dbe7f3; font-size: 11px; text-align: right; }
    .lime-note { color: #8fa6bc; font-size: 10px; margin-top: 10px; }
    .evidence-panel {
        background: #101b28; border: 1px solid #26384c; border-radius: 11px;
        padding: 16px 18px; box-sizing: border-box; margin-top: 14px;
    }
    .evidence-grid {
        display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px; margin-top: 12px;
    }
    .evidence-card {
        background: #0c1723; border: 1px solid #293d52; border-left: 3px solid #ff9d52;
        border-radius: 7px; padding: 12px 13px; min-width: 0;
    }
    .evidence-title { color: #e7eef7; font-size: 12px; font-weight: 700; margin-bottom: 6px; }
    .evidence-description { color: #a9bed2; font-size: 11px; line-height: 1.5; }
    .evidence-number {
        display: inline-block; color: #ffb26f; font-size: 10px; font-weight: 700;
        margin-right: 6px; border: 1px solid #714a2f; background: #2c2119;
        border-radius: 4px; padding: 1px 5px; vertical-align: 1px;
    }
    @media (max-width: 850px) {
        .traffic-layout { grid-template-columns: 1fr; }
        .detail-row { grid-template-columns: 1fr; gap: 3px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("MITM Attack Analysis (XAI)")
st.caption("Explainable analysis of potential Man-in-the-Middle activity. Only fields present in the selected dataset record are displayed.")

# Load the project's Edge-IIoTset CSV; users can override it with another file.
dataset = None
dataset_name = None
if DEFAULT_FILE.is_file():
    try:
        dataset = pd.read_csv(DEFAULT_FILE, low_memory=False)
        dataset_name = DEFAULT_FILE.name
    except Exception as exc:
        st.error(f"Could not load the default dataset: {exc}")

with st.expander("Use another dataset", expanded=False):
    uploaded = st.file_uploader("Upload a CSV or Excel file", type=["csv", "xlsx", "xls"])
    if uploaded is not None:
        try:
            if uploaded.name.lower().endswith(".csv"):
                dataset = pd.read_csv(uploaded, low_memory=False)
            else:
                dataset = pd.read_excel(uploaded)
            dataset_name = uploaded.name
        except Exception as exc:
            st.error(f"Could not read the uploaded file: {exc}")
            st.stop()

if dataset is None:
    st.error(
        f"Dataset not found at {DEFAULT_FILE}. Check the path or upload the CSV above."
    )
    st.stop()
if dataset.empty:
    st.error("The selected dataset contains no rows.")
    st.stop()

st.markdown(
    f'<div class="notice"><b>Dataset:</b> {html.escape(str(dataset_name))}'
    f' &nbsp; | &nbsp; <b>Rows:</b> {len(dataset):,}'
    f' &nbsp; | &nbsp; <b>Columns:</b> {len(dataset.columns):,}'
    ' &nbsp; | &nbsp; No missing packet fields are fabricated.</div>',
    unsafe_allow_html=True,
)

# Focus on MITM/ARP-spoofing labels when a suitable label column exists.
label_col = find_column(dataset.columns, ["Attack_type", "Attack Type", "attacktype", "label", "class"])
view = dataset.copy()
mitm_terms = r"man.?in.?the.?middle|\bmitm\b|arp.?spoof|arp.?poison|spoofing"
if label_col:
    labels = view[label_col].astype(str)
    matches = view[labels.str.contains(mitm_terms, case=False, na=False, regex=True)]
    if not matches.empty:
        use_matches = st.checkbox(
            f"Filter to MITM/ARP-spoofing-labelled rows ({len(matches):,} rows)",
            value=True,
        )
        if use_matches:
            view = matches
    else:
        st.warning(
            f"No rows in '{label_col}' have a label matching MITM/ARP spoofing. "
            "Showing all rows for inspection; this does not mean they are MITM traffic."
        )
else:
    st.warning("No attack-label column was found. Showing records without claiming they are MITM-labelled.")

if view.empty:
    st.warning("No rows remain after filtering.")
    st.stop()

row_number = st.selectbox(
    "Select record",
    options=list(range(len(view))),
    format_func=lambda idx: f"Record {idx + 1} of {len(view)}",
)
row = view.iloc[row_number]

# Read only values that exist in the dataset. Edge-IIoTset variants differ in their columns.
protocol_value = value_from(row, ["ip.proto", "Protocol", "protocol"])
src_ip = value_from(row, ["ip.src_host", "ip.src", "Source IP", "source_ip"])
dst_ip = value_from(row, ["ip.dst_host", "ip.dst", "Destination IP", "destination_ip"])
src_mac = value_from(row, ["eth.src", "eth.src_host", "arp.src.hw_mac", "arp.src_mac", "Source MAC", "src_mac"])
dst_mac = value_from(row, ["eth.dst", "eth.dst_host", "arp.dst.hw_mac", "arp.dst_mac", "Destination MAC", "dst_mac"])
arp_opcode = value_from(row, ["arp.opcode", "arp.op_code", "ARP Opcode"])
arp_src_mac = value_from(row, ["arp.src.hw_mac", "arp.src_mac", "arp.src_mac_addr"])
arp_dst_mac = value_from(row, ["arp.dst.hw_mac", "arp.dst_mac", "arp.dst_mac_addr"])
src_port = value_from(row, ["tcp.srcport", "tcp.src_port", "Source Port", "src_port"])
dst_port = value_from(row, ["tcp.dstport", "tcp.dst_port", "Destination Port", "dst_port"])
tcp_flags = value_from(row, ["tcp.flags", "TCP Flags", "tcp_flags"])
tcp_len = value_from(row, ["tcp.len", "TCP Length", "tcp_length"])
packet_size = value_from(row, ["frame.len", "packet_size", "Packet Size", "pkt_len", "ip.len", "tcp.len"])
ttl = value_from(row, ["ip.ttl", "ttl", "TTL"])
packet_count = value_from(row, ["packet_count", "total_packets", "Packets", "packet count", "flow.pkts"])
byte_count = value_from(row, ["byte_count", "total_bytes", "Bytes", "byte count", "flow.bytes"])
packet_rate = value_from(row, ["packet_rate", "packets_per_second", "packets/sec", "packet rate"])
flow_duration = value_from(row, ["flow_duration", "flow.duration", "duration", "flow_duration_sec"])
inter_arrival = value_from(row, ["packet_inter_arrival_time", "inter_arrival_time", "frame.time_delta", "udp.time_delta"])
timestamp = format_timestamp(value_from(row, ["frame.time", "Timestamp", "DateTime", "timestamp", "time"]))
attack_type = value_from(row, ["Attack_type", "Attack Type", "attacktype", "label", "class"])

# Generate a stable display ID only; this is not an original dataset incident identifier.
incident_id = value_from(row, ["Incident ID", "incident_id", "flow_id", "Flow ID"], default=f"MITM-RECORD-{row_number + 1:06d}")

# UI summary: no model prediction/confidence is claimed unless supplied by an actual model.
status = "Review"
confidence = value_from(row, ["model_confidence", "confidence", "prediction_confidence"])
prediction = attack_type if attack_type != UNAVAILABLE else "Unclassified record"
severity = value_from(row, ["severity", "Severity"], default="Not calculated")

st.markdown(
    '<div class="traffic-panel" style="margin-bottom:10px">'
    '<div class="panel-title"><span class="panel-icon">🛡</span>MITM Incident Overview</div>'
    '<div class="detail-row"><div class="detail-label">Incident ID</div><div class="detail-value">'
    + html.escape(incident_id) + '</div></div>'
    '<div class="detail-row"><div class="detail-label">Status</div><div class="detail-value">'
    + html.escape(status) + '</div></div>'
    '<div class="detail-row"><div class="detail-label">Timestamp</div><div class="detail-value">'
    + html.escape(timestamp) + '</div></div>'
    '<div class="detail-row"><div class="detail-label">Source IP</div><div class="detail-value">'
    + html.escape(src_ip) + '</div></div>'
    '<div class="detail-row"><div class="detail-label">Destination IP</div><div class="detail-value">'
    + html.escape(dst_ip) + '</div></div></div>',
    unsafe_allow_html=True,
)

def metric_card(label, value, subtitle):
    return (
        '<div class="metric-card"><div class="metric-label">' + html.escape(label) +
        '</div><div class="metric-value">' + html.escape(str(value)) +
        '</div><div class="metric-sub">' + html.escape(subtitle) + '</div></div>'
    )

cards = st.columns(4)
card_values = [
    ("Predicted / Labelled Activity", prediction, "Dataset label; not a new prediction"),
    ("Model Confidence", confidence, "Only shown if supplied in the row"),
    ("Severity", severity, "Only shown if supplied in the row"),
    ("Attack Focus", "MITM", "ARP spoofing / traffic interception indicators"),
]
for col, (label, value, subtitle) in zip(cards, card_values):
    with col:
        st.markdown(metric_card(label, value, subtitle), unsafe_allow_html=True)

st.markdown("")
# Detail rows only show source-backed fields. Missing values remain explicitly unavailable.
detail_rows = [
    ("Method / Protocol", protocol_value, True),
    ("Source IP", src_ip, False),
    ("Destination IP", dst_ip, False),
    ("Source MAC", src_mac, False),
    ("Destination MAC", dst_mac, False),
    ("ARP Opcode", arp_opcode, False),
    ("ARP Source MAC", arp_src_mac, False),
    ("ARP Destination MAC", arp_dst_mac, False),
    ("TCP Source Port", src_port, False),
    ("TCP Destination Port", dst_port, False),
    ("TCP Flags", tcp_flags, False),
    ("TCP Length / Packet Size", tcp_len if tcp_len != UNAVAILABLE else packet_size, False),
    ("TTL", ttl, False),
    ("Packet Count", packet_count, False),
    ("Byte Count", byte_count, False),
    ("Packet Rate", packet_rate, False),
    ("Inter-arrival Time", inter_arrival, False),
    ("Flow Duration", flow_duration, False),
    ("Dataset Attack Label", attack_type, False),
]
rows_html = []
for label, value, is_protocol in detail_rows:
    shown = f'<span class="value-chip">{html.escape(str(value))}</span>' if is_protocol else html.escape(str(value))
    rows_html.append(
        '<div class="detail-row"><div class="detail-label">' + html.escape(label) +
        '</div><div class="detail-value">' + shown + '</div></div>'
    )

# Dynamic traffic indicators: values come from the selected record only.
indicator_items = [
    ("arp.opcode", arp_opcode, "red"),
    ("arp.src_mac", arp_src_mac, "red"),
    ("arp.dst_mac", arp_dst_mac, "red"),
    ("ip.src_host", src_ip, "blue"),
    ("ip.dst_host", dst_ip, "blue"),
    ("tcp.dstport", dst_port, "yellow"),
    ("tcp.flags", tcp_flags, "orange"),
    ("packet_rate", packet_rate, "blue"),
    ("flow_duration", flow_duration, "blue"),
]

def indicator_value(value):
    return "not available" if value in (None, "", UNAVAILABLE) else str(value)

indicator_lines = []
for idx, (field, value, style) in enumerate(indicator_items, start=1):
    safe_field = html.escape(field)
    safe_value = html.escape(indicator_value(value))
    token_class = {"red": "token-red", "orange": "token-orange", "yellow": "token-yellow"}.get(style, "token-blue")
    indicator_lines.append(
        f'<div class="indicator-line"><span class="indicator-num">{idx}</span>'
        f'{safe_field} = <span class="{token_class}">{safe_value}</span></div>'
    )

indicator_panel = (
    '<section class="indicator-panel"><div class="panel-title"><span class="panel-icon">&lt;/&gt;</span>'
    'MITM Traffic Indicators</div><div class="indicator-code">' + ''.join(indicator_lines) +
    '</div><div class="indicator-legend">'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ff465b"></span>ARP / MAC fields</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ff9d52"></span>TCP behaviour</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ffd15c"></span>Port / protocol</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#47c2ff"></span>Flow / endpoint</div>'
    '</div></section>'
)

# These bars are design placeholders only. They are deliberately labelled as illustrative.
# Replace them with SHAP/LIME values calculated from the exact trained IDS model.
shap_features = [
    ("arp.dst_mac", 0.41), ("arp.src_mac", 0.34), ("tcp.dstport", 0.22),
    ("packet_rate", 0.18), ("flow_duration", 0.11), ("packet_size", 0.07),
    ("ttl", 0.05), ("tcp.srcport", -0.02),
]
max_abs_shap = max(abs(value) for _, value in shap_features) or 1.0
shap_rows = []
for feature, contribution in shap_features:
    width = max(3, abs(contribution) / max_abs_shap * 100)
    bar_class = "shap-positive" if contribution >= 0 else "shap-negative"
    shap_rows.append(
        '<div class="shap-row"><div class="shap-feature">' + html.escape(feature) +
        '</div><div class="shap-track"><div class="shap-bar ' + bar_class +
        f'" style="width:{width:.1f}%"></div></div><div class="shap-value">{contribution:+.2f}</div></div>'
    )
shap_panel = (
    '<section class="shap-panel"><div class="panel-title"><span class="panel-icon">▥</span>'
    'Model Explanation (SHAP)</div><div class="shap-subtitle">Illustrative feature contributions — not computed from the dataset</div>'
    + ''.join(shap_rows) + '</section>'
)

lime_features = [
    ("ARP Reply / opcode", 0.36), ("Destination MAC", 0.28), ("High packet rate", 0.21),
    ("Modbus port (502)", 0.17), ("Flow duration", 0.12), ("TCP source port", 0.06),
]
max_lime = max(value for _, value in lime_features) or 1.0
lime_rows = []
for index, (feature, weight) in enumerate(lime_features):
    width = max(3, weight / max_lime * 100)
    bar_class = 'lime-bar-alt' if index == len(lime_features) - 1 else ''
    lime_rows.append(
        '<div class="lime-row"><div class="lime-feature">' + html.escape(feature) +
        '</div><div class="lime-track"><div class="lime-bar ' + bar_class +
        f'" style="width:{width:.1f}%"></div></div><div class="lime-value">{weight:.2f}</div></div>'
    )
lime_panel = (
    '<section class="lime-panel"><div class="panel-title"><span class="panel-icon">▦</span>'
    'Local Explanation (LIME)</div><div class="lime-subtitle">Illustrative local explanation for the mockup</div>'
    + ''.join(lime_rows) +
    '<div class="lime-note">Replace these example weights with LIME output from the trained IDS classifier.</div></section>'
)

st.markdown(
    '<div class="traffic-layout"><section class="traffic-panel">'
    '<div class="panel-title"><span class="panel-icon">▣</span>Network Traffic Details</div>'
    + ''.join(rows_html) + '</section><div class="right-stack">' + indicator_panel + shap_panel + lime_panel +
    '</div></div>',
    unsafe_allow_html=True,
)

evidence_items = [
    ("ARP Mapping Check", "Compare observed IP-to-MAC mappings with trusted network records. This dataset row alone may not establish spoofing."),
    ("Unexpected Traffic Path", "Investigate whether traffic is relayed through an unexpected host or gateway; this requires network context beyond a single row."),
    ("Endpoint / MAC Consistency", "Check whether the same IP is associated with changing or conflicting MAC addresses across multiple records."),
    ("Connection Behaviour", "Review TCP flags, ports, packet timing, and flow statistics when those fields are available."),
]
evidence_cards = []
for index, (title, description) in enumerate(evidence_items, start=1):
    evidence_cards.append(
        '<div class="evidence-card"><div class="evidence-title"><span class="evidence-number">'
        + f'{index:02d}</span>' + html.escape(title) + '</div><div class="evidence-description">'
        + html.escape(description) + '</div></div>'
    )
st.markdown(
    '<section class="evidence-panel"><div class="panel-title"><span class="panel-icon">▤</span>'
    'Evidence &amp; Investigation Guidance</div><div class="evidence-grid">' + ''.join(evidence_cards) +
    '</div></section>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="notice"><b>Important:</b> the network fields above are read from the selected dataset row. '
    'SHAP/LIME bars are illustrative UI placeholders and are not actual model explanations. '
    'This script does not train or run an IDS model, so it does not generate a real MITM prediction or confidence score. '
    'ARP/MAC fields may be unavailable in this dataset variant; they are not fabricated.</div>',
    unsafe_allow_html=True,
)
