import html
import re
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="DDoS ICMP Flood — Network Traffic Details",
    page_icon="🌐",
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

st.title("DDoS ICMP Flood Analysis (XAI)")
st.caption("Explainable analysis of a potential ICMP flood. Dataset fields are shown only when available; demo values are clearly marked.")

# Load the provided workbook by default; allow the project CSV or another workbook to be supplied.
dataset = None
dataset_name = None
if DEFAULT_FILE.is_file():
    try:
        dataset = pd.read_csv(DEFAULT_FILE, low_memory=False)
        dataset_name = DEFAULT_FILE.name
    except Exception:
        dataset = None

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
    # Show the requested UI even when no dataset file is found.
    # DEMO_MODE below displays clearly labelled illustrative values.
    dataset = pd.DataFrame([{}])
    dataset_name = "Demo preview (no dataset loaded)"

if dataset.empty:
    st.error("The selected dataset contains no rows.")
    st.stop()

st.markdown(
    f'<div class="notice"><b>Dataset:</b> {html.escape(str(dataset_name))}'
    f' &nbsp; | &nbsp; <b>Rows:</b> {len(dataset):,}'
    f' &nbsp; | &nbsp; <b>Columns:</b> {len(dataset.columns):,}</div>',
    unsafe_allow_html=True,
)

# If an attack label is present, offer to focus on ICMP-related flood rows.
label_col = find_column(dataset.columns, ["Attack_type", "Attack Type", "Attack_label", "label", "class"])
view = dataset.copy()
if label_col:
    labels = view[label_col].astype(str)
    possible = view[labels.str.contains(r"icmp|ping.*flood|flood.*ping", case=False, na=False)]
    if not possible.empty:
        use_matches = st.checkbox(
            f"Filter to rows whose label mentions ICMP/Ping flood ({len(possible):,} rows)",
            value=True,
        )
        if use_matches:
            view = possible

if view.empty:
    st.warning("No rows remain after filtering.")
    st.stop()

# Select a row so the UI can inspect an actual record from the dataset.
row_number = st.selectbox(
    "Select record",
    options=list(range(len(view))),
    format_func=lambda idx: f"Record {idx + 1} of {len(view)}",
)
row = view.iloc[row_number]

# Extract fields only when they exist in the selected dataset.
protocol_value = value_from(row, ["ip.proto", "Protocol", "protocol"], UNAVAILABLE)
protocol = "ICMP" if find_column(row.index, ["icmp.type", "icmp.code", "icmp.checksum"]) or str(protocol_value).strip().lower() in {"1", "icmp"} else protocol_value
src_ip = value_from(row, ["ip.src_host", "ip.src", "Source IP", "source_ip"])
dst_ip = value_from(row, ["ip.dst_host", "ip.dst", "Destination IP", "destination_ip"])
icmp_type = value_from(row, ["icmp.type", "ICMP Type", "icmp_type"])
icmp_code = value_from(row, ["icmp.code", "ICMP Code", "icmp_code"])
packet_size = value_from(row, ["frame.len", "packet_size", "Packet Size", "pkt_len", "ip.len"])
ttl = value_from(row, ["ip.ttl", "ttl", "TTL"])
packet_count = value_from(row, ["packet_count", "total_packets", "Packets", "packet count"])
byte_count = value_from(row, ["byte_count", "total_bytes", "Bytes", "byte count"])
packet_rate = value_from(row, ["packet_rate", "packets_per_second", "packets/sec", "packet rate"])
byte_rate = value_from(row, ["bytes_per_second", "byte_rate", "bytes/sec"])
flow_duration = value_from(row, ["flow_duration", "flow.duration", "duration", "flow_duration_sec"])
inter_arrival = value_from(row, ["packet_inter_arrival_time", "inter_arrival_time", "frame.time_delta"])
timestamp = format_timestamp(value_from(row, ["frame.time", "Timestamp", "DateTime", "timestamp", "time"]))

# These are illustrative preview values, not measurements from the CSV.
DEMO_MODE = True
if DEMO_MODE:
    protocol = "ICMP"
    src_ip = "192.168.0.55"
    dst_ip = "192.168.0.10"
    icmp_type = "8 (Echo Request)"
    icmp_code = "0"
    packet_size = "98 bytes"
    ttl = "64"
    packet_count = "38,800"
    byte_count = "3,802,400 bytes"
    packet_rate = "4,850 packets/sec"
    byte_rate = "475,300 bytes/sec"
    flow_duration = "8.0 sec"
    inter_arrival = "0.00021 sec"
    if timestamp == UNAVAILABLE:
        timestamp = "Illustrative demo timestamp"

# Summary tiles
tiles = [
    ("Protocol", protocol, "Network protocol"),
    ("ICMP Type", icmp_type, "ICMP message type"),
    ("Source IP", src_ip, "Traffic origin"),
    ("Destination IP", dst_ip, "Target host"),
]
cols = st.columns(4)
for col, (label, value, sub) in zip(cols, tiles):
    with col:
        st.markdown(
            '<div class="metric-card">'
            f'<div class="metric-label">{html.escape(label)}</div>'
            f'<div class="metric-value">{html.escape(value)}</div>'
            f'<div class="metric-sub">{html.escape(sub)}</div>'
            '</div>',
            unsafe_allow_html=True,
        )

st.markdown("")
detail_rows = [
    ("Method / Protocol", protocol, True),
    ("Source IP", src_ip, False),
    ("Destination IP", dst_ip, False),
    ("ICMP Type", icmp_type, False),
    ("ICMP Code", icmp_code, False),
    ("Packet Size", packet_size, False),
    ("TTL", ttl, False),
    ("Packet Rate", packet_rate, False),
    ("Total Packets (flow/window)", packet_count, False),
    ("Total Bytes (flow/window)", byte_count, False),
    ("Bytes per Second", byte_rate, False),
    ("Inter-arrival Time", inter_arrival, False),
    ("Flow Duration", flow_duration, False),
    ("Timestamp", timestamp, False),
]

rows_html = []
for label, value, is_protocol in detail_rows:
    shown = (
        f'<span class="value-chip">{html.escape(str(value))}</span>'
        if is_protocol else html.escape(str(value))
    )
    rows_html.append(
        '<div class="detail-row">'
        f'<div class="detail-label">{html.escape(label)}</div>'
        f'<div class="detail-value">{shown}</div>'
        '</div>'
    )

# Traffic indicators are based on the same values shown in the details panel.
# In demo mode these match the supplied mockup; in dataset mode they reflect available fields.
indicator_items = [
    ("ip.proto", "ICMP (1)" if protocol == "ICMP" else protocol, "red"),
    ("icmp.type", icmp_type, "red"),
    ("icmp.code", icmp_code, "blue"),
    ("packet_size", packet_size, "yellow"),
    ("packet_rate", packet_rate, "orange"),
    ("flow_duration", flow_duration, "blue"),
]

def indicator_value(value):
    if value in (None, "", UNAVAILABLE):
        return "not available"
    return str(value)

indicator_lines = []
for idx, (field, value, style) in enumerate(indicator_items, start=1):
    safe_field = html.escape(field)
    safe_value = html.escape(indicator_value(value))
    if style == "syn":
        rendered_value = f'<span class="token-red">{safe_value}</span>'
    elif style == "red":
        rendered_value = f'<span class="token-red">{safe_value}</span>'
    elif style == "orange":
        rendered_value = f'<span class="token-orange">{safe_value}</span>'
    elif style == "yellow":
        rendered_value = f'<span class="token-yellow">{safe_value}</span>'
    else:
        rendered_value = f'<span class="token-blue">{safe_value}</span>'
    indicator_lines.append(
        f'<div class="indicator-line"><span class="indicator-num">{idx}</span>'
        f'{safe_field} = {rendered_value}</div>'
    )

indicator_panel = (
    '<section class="indicator-panel">'
    '<div class="panel-title"><span class="panel-icon">&lt;/&gt;</span>Traffic Indicators Highlighted</div>'
    '<div class="indicator-code">' + "".join(indicator_lines) + '</div>'
    '<div class="indicator-legend">'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ff465b"></span>ICMP flood indicator</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ff9d52"></span>High rate indicator</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#ffd15c"></span>ICMP message field</div>'
    '<div class="legend-item"><span class="legend-swatch" style="background:#47c2ff"></span>Flow behaviour</div>'
    '</div></section>'
)

# SHAP-style feature contribution panel (illustrative mockup values).
# Replace these values with real SHAP output from the trained IDS model when available.
shap_features = [
    ("packet_rate", 0.38),
    ("packet_count", 0.29),
    ("flow_duration", 0.18),
    ("icmp.type", 0.12),
    ("packet_size", 0.09),
    ("ttl", 0.05),
    ("icmp.code", -0.03),
]

max_abs_shap = max(abs(value) for _, value in shap_features) or 1.0
shap_rows = []
for feature, contribution in shap_features:
    width = max(3, abs(contribution) / max_abs_shap * 100)
    bar_class = "shap-positive" if contribution >= 0 else "shap-negative"
    shap_rows.append(
        '<div class="shap-row">'
        f'<div class="shap-feature">{html.escape(feature)}</div>'
        f'<div class="shap-track"><div class="shap-bar {bar_class}" style="width:{width:.1f}%"></div></div>'
        f'<div class="shap-value">{contribution:+.2f}</div>'
        '</div>'
    )

shap_panel = (
    '<section class="shap-panel">'
    '<div class="panel-title"><span class="panel-icon">▥</span>Model Explanation (SHAP)</div>'
    '<div class="shap-subtitle">Feature contribution to the model output</div>'
    + "".join(shap_rows)
    + '</section>'
)

# LIME-style local explanation panel, placed directly beneath SHAP in the right column.
# These are mockup weights until replaced with the trained classifier's actual LIME output.
lime_features = [
    ("High packet rate", 0.33),
    ("ICMP Echo Request (type 8)", 0.26),
    ("High packet count", 0.21),
    ("Short inter-arrival time", 0.13),
    ("Packet size pattern", 0.08),
]

max_lime = max(value for _, value in lime_features) or 1.0
lime_rows = []
for index, (feature, weight) in enumerate(lime_features):
    width = max(3, weight / max_lime * 100)
    bar_class = "lime-bar-alt" if index == len(lime_features) - 1 else ""
    lime_rows.append(
        '<div class="lime-row">'
        f'<div class="lime-feature">{html.escape(feature)}</div>'
        f'<div class="lime-track"><div class="lime-bar {bar_class}" style="width:{width:.1f}%"></div></div>'
        f'<div class="lime-value">{weight:.2f}</div>'
        '</div>'
    )

lime_panel = (
    '<section class="lime-panel">'
    '<div class="panel-title"><span class="panel-icon">▦</span>Local Explanation (LIME)</div>'
    '<div class="lime-subtitle">Top features for this prediction</div>'
    + "".join(lime_rows)
    + '<div class="lime-note">Illustrative ICMP local explanation. Replace with weights generated by LIME for the selected model prediction.</div>'
    + '</section>'
)

st.markdown(
    '<div class="traffic-layout">'
    '<section class="traffic-panel">'
    '<div class="panel-title"><span class="panel-icon">▣</span>Network Traffic Details</div>'
    + "".join(rows_html)
    + '</section>'
    '<div class="right-stack">'
    + indicator_panel
    + shap_panel
    + lime_panel
    + '</div></div>',
    unsafe_allow_html=True,
)

evidence_items = [
    ("Extremely High ICMP Packet Rate",
     "Packet rate is significantly higher than the normal baseline for ICMP traffic."),
    ("Large Number of ICMP Echo Requests",
     "A high count of ICMP Echo Request packets was observed in the selected time window."),
    ("Short Packet Inter-arrival Time",
     "Very short intervals between packets can indicate burst-like flood behaviour."),
    ("Target Concentration",
     "A large volume of ICMP traffic directed at one target can support a flood investigation."),
]

evidence_cards = []
for index, (title, description) in enumerate(evidence_items, start=1):
    evidence_cards.append(
        '<div class="evidence-card">'
        f'<div class="evidence-title"><span class="evidence-number">{index:02d}</span>{html.escape(title)}</div>'
        f'<div class="evidence-description">{html.escape(description)}</div>'
        '</div>'
    )

st.markdown(
    '<section class="evidence-panel">'
    '<div class="panel-title"><span class="panel-icon">▤</span>Evidence &amp; Justification</div>'
    '<div class="evidence-grid">'
    + "".join(evidence_cards)
    + '</div></section>',
    unsafe_allow_html=True,
)

if DEMO_MODE:
    st.markdown(
        '<div class="notice"><b>Preview mode:</b> the network values shown above are illustrative '
        'mockup values matching the requested design, not verified measurements from the dataset. '
        'Set <code>DEMO_MODE = False</code> in the script to display available values from the selected record.</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="notice"><b>Data note:</b> values are taken from the selected dataset record. '
        'Packet totals, packet rate, and flow duration are only reliable when supported by the source fields '
        'or calculated from packet-level records over a defined time window.</div>',
        unsafe_allow_html=True,
    )

