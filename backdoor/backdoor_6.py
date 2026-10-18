"""Backdoor XAI — Network Request Details panel (Streamlit).

This adapts the uploaded SQL-injection request/payload page into a backdoor
network-request details page using the columns in Backdoor_train_80(3).csv.
It displays values from the selected CSV row and does not invent missing fields.
Run with: streamlit run backdoor_xai_request_details.py
"""

import html
import re
import binascii
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Backdoor XAI — Network Request Details",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

PROJECT_ROOT = Path(r"D:\4Y1S\research\xai_iiot_prototype")
UNAVAILABLE = "Not available in dataset"


def normalise_name(value):
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def get_value(row, candidates, default=UNAVAILABLE):
    """Find a matching field name and return its value, safely."""
    normalised_columns = {normalise_name(col): col for col in row.index}
    for candidate in candidates:
        actual = normalised_columns.get(normalise_name(candidate))
        if actual is None:
            continue
        value = row[actual]
        if pd.isna(value):
            continue
        value = str(value).strip()
        if value and value.lower() not in {"nan", "none", "null", "nat"}:
            return value
    return default


def tcp_flag_summary(raw_flags):
    """Return common TCP flag names when tcp.flags can be parsed as an integer."""
    try:
        value = str(raw_flags).strip()
        number = int(value, 16) if value.lower().startswith("0x") else int(value)
    except (TypeError, ValueError):
        return "Flag names unavailable"

    flags = []
    for bit, name in [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"),
                      (0x01, "FIN"), (0x04, "RST"), (0x20, "URG")]:
        if number & bit:
            flags.append(name)
    return ", ".join(flags) if flags else "No common TCP flags set"


def format_timestamp(value):
    if value == UNAVAILABLE:
        return value
    try:
        return pd.to_datetime(value, errors="raise").strftime("%Y-%m-%d %H:%M:%S.%f")
    except (TypeError, ValueError, OverflowError):
        return value


def find_dataset_path():
    script_dir = Path(__file__).resolve().parent
    candidates = [
        PROJECT_ROOT / "data" / "Backdoor_train_80(3).csv",
        PROJECT_ROOT / "data" / "Backdoor_train_80.csv",
        script_dir / "data" / "Backdoor_train_80(3).csv",
        script_dir / "Backdoor_train_80.csv",
        script_dir.parent / "data" / "Backdoor_train_80(3).csv",
        Path.cwd() / "data" / "Backdoor_train_80(3).csv",
        Path.cwd() / "Backdoor_train_80(3).csv",
        Path.cwd() / "data" / "Backdoor_train_80.csv",
        Path.cwd() / "Backdoor_train_80.csv",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


st.markdown(
    """
    <style>
    .stApp { background: #0b1119; color: #e7eef7; }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    .block-container { max-width: 1500px; padding: 1rem 1rem 1.5rem; }
    .xai-panel {
        min-width: 0; background: linear-gradient(145deg, #081723 0%, #0b1825 100%);
        border: 1px solid #26384c; border-radius: 10px; padding: 0;
        box-sizing: border-box; overflow: hidden;
    }
    .panel-title {
        color: #e7eef7; font-size: 16px; font-weight: 700;
        padding: 12px 15px 10px; margin: 0;
        border-bottom: 1px solid #26384c;
    }
    .panel-icon { color: #8bd5ff; margin-right: 9px; }
    .detail-row {
        display: grid; grid-template-columns: minmax(130px, 40%) minmax(0, 60%);
        border-bottom: 1px solid rgba(91, 124, 148, .20); min-height: 27px;
    }
    .detail-row:last-child { border-bottom: 0; }
    .detail-label {
        color: #d7e5f1; font-size: 13px; padding: 5px 12px;
        background: rgba(18, 36, 51, .56); border-right: 1px solid rgba(91, 124, 148, .20);
    }
    .detail-value {
        color: #e9f3fd; font-size: 13px; padding: 5px 12px;
        overflow-wrap: anywhere; line-height: 1.45;
    }
    .chip {
        display: inline-block; padding: 1px 8px; border-radius: 5px;
        font-size: 12px; line-height: 1.45; color: #ffb4aa;
        background: rgba(164, 43, 40, .30); border: 1px solid rgba(248, 91, 81, .25);
    }
    .flags { color: #ffb7ae; }
    .notice {
        color: #aebed0; background: #111d2a; border: 1px solid #293b4e;
        border-radius: 8px; padding: 10px 12px; margin: 8px 0 12px; font-size: 13px;
    }
    .main-grid {
        display: grid;
        grid-template-columns: minmax(300px, .88fr) minmax(0, 1.55fr);
        gap: 12px;
        align-items: start;
    }
    .right-grid {
        display: grid;
        grid-template-columns: minmax(0, .92fr) minmax(0, 1.08fr);
        gap: 12px;
        align-items: stretch;
    }
    .flow-wrap { padding: 16px 12px 12px; }
    .flow-nodes { display: grid; grid-template-columns: 1fr 40px 1fr; align-items: center; gap: 6px; }
    .flow-node { text-align: center; min-width: 0; }
    .node-icon { font-size: 30px; color: #53bdf7; line-height: 1.3; }
    .node-ip { font-size: 12px; color: #e7eef7; overflow-wrap: anywhere; font-weight: 600; }
    .node-role { font-size: 11px; margin-top: 4px; color: #f87171; }
    .node-role.remote { color: #53bdf7; }
    .flow-arrow { font-size: 22px; text-align: center; color: #f87171; }
    .flow-arrow span { display: block; font-size: 10px; line-height: 1.35; color: #c6d3e0; white-space: nowrap; }
    .flow-meta { text-align: center; color: #91a8bd; font-size: 11px; margin-top: 12px; }
    .payload-inner { padding: 12px; }
    .hex-box {
        background: #07111b; border: 1px solid #30475d; border-radius: 8px;
        padding: 10px; color: #dce9f5; font-family: Consolas, "Courier New", monospace;
        font-size: 11px; line-height: 1.8; overflow-x: auto; min-height: 104px;
    }
    .hex-line { display: grid; grid-template-columns: 43px minmax(160px, 1fr) minmax(65px, .6fr); gap: 8px; white-space: nowrap; }
    .hex-offset { color: #6f879d; }
    .hex-ascii { color: #8196a9; }
    .hex-mark { border-radius: 3px; padding: 1px 2px; }
    .legend { display: flex; flex-wrap: wrap; gap: 8px 12px; margin-top: 12px; }
    .legend-item { color: #c4d0dd; font-size: 10px; display: flex; align-items: center; gap: 5px; }
    .legend-dot { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }

    .bottom-grid { display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(300px, 1fr); gap: 12px; margin-top: 14px; align-items: stretch; }
    .shap-wrap { padding: 12px 14px 10px; }
    .shap-chart { display: flex; flex-direction: column; gap: 8px; }
    .shap-row { display: grid; grid-template-columns: minmax(95px, 1fr) minmax(80px, 1.5fr) 38px; gap: 8px; align-items: center; }
    .shap-name { color: #cbd8e5; font-size: 11px; text-align: right; overflow-wrap: anywhere; }
    .shap-track { height: 16px; background: #0a1420; border-left: 1px solid #70849a; border-radius: 2px; overflow: hidden; }
    .shap-bar { height: 100%; border-radius: 0 3px 3px 0; }
    .shap-number { color: #d8e5f2; font-size: 11px; font-variant-numeric: tabular-nums; }
    .shap-axis { display: flex; justify-content: space-between; color: #7f95aa; font-size: 10px; margin: 6px 44px 0 100px; }
    .shap-note { color: #9db0c3; font-size: 10px; line-height: 1.45; margin-top: 12px; padding: 8px 9px; border: 1px solid #26384c; border-radius: 7px; background: #0b1622; }
    .evidence-panel { margin-top: 14px; }
    .evidence-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; padding: 10px; }
    .evidence-card { display: grid; grid-template-columns: 36px minmax(0, 1fr) auto; gap: 8px; align-items: start;
        background: #0c1723; border: 1px solid #1e3447; border-radius: 9px; padding: 11px 10px; min-width: 0; }
    .evidence-icon { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center;
        border-radius: 8px; font-size: 18px; font-weight: 700; }
    .evidence-icon.red { color: #ff6868; background: #6e202a55; }
    .evidence-icon.blue { color: #43c7ff; background: #123c5555; }
    .evidence-icon.green { color: #2bd59a; background: #104c3a55; }
    .evidence-icon.purple { color: #c084fc; background: #48216a55; }
    .evidence-title { color: #eaf2fb; font-size: 12px; font-weight: 700; margin: 0 0 3px; }
    .evidence-desc { color: #aebed0; font-size: 11px; line-height: 1.45; }
    .evidence-level { white-space: nowrap; border-radius: 5px; padding: 3px 6px; font-size: 10px; font-weight: 700; }
    .evidence-level.high { color: #ffb4b4; background: #70252b; }
    .evidence-level.medium { color: #e4c4ff; background: #4d286d; }
    .evidence-level.low { color: #b8d5e9; background: #243c50; }
    @media (max-width: 1000px) {
        .evidence-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .bottom-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 600px) {
        .evidence-grid { grid-template-columns: 1fr; }
        .shap-row { grid-template-columns: 88px minmax(60px, 1fr) 34px; gap: 6px; }
        .shap-axis { margin-left: 92px; margin-right: 40px; }
    }

    @media (max-width: 900px) {
        .main-grid { grid-template-columns: 1fr; }
        .right-grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 600px) {
        .detail-row { grid-template-columns: 42% 58%; }
        .detail-label, .detail-value { padding: 6px 8px; }
        .right-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 600px) {
        .detail-row { grid-template-columns: 42% 58%; }
        .detail-label, .detail-value { padding: 6px 8px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("## 🛡️ Backdoor Incident Analysis (XAI)")
st.caption("Network request details for the selected backdoor-traffic record")

resolved_dataset_path = find_dataset_path()
if resolved_dataset_path:
    try:
        dataset = pd.read_csv(resolved_dataset_path, low_memory=False)
        st.caption(f"Dataset: `{resolved_dataset_path}`")
    except Exception as exc:
        st.error(f"Could not read dataset: {exc}")
        st.stop()
else:
    st.info("Choose your Backdoor CSV file. The file can also be placed in the project's data folder.")
    uploaded_dataset = st.file_uploader(
        "Select Backdoor dataset CSV", type=["csv"], key="backdoor_dataset_upload"
    )
    if uploaded_dataset is None:
        st.stop()
    try:
        dataset = pd.read_csv(uploaded_dataset, low_memory=False)
        st.caption(f"Dataset loaded from upload: `{uploaded_dataset.name}`")
    except Exception as exc:
        st.error(f"Could not read the uploaded CSV: {exc}")
        st.stop()

if dataset.empty:
    st.error("The selected dataset is empty.")
    st.stop()

# Use an explicit attack-type label if the file provides one. Do not assume
# Attack_label=1 means specifically backdoor unless dataset documentation says so.
attack_type_column = next(
    (col for col in dataset.columns if normalise_name(col) in {"attacktype", "attack_type", "attackname"}),
    None,
)
if attack_type_column:
    attack_values = dataset[attack_type_column].dropna().astype(str).unique().tolist()
    chosen_type = st.selectbox("Attack type", attack_values) if attack_values else None
    if chosen_type is not None:
        matching = dataset[dataset[attack_type_column].astype(str) == chosen_type]
    else:
        matching = dataset
else:
    matching = dataset
    st.markdown(
        '<div class="notice">This CSV has no explicit attack-type column detected. '
        'The panel displays a dataset record; verify the file provenance before treating it as a confirmed backdoor incident.</div>',
        unsafe_allow_html=True,
    )

if matching.empty:
    st.warning("No records match the selected attack type.")
    st.stop()

# Keep the selected row tied to the original dataset index.
row_positions = list(range(len(matching)))
if len(matching) > 1:
    selected_position = st.selectbox(
        "Select traffic record",
        row_positions,
        format_func=lambda pos: f"Record {pos + 1} (dataset row index {matching.index[pos]})",
    )
    selected_row = matching.iloc[selected_position]
else:
    selected_row = matching.iloc[0]

source_ip = get_value(selected_row, ["ip.src_host", "ip.src", "Source IP", "source_ip"])
destination_ip = get_value(selected_row, ["ip.dst_host", "ip.dst", "Destination IP", "destination_ip"])
source_port = get_value(selected_row, ["tcp.srcport", "tcp.src_port", "Source Port", "source_port"])
destination_port = get_value(selected_row, ["tcp.dstport", "tcp.dst_port", "Destination Port", "destination_port"])
tcp_length = get_value(selected_row, ["tcp.len", "tcp_length", "TCP Payload Length", "payload_length"])
tcp_flags = get_value(selected_row, ["tcp.flags", "tcp_flags", "TCP Flags"])
timestamp = format_timestamp(get_value(selected_row, ["frame.time", "Timestamp", "timestamp", "time"]))
protocol = get_value(selected_row, ["protocol", "frame.protocols", "Protocol"], default="TCP")

rows = [
    ("Protocol", protocol, "chip" if protocol.upper() == "TCP" else "normal"),
    ("Source IP", source_ip, "normal"),
    ("Destination IP", destination_ip, "normal"),
    ("Source Port", source_port, "port"),
    ("Destination Port", destination_port, "port"),
    ("TCP Payload Length", f"{tcp_length} bytes" if tcp_length != UNAVAILABLE else tcp_length, "normal"),
    ("TCP Flags", f"{tcp_flags}  ({tcp_flag_summary(tcp_flags)})" if tcp_flags != UNAVAILABLE else tcp_flags, "flags"),
    ("Timestamp", timestamp, "normal"),
]

body = []
for label, value, kind in rows:
    safe_label = html.escape(str(label))
    safe_value = html.escape(str(value))
    if kind in {"chip", "port"}:
        rendered_value = f'<span class="chip">{safe_value}</span>'
    elif kind == "flags":
        rendered_value = f'<span class="flags">{safe_value}</span>'
    else:
        rendered_value = safe_value
    body.append(
        f'<div class="detail-row"><div class="detail-label">{safe_label}</div>'
        f'<div class="detail-value">{rendered_value}</div></div>'
    )

# Look for a captured payload field. Flow metadata alone cannot reconstruct payload bytes.
raw_payload = get_value(
    selected_row,
    [
        "tcp.payload", "tcp_payload", "payload_hex", "raw_payload",
        "data.data", "frame.raw", "payload", "Raw Payload",
    ],
    default="",
)

def payload_to_bytes(value):
    """Decode a captured hex payload where possible; return None if unavailable/unparseable."""
    if not value or value == UNAVAILABLE:
        return None
    candidate = str(value).strip()
    # Wireshark-style colon-separated hex and plain hex strings are supported.
    compact = re.sub(r"[^0-9a-fA-F]", "", candidate)
    if len(compact) < 2 or len(compact) % 2:
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None

def hex_dump(data, limit=96):
    """Build a safe, compact hex/ASCII preview of actual captured bytes."""
    shown = data[:limit]
    lines = []
    for offset in range(0, len(shown), 16):
        chunk = shown[offset:offset + 16]
        hex_cells = []
        ascii_cells = []
        for byte in chunk:
            token = f"{byte:02x}"
            if offset == 0 and byte in (0x4d, 0x5a):
                token = f'<span class="hex-mark" style="background:#f6a23a33;color:#ffbd66;border:1px solid #f6a23a">{token}</span>'
            elif 0x20 <= byte <= 0x7e:
                token = f'<span class="hex-mark" style="background:#25a7f022;color:#58c8ff;border:1px solid #25a7f055">{token}</span>'
            else:
                token = html.escape(token)
            hex_cells.append(token)
            ascii_cells.append(chr(byte) if 32 <= byte <= 126 else ".")
        lines.append(
            f'<div class="hex-line"><span class="hex-offset">{offset:04x}:</span>'
            f'<span>{" ".join(hex_cells)}</span>'
            f'<span class="hex-ascii">{html.escape("".join(ascii_cells))}</span></div>'
        )
    return "".join(lines), len(data), min(len(data), limit)

payload_bytes = payload_to_bytes(raw_payload)

# Left column: Network Request Details
panel_html = (
    '<section class="xai-panel">'
    '<div class="panel-title"><span class="panel-icon">▤</span>Network Request Details</div>'
    + "".join(body)
    + "</section>"
)

# Right top: communication flow, grounded in the selected row's IPs, ports and tcp.len.
payload_size = f"{tcp_length} bytes" if tcp_length != UNAVAILABLE else "Payload length unavailable"
flow_html = (
    '<section class="xai-panel">'
    '<div class="panel-title"><span class="panel-icon">⇄</span>Communication Flow</div>'
    '<div class="flow-wrap"><div class="flow-nodes">'
    f'<div class="flow-node"><div class="node-icon">▣</div>'
    f'<div class="node-ip">{html.escape(source_ip)}</div>'
    '<div class="node-role">Source Host</div></div>'
    '<div class="flow-arrow">➜<span>'
    f'TCP {html.escape(source_port)} → {html.escape(destination_port)}'
    '</span></div>'
    f'<div class="flow-node"><div class="node-icon">▤</div>'
    f'<div class="node-ip">{html.escape(destination_ip)}</div>'
    '<div class="node-role remote">Destination Host</div></div>'
    '</div>'
    f'<div class="flow-meta">{html.escape(payload_size)} · TCP flags: {html.escape(tcp_flag_summary(tcp_flags))}</div>'
    '<div class="flow-meta">Reverse-direction traffic is not inferred from this single record.</div>'
    '</div></section>'
)

# Right bottom: show a hex preview only if the dataset contains real payload bytes.
if payload_bytes is not None:
    dump_html, total_bytes, displayed_bytes = hex_dump(payload_bytes)
    payload_content = (
        f'<div class="hex-box">{dump_html}</div>'
        f'<div class="flow-meta">Showing {displayed_bytes} of {total_bytes} captured payload bytes.</div>'
    )
else:
    payload_content = (
        '<div class="notice">Raw payload bytes are not available in the selected dataset row. '
        'The TCP payload length is metadata and cannot be converted into real hex bytes.</div>'
        '<div class="hex-box" style="color:#8297aa">No captured payload to render.</div>'
    )

payload_html = (
    '<section class="xai-panel">'
    '<div class="panel-title"><span class="panel-icon">▧</span>Payload with Highlighted Indicators</div>'
    '<div class="payload-inner">' + payload_content +
    '<div class="legend">'
    '<div class="legend-item"><span class="legend-dot" style="background:#f6a23a"></span>Executable header candidate</div>'
    '<div class="legend-item"><span class="legend-dot" style="background:#25a7f0"></span>Printable / command-like bytes</div>'
    '</div></div></section>'
)

st.markdown(
    '<div class="main-grid"><div>' + panel_html + '</div>'
    '<div class="right-grid"><div>' + flow_html + '</div><div>' + payload_html + '</div></div></div>',
    unsafe_allow_html=True,
)

# Evidence & Justification — use only evidence supported by the selected row/dataset.
def numeric_value(value):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None

dst_port_num = numeric_value(destination_port)
src_port_num = numeric_value(source_port)
tcp_len_num = numeric_value(tcp_length)
flags_text = tcp_flag_summary(tcp_flags)
flags_upper = flags_text.upper()
has_ack_psh = "ACK" in flags_upper and "PSH" in flags_upper

# Check if the same endpoint/port tuple appears repeatedly in the loaded dataset.
src_col = next((c for c in dataset.columns if normalise_name(c) in {"ipsrchost", "ipsrc", "sourceip", "source_ip"}), None)
dst_col = next((c for c in dataset.columns if normalise_name(c) in {"ipdsthost", "ipdst", "destinationip", "destination_ip"}), None)
sport_col = next((c for c in dataset.columns if normalise_name(c) in {"tcpsrcport", "tcpsrc_port", "sourceport", "source_port"}), None)
dport_col = next((c for c in dataset.columns if normalise_name(c) in {"tcpdstport", "tcpdst_port", "destinationport", "destination_port"}), None)
len_col = next((c for c in dataset.columns if normalise_name(c) in {"tcplen", "tcp_length", "tcppayloadlength", "payload_length"}), None)

same_flow_count = 1
reverse_count = 0
flow_lengths = []
if src_col and dst_col and sport_col and dport_col:
    src_series = dataset[src_col].astype(str)
    dst_series = dataset[dst_col].astype(str)
    sport_series = dataset[sport_col].astype(str)
    dport_series = dataset[dport_col].astype(str)
    same_mask = (
        (src_series == str(source_ip)) &
        (dst_series == str(destination_ip)) &
        (sport_series == str(source_port)) &
        (dport_series == str(destination_port))
    )
    same_flow_count = int(same_mask.sum())
    reverse_mask = (
        (src_series == str(destination_ip)) &
        (dst_series == str(source_ip)) &
        (sport_series == str(destination_port)) &
        (dport_series == str(source_port))
    )
    reverse_count = int(reverse_mask.sum())
    if len_col:
        flow_lengths = pd.to_numeric(dataset.loc[same_mask, len_col], errors="coerce").dropna().tolist()

if dst_port_num is not None:
    common_service_ports = {20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 3306, 3389, 5432, 8080, 8443}
    if int(dst_port_num) not in common_service_ports:
        port_title = f"Unusual destination port ({html.escape(str(destination_port))})"
        port_desc = "This port is outside a small common-service list. A non-standard port can warrant review but is not proof of a backdoor."
        port_level, port_class = "Review", "medium"
    else:
        port_title = f"Destination port ({html.escape(str(destination_port))})"
        port_desc = "This destination port is commonly associated with a known service; interpret it with other evidence."
        port_level, port_class = "Context", "low"
else:
    port_title = "Destination port"
    port_desc = "Destination port is not numeric in this record, so a port-based heuristic could not be applied."
    port_level, port_class = "Unavailable", "low"

if reverse_count > 0:
    flow_title = "Bidirectional traffic observed"
    flow_desc = f"Found {reverse_count:,} reverse-tuple record(s) in this dataset. This supports two-way traffic in the capture, but not persistence by itself."
    flow_level, flow_class = "Observed", "high"
elif same_flow_count > 1:
    flow_title = "Repeated flow records"
    flow_desc = f"Found {same_flow_count:,} records with the same source/destination IPs and ports. Reverse-direction traffic was not found for this tuple."
    flow_level, flow_class = "Observed", "medium"
else:
    flow_title = "Single flow record"
    flow_desc = "Only one matching tuple was found. Bidirectional or persistent communication cannot be established from this record alone."
    flow_level, flow_class = "Limited", "low"

if len(flow_lengths) >= 3:
    import statistics
    mean_len = statistics.mean(flow_lengths)
    stdev_len = statistics.pstdev(flow_lengths)
    cv = (stdev_len / mean_len) if mean_len else None
    if cv is not None and cv <= 0.20:
        size_title = "Consistent TCP payload lengths"
        size_desc = f"{len(flow_lengths)} matching records have relatively similar payload lengths (coefficient of variation {cv:.2f}). This pattern alone does not identify command-and-control traffic."
        size_level, size_class = "Observed", "medium"
    else:
        size_title = "Variable TCP payload lengths"
        size_desc = f"Payload lengths vary across {len(flow_lengths)} matching records. Packet-size consistency is not supported for this flow."
        size_level, size_class = "Observed", "low"
elif tcp_len_num is not None:
    size_title = "TCP data transfer"
    size_desc = f"The selected record reports {tcp_len_num:g} bytes in tcp.len. One record is insufficient to infer regular packet sizes or command-and-control behavior."
    size_level, size_class = "Single record", "low"
else:
    size_title = "Payload length unavailable"
    size_desc = "No usable tcp.len value was found, so payload-size behavior cannot be assessed."
    size_level, size_class = "Unavailable", "low"

if has_ack_psh:
    flags_title = "ACK and PSH flags"
    flags_desc = "The TCP flags include ACK and PSH, consistent with acknowledged data being pushed to the receiving application. These flags are also normal in benign traffic."
    flags_level, flags_class = "Observed", "medium"
else:
    flags_title = "TCP flags"
    flags_desc = f"Observed flags: {flags_text}. ACK+PSH was not established for this record."
    flags_level, flags_class = "Observed", "low"

evidence_items = [
    ("↯", "red", port_title, port_desc, port_level, port_class),
    ("⇄", "blue", flow_title, flow_desc, flow_level, flow_class),
    ("▤", "green", size_title, size_desc, size_level, size_class),
    ("⚙", "purple", flags_title, flags_desc, flags_level, flags_class),
]
evidence_cards = []
for icon_text, icon_color, title, description, level, level_class in evidence_items:
    evidence_cards.append(
        '<div class="evidence-card">'
        f'<div class="evidence-icon {icon_color}">{icon_text}</div>'
        '<div><div class="evidence-title">' + title + '</div>'
        '<div class="evidence-desc">' + html.escape(description) + '</div></div>'
        f'<div class="evidence-level {level_class}">{html.escape(level)}</div>'
        '</div>'
    )

evidence_html = (
    '<section class="xai-panel evidence-panel">'
    '<div class="panel-title"><span class="panel-icon">⌕</span>Evidence &amp; Justification</div>'
    '<div class="evidence-grid">' + ''.join(evidence_cards) + '</div>'
    '</section>'
)

# SHAP-style feature contribution panel. These are explicitly illustrative until
# the trained classifier and its SHAP explainer are connected to this page.
# Do not present these sample values as measured model explanations.
shap_demo_features = [
    ("tcp.dstport", 0.42, "#ff4d4d"),
    ("tcp.len", 0.31, "#f6a23a"),
    ("flow_duration", 0.18, "#25a7f0"),
    ("packet_count", 0.12, "#35d07f"),
    ("tcp.flags", 0.09, "#a85cf5"),
    ("bytes_sent", 0.06, "#6f879d"),
    ("bytes_received", 0.04, "#8297aa"),
    ("tcp.connection.syn", 0.03, "#9aa8b5"),
]
max_shap_value = max(value for _, value, _ in shap_demo_features) or 1.0
shap_rows = []
for feature_name, shap_value, color in shap_demo_features:
    bar_width = max(2, (shap_value / max_shap_value) * 100)
    shap_rows.append(
        '<div class="shap-row">'
        f'<div class="shap-name">{html.escape(feature_name)}</div>'
        f'<div class="shap-track"><div class="shap-bar" style="width:{bar_width:.1f}%;background:{color}"></div></div>'
        f'<div class="shap-number">{shap_value:.2f}</div>'
        '</div>'
    )

shap_html = (
    '<section class="xai-panel evidence-panel">'
    '<div class="panel-title"><span class="panel-icon">▥</span>Model Explanation (SHAP)</div>'
    '<div class="shap-wrap">'
    '<div class="shap-chart">' + ''.join(shap_rows) + '</div>'
    '<div class="shap-axis"><span>0.0</span><span>0.1</span><span>0.2</span><span>0.3</span><span>0.4</span></div>'
    '<div class="shap-note"><strong>UI preview:</strong> bars use illustrative values to show the intended layout. '
    'They are not calculated from the selected record or a trained model. Connect the trained IDS model and SHAP explainer '
    'before using these values as research results.</div>'
    '</div></section>'
)

st.markdown(
    '<div class="bottom-grid"><div>' + evidence_html + '</div><div>' + shap_html + '</div></div>',
    unsafe_allow_html=True,
)

st.caption(
    "Values are taken from the selected CSV row. TCP payload length is not necessarily the full frame size. "
    "Hex bytes are shown only when an actual payload field is present; an unusual port or TCP flag combination alone does not prove malicious activity."
)
