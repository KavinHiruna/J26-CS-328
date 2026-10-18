"""Reusable Streamlit UI component for the Backdoor XAI incident page.

Usage:
    from backdoor_network_request_details import render_network_request_details
    render_network_request_details(selected_record)  # pandas Series or dict
"""
from html import escape
import streamlit as st


def _value(record, key, default="Unavailable"):
    try:
        value = record.get(key, default)
    except AttributeError:
        try:
            value = record[key]
        except (KeyError, TypeError, IndexError):
            return default
    if value is None:
        return default
    try:
        if value != value:  # NaN / NaT
            return default
    except (TypeError, ValueError):
        pass
    value = str(value).strip()
    return value if value and value.lower() not in {"nan", "nat", "none"} else default


def _tcp_flag_summary(raw_flags):
    try:
        raw = str(raw_flags).strip()
        number = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except (TypeError, ValueError):
        return "Raw flags unavailable"
    flags = []
    for bit, name in [(0x10, "ACK"), (0x08, "PSH"), (0x02, "SYN"),
                      (0x01, "FIN"), (0x04, "RST"), (0x20, "URG")]:
        if number & bit:
            flags.append(name)
    return ", ".join(flags) if flags else "No common TCP flags set"


def render_network_request_details(record):
    """Render a compact Network Request Details panel from a selected CSV row."""
    if record is None:
        st.info("Select a backdoor incident to view its network request details.")
        return

    timestamp = _value(record, "frame.time")
    source_ip = _value(record, "ip.src_host")
    destination_ip = _value(record, "ip.dst_host")
    source_port = _value(record, "tcp.srcport")
    destination_port = _value(record, "tcp.dstport")
    payload_length = _value(record, "tcp.len")
    tcp_flags = _value(record, "tcp.flags")
    flag_summary = _tcp_flag_summary(tcp_flags)

    rows = [
        ("Protocol", "TCP", "protocol"),
        ("Source IP", source_ip, "plain"),
        ("Destination IP", destination_ip, "plain"),
        ("Source Port", source_port, "port"),
        ("Destination Port", destination_port, "port"),
        ("TCP Payload Length", f"{payload_length} bytes" if payload_length != "Unavailable" else payload_length, "plain"),
        ("TCP Flags", f"{tcp_flags}  ({flag_summary})" if tcp_flags != "Unavailable" else tcp_flags, "flags"),
        ("Timestamp", timestamp, "plain"),
    ]
    html_rows = []
    for label, value, kind in rows:
        safe_label, safe_value = escape(str(label)), escape(str(value))
        if kind == "protocol":
            value_html = f'<span class="nr-chip nr-protocol">{safe_value}</span>'
        elif kind == "port":
            value_html = f'<span class="nr-chip nr-port">{safe_value}</span>'
        elif kind == "flags":
            value_html = f'<span class="nr-flags">{safe_value}</span>'
        else:
            value_html = safe_value
        html_rows.append(
            f'<div class="nr-row"><div class="nr-label">{safe_label}</div>'
            f'<div class="nr-value">{value_html}</div></div>'
        )

    st.markdown("""
    <style>
    .nr-card{background:linear-gradient(145deg,#081723 0%,#0b1825 100%);border:1px solid #1c3445;border-radius:10px;overflow:hidden;color:#e6f0fb;box-shadow:0 4px 16px rgba(0,0,0,.12);margin-bottom:.5rem}
    .nr-title{display:flex;align-items:center;gap:10px;padding:12px 15px 10px;border-bottom:1px solid #1c3445;font-size:16px;font-weight:700}
    .nr-title-icon{color:#9bd8ff;font-size:19px}
    .nr-row{display:grid;grid-template-columns:minmax(130px,40%) minmax(0,60%);min-height:27px;border-bottom:1px solid rgba(91,124,148,.20);font-size:13px}
    .nr-row:last-child{border-bottom:none}
    .nr-label{padding:5px 12px;color:#d7e5f1;background:rgba(18,36,51,.56);border-right:1px solid rgba(91,124,148,.20)}
    .nr-value{min-width:0;overflow-wrap:anywhere;padding:5px 12px;color:#e9f3fd}
    .nr-chip{display:inline-block;padding:1px 8px;border-radius:5px;line-height:1.45;font-size:12px}
    .nr-protocol,.nr-port{color:#ffb4aa;background:rgba(164,43,40,.30);border:1px solid rgba(248,91,81,.24)}
    .nr-flags{color:#ffb7ae}
    @media(max-width:600px){.nr-row{grid-template-columns:42% 58%}.nr-label,.nr-value{padding:6px 8px}}
    </style>
    """, unsafe_allow_html=True)
    st.markdown(
        '<div class="nr-card"><div class="nr-title"><span class="nr-title-icon">▤</span>'
        'Network Request Details</div>' + ''.join(html_rows) + '</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Values are taken from the selected dataset record. `tcp.len` is TCP payload length, "
        "not necessarily the size of the complete network frame."
    )
