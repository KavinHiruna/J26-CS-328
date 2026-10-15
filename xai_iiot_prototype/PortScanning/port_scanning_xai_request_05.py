import html
import re
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Port Scanning Incident Analysis (XAI)", page_icon="🛡️", layout="wide")
NA = "Not available in dataset"
st.markdown("""
<style>
.stApp{background:#08111b;color:#e7eef7}.block-container{max-width:1650px;padding:1rem 1.2rem}
.panel,.metric{background:#101b28;border:1px solid #26384c;border-radius:10px;padding:15px;margin-bottom:12px}
.panel-title{font-size:16px;font-weight:750;border-bottom:1px solid #2b3e52;padding-bottom:10px;margin-bottom:8px}
.hero{background:linear-gradient(100deg,#151b2a,#0b1925);border:1px solid #25364a;border-radius:12px;padding:18px 22px;margin-bottom:12px}
.hero-title{font-size:23px;font-weight:750}.sub,.metric-label{color:#9fb2c7;font-size:12px}.metric-value{font-size:20px;font-weight:750;margin-top:5px}.metric-sub{color:#b8c9da;font-size:12px}
.detail-row{display:grid;grid-template-columns:140px 1fr;gap:10px;padding:6px 0;border-bottom:1px solid #1d2b3b}.detail-label{color:#9db0c4;font-size:12px}.detail-value{font-size:12px;overflow-wrap:anywhere}
.payload{background:#08111b;border:1px solid #354b62;border-radius:8px;padding:18px 14px;font-family:Consolas,monospace;line-height:2;overflow-wrap:anywhere}
.evidence{background:#0c1723;border:1px solid #26384c;border-radius:8px;padding:10px;margin:7px 0;display:grid;grid-template-columns:34px 1fr auto;gap:10px;align-items:center}
.evidence-name{font-weight:700;font-size:12px}.evidence-desc{color:#aebed0;font-size:11px;line-height:1.5;margin-top:3px}.sev{padding:4px 8px;border-radius:6px;font-size:10px;font-weight:750}
</style>""", unsafe_allow_html=True)

incident_id = "PRT-000042"
analyst = "SOC Analyst"
uploaded = None

demo = {"frame.time":"2026-10-12 15:48:21","ip.src_host":"192.168.1.57","ip.dst_host":"192.168.1.100","tcp.srcport":52344,"tcp.dstport":22,"tcp.flags.syn":1,"tcp.flags.ack":0,"tcp.len":0,"connection_count":120,"unique_dstports":15,"connection_rate":8.5,"Attack_type":"Port Scanning","User-Agent":"Nmap 7.94 (demonstration)"}
# Load the requested workbook automatically from the project's data folder.
DEFAULT_DATASET = Path(__file__).resolve().parent / "data" / "Port_Scanning_train_80.xlsx"

try:
    if DEFAULT_DATASET.is_file():
        data = pd.read_excel(DEFAULT_DATASET)
        dataset_name = str(DEFAULT_DATASET)
    else:
        data = None
        dataset_name = "Demonstration record"

    if data is not None:
        if data.empty:
            st.error("The selected dataset is empty.")
            st.stop()
        row = data.iloc[0].to_dict()
    else:
        row = demo.copy()
        st.warning(f"Dataset not found at: {DEFAULT_DATASET}. Showing demonstration data. Place Port_Scanning_train_80.xlsx in the data folder.")
except Exception as e:
    st.error(f"Could not load dataset: {e}")
    st.stop()

def getv(names, default=NA):
    cols = {re.sub(r"[^a-z0-9]", "", str(k).lower()): k for k in row}
    for name in names:
        k = cols.get(re.sub(r"[^a-z0-9]", "", name.lower()))
        if k is not None and pd.notna(row[k]) and str(row[k]).strip().lower() not in {"", "nan", "none", "null"}:
            return str(row[k]).strip()
    return default

def num(names, default=0.0):
    try: return float(getv(names, str(default)))
    except (ValueError, TypeError): return default

src=getv(["ip.src_host","ip.src","source_ip","Source IP"])
dst=getv(["ip.dst_host","ip.dst","destination_ip","Destination IP"])
sport=getv(["tcp.srcport","udp.srcport","src_port","Source Port"])
dport=getv(["tcp.dstport","udp.dstport","dst_port","Destination Port"])
syn=num(["tcp.flags.syn","tcp.flags.syn == 1","tcp_syn","syn_flag"])
ack=num(["tcp.flags.ack","tcp.flags.ack == 1","tcp_ack","ack_flag"])
raw_flags=getv(["tcp.flags","tcp.flags.str","flags","TCP Flags"], "")
if raw_flags:
    flags=raw_flags
else:
    flag_names=[]
    if syn: flag_names.append("SYN")
    if ack: flag_names.append("ACK")
    if num(["tcp.flags.fin"], 0): flag_names.append("FIN")
    if num(["tcp.flags.rst"], 0): flag_names.append("RST")
    if num(["tcp.flags.psh"], 0): flag_names.append("PSH")
    if num(["tcp.flags.urg"], 0): flag_names.append("URG")
    flags=", ".join(flag_names) if flag_names else NA
plen=getv(["tcp.len","frame.len","packet_length","Packet Length"])
timestamp=getv(["frame.time","Timestamp","timestamp","DateTime"])
user_agent=getv(["http.user_agent","http.user-agent","User-Agent","user_agent","http_user_agent"], "Not available (not an HTTP request)")
protocol=getv(["protocol","frame.protocol","frame.protocols"], "")
if protocol and ":" in protocol:
    protocol=protocol.split(":")[-1].upper()
if not protocol or protocol == NA:
    protocol="TCP" if any(k in row for k in ["tcp.srcport","tcp.dstport","tcp.flags"]) else "UDP" if any(k in row for k in ["udp.srcport","udp.dstport"]) else NA
label=getv(["Attack_type","Attack Type","label","class"],"Unknown")
connections=num(["connection_count","flow_count","connections"],120); unique_ports=num(["unique_dstports","unique_destination_ports","dstport_count"],15)
rate=num(["connection_rate","packets_per_second","flow_rate"],8.5)
is_scan=bool(re.search(r"port[\s_-]*scan|reconnaissance",label,re.I)) or (syn==1 and unique_ports>=5 and connections>=20)
prediction="Port Scanning" if is_scan else "Review Required"
now=datetime.now(ZoneInfo("Asia/Colombo"))
st.markdown(f'<div style="color:#52c7ff;margin-bottom:12px">⌂ &nbsp;›&nbsp; Dashboard &nbsp;›&nbsp; Port Scanning &nbsp;›&nbsp; Incident Detail (XAI)<span style="float:right">{now:%b %d, %Y %H:%M:%S}</span></div>',unsafe_allow_html=True)
st.markdown(f'<div class="hero"><div style="font-size:22px">🛡️ &nbsp; <span class="hero-title">Port Scanning Incident Analysis (XAI)</span></div><div class="sub">Detailed explanation of why network activity may indicate port scanning</div><div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:14px"><div><div class="sub">Incident ID</div><b>{html.escape(incident_id)}</b></div><div><div class="sub">Status</div><b style="color:#ff5964">● Open</b></div><div><div class="sub">Date & Time</div><b>{html.escape(timestamp)}</b></div><div><div class="sub">Source IP</div><b>{html.escape(src)}</b></div></div></div>',unsafe_allow_html=True)
metrics=st.columns(4)
for col,(title,value,sub) in zip(metrics,[("Predicted Activity",prediction,"Multiple-port probing indicators"),("Model Confidence","Not connected","No trained model loaded"),("Severity","High" if is_scan else "Review","Investigate before response"),("Attack Type","Network Recon","Port/service discovery pattern")]):
    col.markdown(f'<div class="metric"><div class="metric-label">{title}</div><div class="metric-value">{value}</div><div class="metric-sub">{sub}</div></div>',unsafe_allow_html=True)

tabs=st.tabs(["Request & Traffic","Evidence & Justification","Model Explanation (SHAP)","Local Explanation (LIME)","Analyst Review"])
with tabs[0]:
    a,b=st.columns([1,1.3])
    with a:
        st.markdown('<div class="panel"><div class="panel-title">▤ Network Request Details</div>',unsafe_allow_html=True)
        for k,v in [("Protocol",protocol),("Source IP",src),("Source Port",sport),("Destination Port",dport),("Flags",flags),("Packet Length",plen),("Timestamp",timestamp),("User-Agent",user_agent)]:
            st.markdown(f'<div class="detail-row"><div class="detail-label">{html.escape(str(k))}</div><div class="detail-value">{html.escape(str(v))}</div></div>',unsafe_allow_html=True)
        st.markdown("</div>",unsafe_allow_html=True)

        # Evidence & Justification directly below Network Request Details
        st.markdown('<div class="panel"><div class="panel-title">Evidence &amp; Justification</div>', unsafe_allow_html=True)
        evidence_items = [
            ("⌘", "#ff5964", "Multiple Port Probing",
             f"Unique destination-port count: {unique_ports:g}. Many distinct ports may indicate service discovery.",
             "High" if unique_ports >= 5 else "Review"),
            ("◷", "#27b8ff", "Rapid Connection Attempts",
             f"Connection count: {connections:g}; connection rate: {rate:g}/s. Verify the time window and feature definitions.",
             "High" if connections >= 20 else "Review"),
            ("⇥", "#25c7a0", "TCP SYN Pattern",
             f"SYN={int(syn)}, ACK={int(ack)}. Repeated SYN attempts without completed handshakes can be consistent with SYN scanning; one packet is insufficient.",
             "Medium" if syn == 1 and ack == 0 else "Review"),
            ("◎", "#b56cff", "Dataset Label",
             f"Source label: {label}. This app uses a label/simple heuristic, not a trained model.", "Context"),
        ]
        for icon, color, title, desc, sev in evidence_items:
            st.markdown(
                f'<div class="evidence"><div style="color:{color};font-size:20px">{icon}</div>'
                f'<div><div class="evidence-name">{html.escape(title)}</div>'
                f'<div class="evidence-desc">{html.escape(desc)}</div></div>'
                f'<div class="sev" style="background:#57232b;color:white">{html.escape(sev)}</div></div>',
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)
    with b:
        st.markdown('<div class="panel"><div class="panel-title">▧ Traffic Indicators</div>',unsafe_allow_html=True)
        st.markdown(f'<div class="payload"><span style="color:#ff5964">{html.escape(src)}</span>:{html.escape(sport)} &nbsp;→&nbsp; <span style="color:#b56cff">{html.escape(dst)}</span>:<span style="color:#ffad45">{html.escape(dport)}</span> &nbsp;→&nbsp; <span style="color:#27b8ff">SYN={int(syn)}</span> ACK={int(ack)} Len={html.escape(plen)}</div>',unsafe_allow_html=True)
        x,y,z=st.columns(3); x.metric("Connection count",f"{connections:g}"); y.metric("Unique destination ports",f"{unique_ports:g}"); z.metric("Connection rate",f"{rate:g}/s")
        st.markdown("</div>",unsafe_allow_html=True)

        # Place SHAP and LIME explanations in the open area beneath Traffic Indicators.
        shap_col, lime_col = st.columns(2, gap="small")
        with shap_col:
            st.markdown('<div class="panel"><div class="panel-title">▥ Model Explanation (SHAP)</div>', unsafe_allow_html=True)
            st.caption("Illustrative feature contributions — not computed from a trained model.")
            shap_preview = pd.DataFrame(
                {"Contribution": [0.42, 0.28, 0.18, 0.12, 0.08, -0.05]},
                index=[
                    "tcp.flags.syn", "tcp.dstport", "connection_count",
                    "unique_dstports", "packet_count", "tcp.flags.ack"
                ],
            )
            st.bar_chart(shap_preview, horizontal=True, height=280)
            st.markdown("</div>", unsafe_allow_html=True)

        with lime_col:
            st.markdown('<div class="panel"><div class="panel-title">⌁ Local Explanation (LIME)</div>', unsafe_allow_html=True)
            st.caption("Illustrative local weights — not computed from a trained model.")
            lime_preview = pd.DataFrame(
                {"Local weight": [0.36, 0.24, 0.16, 0.12, 0.07]},
                index=[
                    "tcp.flags.syn = 1", "tcp.dstport = 22",
                    f"unique_dstports = {unique_ports:g}",
                    f"connection_count = {connections:g}",
                    f"connection_rate = {rate:g}"
                ],
            )
            st.bar_chart(lime_preview, horizontal=True, height=280)
            st.markdown(
                "SYN-oriented traffic and activity across multiple destination ports "
                "can support a port-scanning hypothesis. Validate using the trained IDS model.",
            )
            st.markdown("</div>", unsafe_allow_html=True)
with tabs[1]:
    st.markdown('<div class="panel"><div class="panel-title">Evidence & Justification</div>',unsafe_allow_html=True)
    items=[("⌘","#ff5964","Multiple Port Probing",f"Unique destination-port count: {unique_ports:g}. Many distinct ports may indicate service discovery.","High" if unique_ports>=5 else "Review"),("◷","#27b8ff","Rapid Connection Attempts",f"Connection count: {connections:g}; connection rate: {rate:g}/s. Verify the time window and feature definitions.","High" if connections>=20 else "Review"),("⇥","#25c7a0","TCP SYN Pattern",f"SYN={int(syn)}, ACK={int(ack)}. Repeated SYN attempts without completed handshakes can be consistent with SYN scanning; one packet is insufficient.","Medium" if syn==1 and ack==0 else "Review"),("◎","#b56cff","Dataset Label",f"Source label: {label}. This app uses a label/simple heuristic, not a trained model.","Context")]
    for icon,color,title,desc,sev in items:
        st.markdown(f'<div class="evidence"><div style="color:{color};font-size:20px">{icon}</div><div><div class="evidence-name">{title}</div><div class="evidence-desc">{html.escape(desc)}</div></div><div class="sev" style="background:#57232b;color:white">{sev}</div></div>',unsafe_allow_html=True)
    st.markdown("</div>",unsafe_allow_html=True)
with tabs[2]:
    st.warning("Illustrative preview only. These are not SHAP values computed from a trained model.")
    shap_preview = pd.DataFrame({
        "Illustrative contribution": [.42, .28, .18, .12, .08, -.05]
    }, index=["tcp.flags.syn", "tcp.dstport", "unique_dstports", "connection_count", "connection_rate", "tcp.flags.ack"])
    st.bar_chart(shap_preview, horizontal=True)
    st.caption("Connect SHAP to your fitted IDS classifier before reporting results.")
with tabs[3]:
    st.warning("Illustrative preview only. Real LIME weights require the trained classifier and selected row feature vector.")
    lime_preview = pd.DataFrame({
        "Illustrative local weight": [.36, .29, .21, .14, .09]
    }, index=["SYN flag = 1", "Unique ports above threshold", "High connection count", "Destination port", "ACK flag = 0"])
    st.bar_chart(lime_preview, horizontal=True)
    st.write("Human-readable summary: multiple destination ports, repeated connections, and SYN-oriented traffic can support a port-scanning hypothesis. Validate across a time window and compare with IDS output.")
with tabs[4]:
    assessment=st.selectbox("Assessment",["Suspected Port Scanning","Confirmed Port Scanning","Benign / Authorized Scan","False Positive","Needs Further Investigation"])
    notes=st.text_area("Analyst notes",placeholder="Record evidence, affected host, time window, and next steps...")
    if st.button("💾 Save Review",type="primary"):
        review={"incident_id":incident_id,"assessment":assessment,"analyst":analyst,"notes":notes,"saved_at":datetime.now(ZoneInfo("Asia/Colombo")).isoformat(timespec="seconds"),"source_dataset":dataset_name}
        p=Path("port_scanning_review_history.csv"); pd.DataFrame([review]).to_csv(p,mode="a",header=not p.exists(),index=False); st.success(f"Review saved to {p.resolve()}")
    st.caption("This dashboard analyzes existing records; it does not actively scan hosts. Use only authorized network data.")
st.caption("Research prototype • SHAP/LIME charts are placeholders until connected to your trained IDS model.")
