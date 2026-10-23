"""
Stage 6-7: Forensic Report Generation
Builds a structured Markdown report from the pipeline outputs. The summary and
the recommendations are generated from what was actually detected (origin,
attack stages, compromised assets) - nothing is hard-coded to one scenario.
"""

from datetime import datetime
from typing import Dict, List, Optional

from log_loader import EvidenceRecord
from correlator import CorrelatedCluster
from timeline_rca import TimelineEvent, RootCauseAnalysis, canonical_stage


def _stage_set(timeline: List[TimelineEvent]) -> set:
    return {canonical_stage(t.stage) for t in timeline}


def _distinct_stage_order(timeline: List[TimelineEvent]) -> List[str]:
    order: List[str] = []
    for t in timeline:
        if t.source == "firewall":
            continue
        st = canonical_stage(t.stage)
        if not order or order[-1] != st:
            order.append(st)
    return order


def build_recommendations(rca: RootCauseAnalysis, stages: set) -> List[str]:
    recs = []
    if rca.origin_type == "internal":
        recs.append(f"Isolate and physically locate the unauthorised internal device at {rca.entry_point_ip}; "
                    "enforce port security / 802.1X on OT switches so unknown devices cannot join the control network.")
    else:
        recs.append(f"Block the external source {rca.entry_point_ip} at the perimeter firewall and review all "
                    "remote-access paths (VPN / RDP) that it used.")
    if "Initial Access" in stages and rca.origin_type != "internal":
        recs.append("Enforce multi-factor authentication and geo/time restrictions on remote and vendor accounts; "
                    "rotate any credentials seen in the evidence.")
    if "Credential Access" in stages:
        recs.append("Enable account lockout / rate limiting and monitor repeated authentication failures; "
                    "reset credentials on every compromised host.")
    if "Malware Delivery" in stages or "Execution" in stages:
        recs.append("Quarantine the hosts that executed the dropped payload, collect a disk/memory image, and "
                    "apply application allow-listing on engineering workstations.")
    if "Command and Control" in stages:
        recs.append("Block the command-and-control address at the perimeter, review outbound firewall rules from "
                    "OT-adjacent hosts, and hunt for other hosts that contacted the same address.")
    if "Lateral Movement" in stages:
        recs.append("Segment IT and OT networks and restrict RDP/SMB between zones (historian, EMS, engineering "
                    "workstations) to named jump hosts only.")
    if "Impact" in stages:
        recs.append("Restore the affected controller / relay / EMS configuration (logic, trip and protection setpoints) "
                    "from a known-good backup and verify integrity before returning equipment to service.")
        recs.append("Add IDS signatures for unauthorised Modbus / IEC 60870-5-104 write or setpoint commands "
                    "targeting protection and breaker registers.")
    recs.append("Keep firewall, IDS and OT device logs centrally collected and time-synchronised (NTP) to improve "
                "future correlation accuracy.")
    return recs


def _cell(v) -> str:
    """Make a value safe for a markdown table cell."""
    return str(v).replace("|", "/").replace("\n", " ")


def upstream_section(incident: Dict) -> List[str]:
    """Optional section built from the 'upstream' block of incident.json (Components 1-3).
    Every field is optional; values are shown as supplied and are not verified here."""
    up = (incident or {}).get("upstream")
    if not isinstance(up, dict) or not up:
        return []
    L: List[str] = ["## 1b. Upstream Detection and Explanation Context"]
    if up.get("illustrative_sample"):
        L.append("*These values are illustrative sample data used to demonstrate the handoff format. "
                 "They are not output from a trained model.*")
        L.append("")
    det = up.get("detection") or {}
    if det:
        L.append("**Detection (Component 1 - ML-based IDS)**")
        L.append("")
        L.append("| Field | Value |")
        L.append("|---|---|")
        for key, label in (("model", "Model"), ("predicted_class", "Predicted class"),
                           ("confidence", "Confidence"), ("detected_at", "Detected at"),
                           ("alert_count", "Alerts raised")):
            if key in det:
                L.append(f"| {label} | {_cell(det[key])} |")
        L.append("")
    exp = up.get("explanation") or {}
    if exp:
        L.append(f"**Explanation (Component 2 - XAI{', ' + _cell(exp['method']) if exp.get('method') else ''})**")
        L.append("")
        feats = exp.get("top_features") or []
        if feats:
            L.append("| Feature | Contribution | Direction |")
            L.append("|---|---|---|")
            for f in feats:
                if isinstance(f, dict):
                    L.append(f"| {_cell(f.get('feature', 'n/a'))} | {_cell(f.get('contribution', 'n/a'))} | "
                             f"{_cell(f.get('direction', 'n/a'))} |")
            L.append("")
        if exp.get("summary"):
            L.append(_cell(exp["summary"]))
            L.append("")
    pri = up.get("prioritization") or {}
    if pri:
        L.append("**Prioritization (Component 3 - SOC)**")
        L.append("")
        L.append("| Field | Value |")
        L.append("|---|---|")
        for key, label in (("priority_score", "Priority score"), ("reason", "Reason")):
            if key in pri:
                L.append(f"| {label} | {_cell(pri[key])} |")
        L.append("")
    L.append("*Upstream values are reported as supplied by the other components. This framework does not "
             "verify them, and its own findings below are derived only from the collected logs.*")
    L.append("")
    return L


def generate_report(evidence: List[EvidenceRecord],
                    clusters: List[CorrelatedCluster],
                    timeline: List[TimelineEvent],
                    rca: RootCauseAnalysis,
                    incident: Optional[Dict] = None,
                    manifest: Optional[Dict] = None,
                    figures: Optional[Dict[str, str]] = None) -> str:

    incident = incident or {}
    incident_id = incident.get("incident_id", "UNSPECIFIED")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    relevant = [r for c in clusters for r in c.records]
    relevant_ids = {r.record_id for r in relevant}
    stages = _stage_set(timeline)
    order = _distinct_stage_order(timeline)

    L: List[str] = []
    L.append(f"# Forensic Investigation Report - {incident_id}")
    L.append(f"*Generated: {generated_at}*  ")
    L.append("*Environment: Energy Plant IIoT / SCADA network*  ")
    if incident:
        L.append(f"*Trigger: confirmed incident from {incident.get('source_component', 'SOC component')} "
                 f"(priority {incident.get('priority', 'n/a')}), window "
                 f"{incident.get('window_start')} to {incident.get('window_end')}*")
    L.append("")

    L.append("## 1. Incident Summary")
    L.append(
        f"The attack originated from an **{rca.origin_type}** source (**{rca.entry_point_ip}**) and progressed through "
        f"the stages **{' -> '.join(order) if order else 'n/a'}**. The following asset(s) show attacker activity or "
        f"impact: **{', '.join(rca.compromised_energy_assets) or 'none identified'}**. "
        f"Of **{len(evidence)}** records collected in the incident window, **{len(relevant)}** were correlated as "
        f"attack evidence across {len({r.source for r in relevant})} sources (IT: firewall/IDS, OT: device logs) and "
        f"**{len(evidence) - len(relevant)}** were excluded as unrelated routine activity. The reconstructed timeline "
        f"spans {timeline[0].timestamp if timeline else 'N/A'} to {timeline[-1].timestamp if timeline else 'N/A'}.\n"
    )

    L.extend(upstream_section(incident))

    L.append("## 2. Evidence List (correlated records only)")
    L.append("| ID | Time | Source | Severity | Description |")
    L.append("|---|---|---|---|---|")
    for r in sorted(relevant, key=lambda x: x.timestamp):
        L.append(f"| {r.record_id} | {r.timestamp.strftime('%H:%M:%S')} | {r.source} | {r.severity} | {r.description} |")
    L.append("")

    L.append("## 3. Correlated IT-OT Evidence Clusters")
    for c in clusters:
        L.append(f"**Cluster {c.cluster_id}** - seed indicator `{c.key_ip}` - sources: {', '.join(c.sources)} - "
                 f"{c.start.strftime('%H:%M:%S')} to {c.end.strftime('%H:%M:%S')} ({len(c.records)} records)")
    L.append("")

    L.append("## 4. Attack Timeline")
    L.append("| Time | Stage | Asset | Source | Description |")
    L.append("|---|---|---|---|---|")
    for t in timeline:
        L.append(f"| {t.timestamp} | {t.stage} | {t.asset} | {t.source} | {t.description} |")
    L.append("")

    if figures:
        L.append("## 4b. Evidence Visualization")
        for title, fname in figures.items():
            L.append(f"**{title}**")
            L.append("")
            L.append(f"![{title}]({fname})")
            L.append("")
        L.append("An interactive-style summary page is available as `dashboard.html` in the same folder.")
        L.append("")

    L.append("## 5. Root Cause Analysis")
    L.append(f"- **Initial attack vector:** {rca.initial_vector}")
    L.append(f"- **Origin type:** {rca.origin_type}")
    L.append(f"- **Entry point IP:** {rca.entry_point_ip}")
    L.append(f"- **Entry asset:** {rca.entry_asset}")
    L.append(f"- **Affected assets (touched):** {', '.join(rca.affected_assets)}")
    L.append(f"- **Compromised assets (attacker acted / impact):** {', '.join(rca.compromised_energy_assets) or 'None identified'}")
    L.append("- **Stage sequence:** " + (" -> ".join(order) if order else "n/a"))
    L.append("")

    L.append("## 6. Recommendations")
    for rec in build_recommendations(rca, stages):
        L.append(f"- {rec}")
    L.append("")

    if manifest:
        L.append("## 7. Evidence Integrity (Chain of Custody)")
        L.append(f"Source files were hashed (SHA-256) at collection time: {manifest.get('collected_at')}.")
        L.append("")
        L.append("| File | SHA-256 |")
        L.append("|---|---|")
        for name, digest in manifest.get("files", {}).items():
            L.append(f"| {name} | `{digest}` |")
        L.append("")
    return "\n".join(L)
