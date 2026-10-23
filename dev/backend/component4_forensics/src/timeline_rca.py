"""
Stage 4: Attack Timeline Reconstruction
Stage 5: Root Cause Analysis (identifies the specific compromised energy assets)

Contains BOTH the original v1 logic (kept as the evaluation baseline) and the
improved v2 logic (source-aware stage classification, seeded RCA with
internal/external origin handling).
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, List, Optional

from log_loader import EvidenceRecord
from correlator import CorrelatedCluster

IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# ---------------------------------------------------------------------------
# Stage classification
# ---------------------------------------------------------------------------
# v1 (legacy): first matching keyword wins.  Known weakness: "SSH Brute Force
# *Login* Attempt" matches "login" first and is mislabelled "Initial Access".
STAGE_KEYWORDS = [
    ("allow tcp", "Reconnaissance / Network Connection"),
    ("login", "Initial Access"),
    ("auth_fail", "Credential Access (Attempt)"),
    ("auth_success", "Credential Access (Success)"),
    ("brute force", "Credential Access (Success)"),
    ("scan", "Reconnaissance"),
    ("nmap", "Reconnaissance"),
    ("malware", "Malware Delivery"),
    ("file_write", "Malware Delivery"),
    ("process_start", "Execution"),
    ("config_access", "Discovery / Staging"),
    ("logic_change", "Impact - Breaker/PLC Compromised"),
    ("state_change", "Impact - Breaker/PLC Compromised"),
    ("modbus write function code anomaly", "Impact - Breaker/PLC Compromised"),
]


def classify_stage_legacy(record: EvidenceRecord) -> str:
    text = (record.description + " " + record.event_type).lower()
    for keyword, stage in STAGE_KEYWORDS:
        if keyword in text:
            return stage
    return "Uncategorized"


# v2: use the structured field each source already provides (IDS category,
# device event type) and fall back to keywords only when nothing matches.
IDS_CATEGORY_STAGE = {
    "reconnaissance": "Reconnaissance",
    "initial-access": "Initial Access",
    "credential-access": "Credential Access",
    "malware": "Malware Delivery",
    "lateral-movement": "Lateral Movement",
    "command-and-control": "Command and Control",
    "ics-attack": "Impact",
}
DEVICE_EVENT_STAGE = {
    "login": "Initial Access",
    "vpn_login": "Initial Access",
    "auth_fail": "Credential Access",
    "auth_success": "Credential Access",
    "cred_dump": "Credential Access",
    "file_write": "Malware Delivery",
    "process_start": "Execution",
    "rdp_session": "Lateral Movement",
    "remote_login": "Lateral Movement",
    "config_access": "Discovery",
    "logic_change": "Impact",
    "state_change": "Impact",
    "setpoint_change": "Impact",
}


def classify_stage(record: EvidenceRecord) -> str:
    if record.source == "firewall":
        return "Network Connection"          # a firewall line is supporting evidence, not a stage
    if record.source == "ids":
        stage = IDS_CATEGORY_STAGE.get(str(record.raw.get("category", "")).strip().lower())
        if stage:
            return stage
    if record.source == "device":
        stage = DEVICE_EVENT_STAGE.get(record.event_type)
        if stage:
            return stage
    return classify_stage_legacy(record)


CANONICAL_STAGES = [
    "Reconnaissance", "Initial Access", "Credential Access", "Malware Delivery",
    "Execution", "Command and Control", "Lateral Movement", "Discovery", "Impact", "Network Connection",
]


def canonical_stage(stage: str) -> str:
    """Collapse detailed stage labels (e.g. 'Impact - Breaker/PLC Compromised') to a canonical name."""
    for c in CANONICAL_STAGES:
        if stage.startswith(c):
            return c
    return "Uncategorized"


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
@dataclass
class TimelineEvent:
    timestamp: str
    stage: str
    source: str
    asset: str
    description: str
    evidence_id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None


def build_timeline(clusters: List[CorrelatedCluster],
                   classifier: Callable[[EvidenceRecord], str] = classify_stage) -> List[TimelineEvent]:
    """Stage 4: flatten correlated clusters into one chronological, stage-labelled timeline."""
    seen = {}
    for c in clusters:
        for r in c.records:
            seen[r.record_id] = r
    ordered = sorted(seen.values(), key=lambda r: r.timestamp)
    return [
        TimelineEvent(
            timestamp=r.timestamp.strftime("%H:%M:%S"),
            stage=classifier(r),
            source=r.source,
            asset=r.asset or (r.dst_ip or "n/a"),
            description=r.description,
            evidence_id=r.record_id,
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
        )
        for r in ordered
    ]


# ---------------------------------------------------------------------------
# Root cause analysis
# ---------------------------------------------------------------------------
@dataclass
class RootCauseAnalysis:
    initial_vector: str
    entry_point_ip: str
    entry_asset: str
    affected_assets: List[str]
    compromised_energy_assets: List[str]
    attack_sequence: List[str]
    origin_type: str = "unknown"          # external | internal | unknown


ENERGY_ASSET_KEYWORDS = ["plc", "breaker", "scada", "ems", "rtu", "substation"]


def is_energy_asset(asset_name: str) -> bool:
    name = asset_name.lower()
    return any(k in name for k in ENERGY_ASSET_KEYWORDS)


def perform_rca_legacy(timeline: List[TimelineEvent], evidence: List[EvidenceRecord]) -> RootCauseAnalysis:
    """v1 RCA (baseline): first event = vector; entry IP = first non-10.10.0.x source."""
    if not timeline:
        return RootCauseAnalysis("Unknown", "Unknown", "Unknown", [], [], [])
    first_event = timeline[0]
    affected = sorted(set(t.asset for t in timeline if t.asset))
    compromised = sorted(set(
        t.asset for t in timeline
        if (t.stage.startswith("Impact") or t.stage == "Execution") and is_energy_asset(t.asset)
    ))
    if not compromised:
        compromised = sorted(set(t.asset for t in timeline if t.stage.startswith("Impact")))
    entry_ip = "Unknown"
    for r in evidence:
        if r.src_ip and not r.src_ip.startswith("10.10.0"):
            entry_ip = r.src_ip
            break
    sequence = [f"{t.timestamp} - {t.stage} ({t.asset})" for t in timeline]
    return RootCauseAnalysis(first_event.stage, entry_ip, first_event.asset, affected,
                             compromised, sequence, "unknown")


# Address space that counts as "inside the plant". Note: ipaddress.is_private is NOT used,
# because documentation/test ranges (203.0.113.0/24, 198.51.100.0/24) are flagged private
# by Python although they are outside the plant network.
PLANT_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in PLANT_NETWORKS)


ACTION_STAGES = {"Initial Access", "Credential Access", "Malware Delivery", "Execution",
                 "Lateral Movement", "Discovery", "Impact"}


def _asset_ip(name: str) -> Optional[str]:
    if not name or "/" in name:                 # skip subnet-wide targets such as 10.10.0.0/24
        return None
    m = IP_RE.search(name)
    return m.group(0) if m else None


def perform_rca(timeline: List[TimelineEvent],
                evidence: List[EvidenceRecord],
                seed_ips: List[str]) -> RootCauseAnalysis:
    """
    v2 RCA.
      * initial vector  = stage of the earliest STAGE-BEARING event (IDS/device),
                          not a bare firewall connection;
      * entry point     = the seed IP that appears as the earliest source;
      * origin type     = external vs internal (insider / unauthorised device);
      * compromised     = hosts where the attacker ACTED (device events in action
                          stages, or IDS malware/impact targets) - not merely scanned hosts.
    """
    if not timeline:
        return RootCauseAnalysis("Unknown", "Unknown", "Unknown", [], [], [], "unknown")

    stage_events = [t for t in timeline if canonical_stage(t.stage) != "Network Connection"]
    first = stage_events[0] if stage_events else timeline[0]

    entry_ip = next((t.src_ip for t in timeline if t.src_ip in seed_ips),
                    seed_ips[0] if seed_ips else "Unknown")
    try:
        origin = "internal" if _is_internal(entry_ip) else "external"
    except ValueError:
        origin = "unknown"

    names_by_ip = {}
    for r in evidence:
        if r.source == "device":
            ip = _asset_ip(r.asset)
            if ip:
                names_by_ip.setdefault(ip, r.asset)

    compromised_ips: List[str] = []
    for t in stage_events:
        st = canonical_stage(t.stage)
        ip = _asset_ip(t.asset)
        if not ip:
            continue
        if (t.source == "device" and st in ACTION_STAGES) or \
           (t.source == "ids" and st in {"Malware Delivery", "Impact"}):
            if ip not in compromised_ips:
                compromised_ips.append(ip)

    affected_ips: List[str] = []
    for t in timeline:
        ip = _asset_ip(t.asset)
        if ip and ip not in affected_ips:
            affected_ips.append(ip)

    if origin == "internal":
        entry_asset = f"{entry_ip} (unauthorised internal device)"
    else:
        init = next((t for t in stage_events if canonical_stage(t.stage) == "Initial Access"), first)
        entry_asset = init.asset

    return RootCauseAnalysis(
        initial_vector=first.stage,
        entry_point_ip=entry_ip,
        entry_asset=entry_asset,
        affected_assets=[names_by_ip.get(ip, ip) for ip in affected_ips],
        compromised_energy_assets=[names_by_ip.get(ip, ip) for ip in compromised_ips],
        attack_sequence=[f"{t.timestamp} - {t.stage} ({t.asset})" for t in timeline],
        origin_type=origin,
    )
