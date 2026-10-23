"""
Stage 1-2: Log Collection & Evidence Collection/Normalization
Parses heterogeneous energy plant IIoT/SCADA log sources (firewall, IDS,
OT device logs) into a unified EvidenceRecord schema for correlation.
"""

import csv
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
import hashlib


@dataclass
class EvidenceRecord:
    """Normalized evidence record - common schema across all log sources."""
    timestamp: datetime
    source: str            # e.g. "firewall", "ids", "device"
    event_type: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    asset: Optional[str]   # device/host identifier if applicable
    description: str
    severity: str = "Info"
    raw: dict = field(default_factory=dict)
    record_id: str = ""

    def __post_init__(self):
        basis = f"{self.timestamp}|{self.source}|{self.description}"
        self.record_id = hashlib.sha256(basis.encode()).hexdigest()[:12]


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S")


def load_firewall_log(path: str) -> List[EvidenceRecord]:
    records = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            records.append(EvidenceRecord(
                timestamp=_parse_ts(row["timestamp"]),
                source="firewall",
                event_type="connection",
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                asset=row["dst_ip"],
                description=f"{row['action']} {row['protocol']} {row['src_ip']} -> "
                             f"{row['dst_ip']}:{row['dst_port']}",
                severity="Info",
                raw=row,
            ))
    return records


def load_ids_log(path: str) -> List[EvidenceRecord]:
    records = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            records.append(EvidenceRecord(
                timestamp=_parse_ts(row["timestamp"]),
                source="ids",
                event_type="alert",
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                asset=row["dst_ip"],
                description=f"{row['signature']} ({row['category']})",
                severity=row["severity"],
                raw=row,
            ))
    return records


def load_device_log(path: str) -> List[EvidenceRecord]:
    """Parses OT device logs (SCADA engineering workstation, substation PLC)."""
    records = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            records.append(EvidenceRecord(
                timestamp=_parse_ts(row["timestamp"]),
                source="device",
                event_type=row["event_type"].lower(),
                src_ip=None,
                dst_ip=None,
                asset=row["device"],
                description=f"[{row['device']}] {row['event_type']} by {row['user']}: "
                             f"{row['description']}",
                severity="High" if row["event_type"] in (
                    "LOGIC_CHANGE", "STATE_CHANGE", "PROCESS_START") else "Info",
                raw=row,
            ))
    return records


def load_all_evidence(firewall_path: str, ids_path: str, device_path: str) -> List[EvidenceRecord]:
    """Collects and normalizes evidence from all configured sources (Stage 1-2)."""
    evidence = []
    evidence.extend(load_firewall_log(firewall_path))
    evidence.extend(load_ids_log(ids_path))
    evidence.extend(load_device_log(device_path))
    evidence.sort(key=lambda r: r.timestamp)
    return evidence


# Public alias so other modules can parse timestamps the same way
parse_ts = _parse_ts


def scope_evidence(evidence: List[EvidenceRecord], window_start: str, window_end: str) -> List[EvidenceRecord]:
    """
    Step 1 scoping: keep only evidence inside the incident time window that the
    confirmed-incident handoff (Component 3) provides.
    """
    start, end = _parse_ts(window_start), _parse_ts(window_end)
    return [r for r in evidence if start <= r.timestamp <= end]
