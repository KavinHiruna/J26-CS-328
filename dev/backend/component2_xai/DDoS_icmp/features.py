"""
Feature engineering for DDoS ICMP Flood detection on Edge-IIoTset style CSVs.

Edge-IIoTset does not export every field in the parameter sheet (for example
ip.proto, icmp.type, frame.len and TTL are missing from the published CSVs).
`build_features` therefore uses the real column when it exists and otherwise
derives or estimates it. What was derived is reported in `FeatureReport` so the
dashboard can label those values honestly ("inferred" / "estimated" / "n/a").
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .config import (
    ATTACK_TYPE_ALIASES,
    MODEL_FEATURES,
    WINDOW_SECONDS,
)

_TIME_RE = re.compile(r"(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)")

# Ethernet(14) + IPv4(20) header bytes
_L2L3 = 34
_ICMP_DEFAULT_LEN = _L2L3 + 8 + 56   # default ping payload -> 98 bytes on the wire
_UDP_HDR = 8
_TCP_HDR = 20
_ARP_LEN = 42


@dataclass
class FeatureReport:
    n_rows: int = 0
    source_columns: dict = field(default_factory=dict)   # feature -> "column" | "inferred" | "estimated" | "unavailable"
    has_labels: bool = False
    label_column: str | None = None
    attack_types: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def status(self, feature: str) -> str:
        return self.source_columns.get(feature, "column")


# --------------------------------------------------------------------------- helpers
def to_numeric(series: pd.Series) -> pd.Series:
    """Numeric conversion that also understands hex strings such as '0x00000010'."""
    if pd.api.types.is_numeric_dtype(series):
        return series.astype(float)
    s = series.astype(str).str.strip()
    out = pd.to_numeric(s, errors="coerce")
    hex_mask = out.isna() & s.str.match(r"^0x[0-9a-fA-F]+$", na=False)
    if hex_mask.any():
        out.loc[hex_mask] = s[hex_mask].map(lambda v: float(int(v, 16)))
    return out.astype(float)


def _col(df: pd.DataFrame, *names: str) -> pd.Series | None:
    for n in names:
        if n in df.columns:
            return df[n]
    return None


def _nonzero(df: pd.DataFrame, cols: list[str]) -> pd.Series:
    mask = pd.Series(False, index=df.index)
    for c in cols:
        if c in df.columns:
            mask |= to_numeric(df[c]).fillna(0).ne(0)
    return mask


def parse_timestamps(df: pd.DataFrame, report: FeatureReport) -> pd.Series:
    """Seconds as float. Uses frame.time_epoch / frame.time_relative or parses frame.time."""
    direct = _col(df, "frame.time_epoch", "frame.time_relative", "timestamp", "ts")
    if direct is not None:
        t = to_numeric(direct)
        if t.notna().mean() > 0.5:
            return t.interpolate(limit_direction="both").fillna(0.0)

    raw = _col(df, "frame.time")
    if raw is None:
        report.notes.append("No timestamp column - packet order used as time (1 ms spacing).")
        return pd.Series(np.arange(len(df)) * 1e-3, index=df.index, dtype=float)

    parts = raw.astype(str).str.extract(_TIME_RE)
    secs = (
        pd.to_numeric(parts[0], errors="coerce") * 3600
        + pd.to_numeric(parts[1], errors="coerce") * 60
        + pd.to_numeric(parts[2], errors="coerce")
    )
    bad = secs.isna().mean()
    if bad > 0:
        report.notes.append(f"{bad:.1%} of frame.time values could not be parsed and were interpolated.")
    if secs.notna().sum() == 0:
        return pd.Series(np.arange(len(df)) * 1e-3, index=df.index, dtype=float)
    secs = secs.interpolate(limit_direction="both")
    # handle midnight roll-over (time goes 23:59:59 -> 00:00:00)
    jumps = secs.diff().fillna(0)
    secs = secs + (jumps < -43_200).cumsum() * 86_400
    return secs.astype(float)


# --------------------------------------------------------------------------- labels
def extract_labels(df: pd.DataFrame, report: FeatureReport) -> tuple[pd.Series | None, pd.Series | None]:
    """Returns (binary_target, attack_type). Target = 1 for ICMP flood, 0 for everything else."""
    atype = _col(df, "Attack_type", "attack_type", "Label", "label")
    alabel = _col(df, "Attack_label", "attack_label")
    if atype is not None:
        atype = atype.astype(str).str.strip()
        aliases = {a.lower() for a in ATTACK_TYPE_ALIASES}
        target = atype.str.lower().isin(aliases).astype(int)
        report.has_labels = True
        report.label_column = atype.name
        report.attack_types = atype.value_counts().to_dict()
        return target, atype
    if alabel is not None:
        target = to_numeric(alabel).fillna(0).astype(int).clip(0, 1)
        report.has_labels = True
        report.label_column = alabel.name
        report.attack_types = target.map({0: "Normal", 1: "Attack"}).value_counts().to_dict()
        return target, target.map({0: "Normal", 1: "Attack"})
    return None, None


# --------------------------------------------------------------------------- main builder
def build_features(df_raw: pd.DataFrame, window_seconds: float = WINDOW_SECONDS) -> tuple[pd.DataFrame, FeatureReport]:
    """
    Turn a raw Edge-IIoTset packet CSV into one row per packet with the
    parameter-sheet features + context columns (row_id, src_ip, dst_ip, timestamp, window_id)
    and, when labels exist, `target` (1 = DDoS ICMP flood) and `attack_type`.
    """
    report = FeatureReport(n_rows=len(df_raw))
    df = df_raw.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.reset_index(drop=True)
    out = pd.DataFrame(index=df.index)
    out["row_id"] = np.arange(len(df))

    src = _col(df, "ip.src_host", "ip.src", "src_ip", "Source IP")
    dst = _col(df, "ip.dst_host", "ip.dst", "dst_ip", "Destination IP")
    out["src_ip"] = (src.astype(str).str.strip() if src is not None else pd.Series("unknown", index=df.index))
    out["dst_ip"] = (dst.astype(str).str.strip() if dst is not None else pd.Series("unknown", index=df.index))
    out["timestamp"] = parse_timestamps(df, report)

    # ---- ip.proto
    icmp_cols = ["icmp.checksum", "icmp.seq_le", "icmp.transmit_timestamp", "icmp.unused", "icmp.type"]
    is_icmp = _nonzero(df, icmp_cols)
    proto_col = _col(df, "ip.proto", "ip_proto")
    if proto_col is not None:
        proto = to_numeric(proto_col).fillna(0)
        report.source_columns["ip_proto"] = "column"
    else:
        proto = pd.Series(0.0, index=df.index)
        is_tcp = _nonzero(df, ["tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.seq", "tcp.ack"])
        is_udp = _nonzero(df, ["udp.port", "udp.stream", "udp.time_delta"])
        proto[is_udp] = 17
        proto[is_tcp] = 6
        proto[is_icmp] = 1
        report.source_columns["ip_proto"] = "inferred"
    out["ip_proto"] = proto.astype(float)
    icmp_mask = out["ip_proto"].eq(1)

    # ---- icmp.type / icmp.code
    type_col, code_col = _col(df, "icmp.type"), _col(df, "icmp.code")
    if type_col is not None:
        out["icmp_type"] = to_numeric(type_col).fillna(-1)
        out.loc[~icmp_mask, "icmp_type"] = -1
        report.source_columns["icmp_type"] = "column"
    else:
        itype = pd.Series(-1.0, index=df.index)
        if icmp_mask.any():
            seq = to_numeric(_col(df, "icmp.seq_le")).fillna(0) if "icmp.seq_le" in df else pd.Series(0.0, index=df.index)
            ts_req = _nonzero(df, ["icmp.transmit_timestamp"])
            a = np.where(out["src_ip"] < out["dst_ip"], out["src_ip"], out["dst_ip"])
            b = np.where(out["src_ip"] < out["dst_ip"], out["dst_ip"], out["src_ip"])
            key = pd.Series(a, index=df.index) + "|" + pd.Series(b, index=df.index) + "|" + seq.astype(str)
            sub = pd.DataFrame({"key": key[icmp_mask], "src": out.loc[icmp_mask, "src_ip"]})
            first_src = sub.groupby("key")["src"].transform("first")
            echo = np.where(sub["src"].eq(first_src), 8.0, 0.0)   # first sender = request, other side = reply
            itype.loc[icmp_mask] = echo
            itype.loc[icmp_mask & ts_req] = 13.0                   # timestamp request
        out["icmp_type"] = itype
        report.source_columns["icmp_type"] = "inferred"
    if code_col is not None:
        out["icmp_code"] = to_numeric(code_col).fillna(-1)
        out.loc[~icmp_mask, "icmp_code"] = -1
        report.source_columns["icmp_code"] = "column"
    else:
        out["icmp_code"] = np.where(icmp_mask, 0.0, -1.0)
        report.source_columns["icmp_code"] = "inferred"

    # ---- frame.len
    flen_col = _col(df, "frame.len", "frame_len")
    if flen_col is not None and to_numeric(flen_col).fillna(0).gt(0).any():
        out["frame_len"] = to_numeric(flen_col).fillna(0)
        report.source_columns["frame_len"] = "column"
    else:
        tcp_len = to_numeric(df["tcp.len"]).fillna(0) if "tcp.len" in df else pd.Series(0.0, index=df.index)
        est = pd.Series(float(_ARP_LEN), index=df.index)
        is_tcp = out["ip_proto"].eq(6)
        est[is_tcp] = _L2L3 + _TCP_HDR + tcp_len[is_tcp]
        est[out["ip_proto"].eq(17)] = _L2L3 + _UDP_HDR + 32
        est[icmp_mask] = _ICMP_DEFAULT_LEN
        out["frame_len"] = est.astype(float)
        report.source_columns["frame_len"] = "estimated"

    # ---- TTL
    ttl_col = _col(df, "ip.ttl", "ttl", "TTL")
    if ttl_col is not None:
        out["ttl"] = to_numeric(ttl_col).fillna(0)
        report.source_columns["ttl"] = "column"
    else:
        out["ttl"] = 0.0
        report.source_columns["ttl"] = "unavailable"
        report.notes.append("TTL is not exported in this CSV - feature kept at 0 (no influence on the model).")

    # ---- order by time (stable) for deltas and windows
    out =out.sort_values(["timestamp", "row_id"], kind="mergesort")

    # ---- frame.time_delta (to the same destination)
    delta_col = _col(df, "frame.time_delta", "frame.time_delta_displayed")
    if delta_col is not None:
        out["frame_time_delta"] = to_numeric(delta_col).reindex(out.index).fillna(0).clip(lower=0)
        report.source_columns["frame_time_delta"] = "column"
    else:
        d = out.groupby("dst_ip")["timestamp"].diff()
        out["frame_time_delta"] = d.fillna(window_seconds).clip(lower=0, upper=60)
        report.source_columns["frame_time_delta"] = "inferred"

    # ---- window (target-centric) features
    t0 = out["timestamp"].min()
    out["window_id"] = np.floor((out["timestamp"] - t0) / window_seconds).astype(int)
    g = out.groupby(["dst_ip", "window_id"])
    win_pkts = g["row_id"].transform("count").astype(float)
    win_bytes = g["frame_len"].transform("sum").astype(float)
    out["pkts_per_sec"] = win_pkts / window_seconds
    out["bytes_per_sec"] = win_bytes / window_seconds
    out["unique_src_count"] = g["src_ip"].transform("nunique").astype(float)
    per_src = out.groupby(["dst_ip", "window_id", "src_ip"])["row_id"].transform("count").astype(float)
    top_src = per_src.groupby([out["dst_ip"], out["window_id"]]).transform("max")
    out["src_concentration"] = (top_src / win_pkts).fillna(1.0)
    for f in ("pkts_per_sec", "bytes_per_sec", "unique_src_count", "src_concentration"):
        report.source_columns[f] = "inferred"

    # ---- flow (src, dst, proto) inside the window
    fg = out.groupby(["src_ip", "dst_ip", "ip_proto", "window_id"])
    out["flow_pkt_count"] = fg["row_id"].transform("count").astype(float)
    out["flow_byte_count"] = fg["frame_len"].transform("sum").astype(float)
    out["flow_duration"] = (fg["timestamp"].transform("max") - fg["timestamp"].transform("min")).astype(float)
    for f in ("flow_pkt_count", "flow_byte_count", "flow_duration"):
        report.source_columns[f] = "inferred"

    out = out.sort_values("row_id")

    target, atype = extract_labels(df, report)
    if target is not None:
        out["target"] = target.values
        out["attack_type"] = atype.values

    for f in MODEL_FEATURES:
        out[f] = pd.to_numeric(out[f], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)

    return out.reset_index(drop=True), report


def build_features_many(frames: list[pd.DataFrame], window_seconds: float = WINDOW_SECONDS) -> tuple[pd.DataFrame, FeatureReport]:
    """Engineer each capture separately (time windows must not mix captures) then stack."""
    parts, merged = [], FeatureReport()
    offset = 0
    for i, f in enumerate(frames):
        feat, rep = build_features(f, window_seconds)
        feat["row_id"] += offset
        feat["capture"] = i
        offset += len(feat)
        parts.append(feat)
        merged.n_rows += rep.n_rows
        merged.has_labels = merged.has_labels or rep.has_labels
        for k, v in rep.source_columns.items():
            merged.source_columns.setdefault(k, v)
        for k, v in rep.attack_types.items():
            merged.attack_types[k] = merged.attack_types.get(k, 0) + v
        merged.notes.extend(rep.notes)
    merged.notes = list(dict.fromkeys(merged.notes))
    return pd.concat(parts, ignore_index=True), merged
