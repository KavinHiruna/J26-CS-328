"""
Load Edge-IIoTset CSVs and build a binary Normal vs DDoS Network Flood dataset (TCP SYN · UDP · ICMP).

Accepted inputs (any mix):
  * the per-sensor normal CSVs (Distance.csv, Heart_Rate.csv, Modbus.csv …)
  * DDoS_TCP_SYN_Flood / DDoS_UDP_Flood / DDoS_ICMP_Flood CSVs from Edge-IIoTset "Attack traffic"
  * the combined ML/DNN files (DNN-EdgeIIoT-dataset.csv, ML-EdgeIIoT-dataset.csv)

Only rows labelled Normal, DDoS_TCP, DDoS_UDP or DDoS_ICMP are kept; other attacks are ignored.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pandas as pd

from . import config


def _is_attack(label: pd.Series) -> pd.Series:
    """Rows of the flood type(s) this package detects (config.ATTACK_LABELS)."""
    wanted = "|".join(a.upper() for a in config.ATTACK_LABELS)
    return label.astype(str).str.strip().str.upper().str.replace(" ", "_").str.contains(f"^(?:{wanted})", regex=True)


def _is_normal(label: pd.Series) -> pd.Series:
    return label.astype(str).str.strip().str.lower().eq(config.NORMAL_LABEL.lower())


_EMPTY = ["", "0", "0.0", "nan"]
_IPV4 = r"^\d{1,3}(?:\.\d{1,3}){3}$"


def _col(df: pd.DataFrame, name: str) -> pd.Series:
    return df[name].astype(str).str.strip() if name in df.columns else pd.Series("", index=df.index)


def repair_shifted(df: pd.DataFrame) -> pd.DataFrame:
    """Rows whose frame.time holds an IP lost their timestamp and are shifted one column left.

    Puts source/destination back (ip.src_host <- frame.time, ip.dst_host <- ip.src_host) and
    blanks frame.time; other fields are left as exported. Returns a copy only if needed.
    """
    if config.TIME_COL not in df.columns or "ip.src_host" not in df.columns or "ip.dst_host" not in df.columns:
        return df
    shifted = df[config.TIME_COL].astype(str).str.strip().str.match(_IPV4)
    if not shifted.any():
        return df
    df = df.copy()
    df.loc[shifted, "ip.dst_host"] = df.loc[shifted, "ip.src_host"]
    df.loc[shifted, "ip.src_host"] = df.loc[shifted, config.TIME_COL].astype(str).str.strip()
    df.loc[shifted, config.TIME_COL] = ""
    return df


def protocol(df: pd.DataFrame) -> pd.Series:
    """Per-packet protocol view used for flood types: ICMP / UDP / TCP SYN / TCP / other."""
    is_icmp = pd.Series(False, index=df.index)
    for c in config.ICMP_COLS:
        is_icmp |= ~_col(df, c).isin(_EMPTY)
    is_udp = pd.Series(False, index=df.index)
    for c in config.UDP_COLS:
        is_udp |= ~_col(df, c).isin(_EMPTY)
    syn = _col(df, "tcp.connection.syn").str.startswith("1") & ~_col(df, "tcp.flags.ack").str.startswith("1")
    is_tcp = ~_col(df, "tcp.flags").isin(_EMPTY) | ~_col(df, "tcp.len").isin(_EMPTY) | syn
    out = pd.Series("other", index=df.index)
    out[is_tcp] = "TCP"
    out[syn] = "TCP SYN"
    out[is_udp] = "UDP"
    out[is_icmp] = "ICMP"
    return out


def derive_attack_type(df: pd.DataFrame) -> pd.DataFrame:
    """Add Attack_type (DDoS_ICMP / DDoS_UDP / DDoS_TCP) to a frame that only has Attack_label.

    Rules in config.py; Normal = Attack_label 0; every other attack row is left out of training.
    """
    df = repair_shifted(df)
    if config.LABEL_COL in df.columns or config.BINARY_LABEL_COL not in df.columns:
        return df
    attack = pd.to_numeric(df[config.BINARY_LABEL_COL], errors="coerce").fillna(0).astype(int) == 1
    proto = protocol(df)
    src, dst = _col(df, "ip.src_host"), _col(df, "ip.dst_host")
    scanner = src.isin(config.SCANNER_HOSTS) | dst.isin(config.SCANNER_HOSTS)
    valid_time = _col(df, config.TIME_COL).str.contains(":", regex=False)
    df = df.copy()
    df[config.LABEL_COL] = config.OTHER_ATTACK_LABEL
    df.loc[~attack, config.LABEL_COL] = config.NORMAL_LABEL
    rules = {"DDoS_TCP": attack & (proto == "TCP SYN") & ~src.isin(config.TESTBED_HOSTS),
             "DDoS_UDP": attack & (proto == "UDP") & ~scanner,
             "DDoS_ICMP": attack & (proto == "ICMP") & ~scanner & valid_time}
    for name, mask in rules.items():
        df.loc[mask, config.LABEL_COL] = name     # other floods stay labelled; _is_attack picks this package's
    return df


def read_csv(path: str | Path, chunksize: int = 200_000) -> pd.DataFrame:
    """Read one CSV, keeping only Normal / network-flood rows (chunked for big files)."""
    frames = []
    for chunk in pd.read_csv(path, low_memory=False, chunksize=chunksize, dtype=str):
        chunk.columns = [c.strip() for c in chunk.columns]
        chunk = derive_attack_type(chunk)
        if config.LABEL_COL not in chunk.columns:
            raise ValueError(f"{path}: missing '{config.LABEL_COL}' or '{config.BINARY_LABEL_COL}' column")
        keep = _is_attack(chunk[config.LABEL_COL]) | _is_normal(chunk[config.LABEL_COL])
        frames.append(chunk[keep])
    df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    df["__source"] = Path(path).name
    return df


def expand_paths(paths: Iterable[str | Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out.extend(sorted(p.rglob("*.csv")))
        elif p.exists():
            out.append(p)
        else:
            raise FileNotFoundError(p)
    return out


def build_dataset(paths: Iterable[str | Path],
                  max_normal_per_file: int = config.MAX_NORMAL_ROWS_PER_FILE,
                  max_attack: int = config.MAX_ATTACK_ROWS,
                  seed: int = config.RANDOM_STATE,
                  verbose: bool = True) -> tuple[pd.DataFrame, pd.Series]:
    """Return (raw feature frame, y) where y = 1 for the flood type(s) in config.ATTACK_LABELS."""
    normal_parts, attack_parts = [], []
    for path in expand_paths(paths):
        df = read_csv(path)
        att = df[_is_attack(df[config.LABEL_COL])]
        nor = df[_is_normal(df[config.LABEL_COL])]
        if len(nor) > max_normal_per_file:
            nor = nor.sample(max_normal_per_file, random_state=seed)
        normal_parts.append(nor)
        attack_parts.append(att)
        if verbose:
            print(f"  {path.name:<40} normal={len(nor):>7,}  network_flood={len(att):>7,}")

    normal = pd.concat(normal_parts, ignore_index=True) if normal_parts else pd.DataFrame()
    attack = pd.concat(attack_parts, ignore_index=True) if attack_parts else pd.DataFrame()

    if attack.empty:
        raise ValueError(
            "No DDoS_TCP / DDoS_UDP / DDoS_ICMP rows found in the supplied files. Add Edge-IIoTset's "
            "network-flood CSVs (Attack traffic folder) or "
            "'DNN-EdgeIIoT-dataset.csv'."
        )
    if normal.empty:
        raise ValueError("No Normal rows found in the supplied files.")

    if len(attack) > max_attack:
        attack = attack.sample(max_attack, random_state=seed)

    data = pd.concat([normal, attack], ignore_index=True)
    # Paper preprocessing: drop duplicates & rows with missing labels.
    feature_cols = [c for c in data.columns if c not in config.DROP_COLUMNS and c != "__source"]
    before = len(data)
    if config.DROP_DUPLICATES:
        dup = data.duplicated(subset=feature_cols + [config.LABEL_COL])
        if not config.DROP_DUPLICATE_ATTACK_ROWS:
            dup &= ~_is_attack(data[config.LABEL_COL])
        data = data[~dup].reset_index(drop=True)
    if verbose:
        print(f"  removed {before - len(data):,} duplicate rows")

    y = _is_attack(data[config.LABEL_COL]).astype(int)
    return data, y
