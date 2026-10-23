"""
Load Edge-IIoTset CSVs and build a binary Normal vs DDoS HTTP Flood dataset.

Accepted inputs (any mix):
  * the per-sensor normal CSVs (Distance.csv, Heart_Rate.csv, Modbus.csv …)
  * DDoS_HTTP_Flood_attack.csv from Edge-IIoTset "Attack traffic"
  * the combined ML/DNN files (DNN-EdgeIIoT-dataset.csv, ML-EdgeIIoT-dataset.csv)

Only rows labelled Normal or DDoS_HTTP are kept; other attacks are ignored.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pandas as pd

from . import config


def _is_attack(label: pd.Series) -> pd.Series:
    return label.astype(str).str.strip().str.upper().str.replace(" ", "_").str.contains("DDOS_HTTP")


def _is_normal(label: pd.Series) -> pd.Series:
    return label.astype(str).str.strip().str.lower().eq(config.NORMAL_LABEL.lower())


def derive_attack_type(df: pd.DataFrame) -> pd.DataFrame:
    """Add Attack_type to a frame that only has the binary Attack_label.

    Normal = Attack_label 0; DDoS_HTTP = attack row requesting the flood URL
    (config.FLOOD_URI_REGEX); every other attack row is left out of training.
    """
    if config.LABEL_COL in df.columns or config.BINARY_LABEL_COL not in df.columns:
        return df
    attack = pd.to_numeric(df[config.BINARY_LABEL_COL], errors="coerce").fillna(0).astype(int) == 1
    uri = df.get(config.FLOOD_URI_COL, pd.Series("", index=df.index)).astype(str).str.strip()
    flood = attack & uri.str.match(config.FLOOD_URI_REGEX, case=False)
    df = df.copy()
    df[config.LABEL_COL] = config.OTHER_ATTACK_LABEL
    df.loc[~attack, config.LABEL_COL] = config.NORMAL_LABEL
    df.loc[flood, config.LABEL_COL] = config.ATTACK_LABEL
    return df


def read_csv(path: str | Path, chunksize: int = 200_000) -> pd.DataFrame:
    """Read one CSV, keeping only Normal / DDoS_HTTP rows (chunked for big files)."""
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
    """Return (raw feature frame, y) where y = 1 for DDoS HTTP Flood."""
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
            print(f"  {path.name:<40} normal={len(nor):>7,}  ddos_http={len(att):>7,}")

    normal = pd.concat(normal_parts, ignore_index=True) if normal_parts else pd.DataFrame()
    attack = pd.concat(attack_parts, ignore_index=True) if attack_parts else pd.DataFrame()

    if attack.empty:
        raise ValueError(
            "No DDoS_HTTP rows found in the supplied files. Add Edge-IIoTset's "
            "'DDoS_HTTP_Flood_attack.csv' (Attack traffic folder) or "
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
