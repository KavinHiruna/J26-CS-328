"""
FIX M5 — Rate-based features derived from raw packet columns.

Computed BEFORE identifier columns are dropped so the model can learn the
real flood signature (high request rate from few sources) instead of
shortcut features like "is this HTTP?".

Each feature name starts with ``_rate_`` so it sorts together and is easy
to spot in importance rankings.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import config

_EMPTY = {"", "0", "0.0", "nan", "None", "none"}


def _parse_seconds(df: pd.DataFrame) -> pd.Series:
    """frame.time → seconds since midnight (NaN when absent or unparseable)."""
    if "frame.time" not in df.columns:
        return pd.Series(np.nan, index=df.index)
    hms = df["frame.time"].astype(str).str.extract(
        r"(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)")
    return (hms[0].astype(float) * 3600
            + hms[1].astype(float) * 60
            + hms[2].astype(float))


def _is_http_request(df: pd.DataFrame) -> pd.Series:
    method = (df["http.request.method"].astype(str).str.strip()
              if "http.request.method" in df.columns
              else pd.Series("", index=df.index))
    return ~method.isin(_EMPTY)


def add_rate_features(df: pd.DataFrame,
                      window_s: float = config.RATE_WINDOW_S) -> pd.DataFrame:
    """Return *df* with ``_rate_*`` columns appended (no columns removed)."""
    df = df.copy()
    secs = _parse_seconds(df)
    src = (df["ip.src_host"].astype(str).str.strip()
           if "ip.src_host" in df.columns
           else pd.Series("unknown", index=df.index))
    is_http = _is_http_request(df)

    # -- per-source statistics (groupby src) ----------------------------------
    g = df.assign(_src=src, _sec=secs, _http=is_http.astype(int)).groupby("_src")
    src_pkt = g["_src"].transform("count")
    src_req = g["_http"].transform("sum")
    src_span = g["_sec"].transform(lambda s: s.max() - s.min())
    src_span = src_span.clip(lower=1.0)
    df["_rate_src_pkt_count"] = src_pkt
    df["_rate_src_req_count"] = src_req
    df["_rate_src_req_per_s"] = src_req / src_span

    # inter-packet time within each source
    sorted_df = df.assign(_src=src, _sec=secs).sort_values(["_src", "_sec"])
    deltas = sorted_df.groupby("_src")["_sec"].diff()
    mean_delta = deltas.groupby(sorted_df["_src"]).transform("mean").reindex(df.index)
    std_delta = deltas.groupby(sorted_df["_src"]).transform("std").reindex(df.index)
    df["_rate_src_interval_mean"] = mean_delta.fillna(0.0)
    df["_rate_src_interval_std"] = std_delta.fillna(0.0)

    # -- per-window statistics (bin by time) ----------------------------------
    has_time = secs.notna()
    if has_time.any():
        window_id = (secs // window_s).astype("Int64")
        wg = df.assign(_win=window_id, _src=src, _http=is_http.astype(int))
        win = wg[has_time].groupby("_win")
        win_pkt = win["_win"].transform("count")
        win_src = win["_src"].transform("nunique")
        win_http = win["_http"].transform("mean")
        df.loc[has_time, "_rate_win_pkt_count"] = win_pkt.values
        df.loc[has_time, "_rate_win_src_count"] = win_src.values
        df.loc[has_time, "_rate_win_http_frac"] = win_http.values

    for col in ("_rate_win_pkt_count", "_rate_win_src_count", "_rate_win_http_frac"):
        if col not in df.columns:
            df[col] = 0.0
    df[["_rate_win_pkt_count", "_rate_win_src_count", "_rate_win_http_frac"]] = (
        df[["_rate_win_pkt_count", "_rate_win_src_count", "_rate_win_http_frac"]]
        .fillna(0.0).astype(float))

    return df
