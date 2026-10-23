"""
factors.py - turns an alert into the four numbers the score needs.

  severity   S  how damaging is this attack type?            (config.SEVERITY: CAPEC rating or survey-2 median)
  confidence C  how sure is the detector?                    (calibrated probability, see calibrate.py)
  asset      A  how important is the target device?          (config.ASSETS + ROLE_CRITICALITY)
  frequency  F  how often was it repeated on this target?    (count in the last 60 s, log scale)
"""
import bisect
import math
from collections import defaultdict

import numpy as np
import pandas as pd

from .config import (ASSETS, FALLBACK_ASSET_ID, ROLE_CRITICALITY, SEVERITY, WINDOW_CAP, WINDOW_SECONDS)


# ---- Severity ---------------------------------------------------------------------------------------
def severity_table():
    """attack type -> severity (1-5). The numbers are in config.SEVERITY, each with its evidence in a comment."""
    return {name: float(value) for name, value in SEVERITY.items()}


def get_severity(attack_type):
    if attack_type not in SEVERITY:
        raise ValueError(f"Unknown attack type: {attack_type!r}")
    return float(SEVERITY[attack_type])


# ---- Asset ------------------------------------------------------------------------------------------
def registry():
    """Return (ip -> asset_id, asset_id -> {name, criticality}) from config.ASSETS and config.ROLE_CRITICALITY."""
    by_id = {aid: {"name": a["name"], "criticality": float(ROLE_CRITICALITY[a["role"]])} for aid, a in ASSETS.items()}
    by_ip = {a["ip"]: aid for aid, a in ASSETS.items() if a["ip"]}
    return by_ip, by_id


def get_asset(target_ip):
    """Look the target IP up. An unknown IP gets the fallback asset and is flagged as such."""
    by_ip, by_id = registry()
    asset_id = by_ip.get(str(target_ip), FALLBACK_ASSET_ID)
    info = by_id[asset_id]
    status = "fallback (destination not in registry)" if asset_id == FALLBACK_ASSET_ID else "mapped from registry IP"
    return asset_id, info["name"], info["criticality"], status


# ---- Frequency --------------------------------------------------------------------------------------
def log_frequency(count, cap=WINDOW_CAP):
    """Count -> 1..5 on a log scale: 1 alert = 1.0, `cap` or more = 5.0.
    (Log scale: one huge burst cannot squash everything else.)"""
    return round(1 + 4 * min(math.log10(max(count, 1)) / math.log10(cap), 1.0), 2)


def window_counts(alerts, seconds=WINDOW_SECONDS):
    """BATCH. For every alert: how many alerts of the SAME attack type hit the SAME target in the
    previous `seconds` (including itself). Alerts without a timestamp get NaN (see capture_counts)."""
    counts = pd.Series(np.nan, index=alerts.index)
    timed = alerts[alerts["event_time"].notna()]
    for _, group in timed.groupby(["dst_ip", "predicted_type"]):
        t = np.sort(group["event_time"].to_numpy())
        in_window = np.searchsorted(t, group["event_time"].to_numpy(), side="right") - \
            np.searchsorted(t, group["event_time"].to_numpy() - seconds, side="left")
        counts.loc[group.index] = in_window
    return counts


def capture_counts(alerts):
    """FALLBACK for alerts with no timestamp (DDoS_UDP and MITM): the number of alerts of the same attack type
    on the same target in the whole capture. The output marks these rows so nobody mistakes them for windows."""
    return alerts.groupby(["dst_ip", "predicted_type"])["flow_id"].transform("size")


class WindowCounter:
    """LIVE. Same count as window_counts(), but alert by alert as they arrive."""

    def __init__(self, seconds=WINDOW_SECONDS):
        self.seconds = seconds
        self.times = defaultdict(list)           # (target, attack type) -> sorted event times

    def add(self, target_ip, attack_type, event_time):
        times = self.times[(str(target_ip), attack_type)]
        bisect.insort(times, event_time)
        return bisect.bisect_right(times, event_time) - bisect.bisect_left(times, event_time - self.seconds)

    def reset(self):
        self.times.clear()
