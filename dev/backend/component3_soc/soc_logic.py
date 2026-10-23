"""
soc_logic.py - the small functions the Streamlit page uses. All the thinking is here (and in scoring.py),
so the page only displays things. Easy to test without opening a browser.
"""
import pandas as pd

from . import factors, scoring
from .config import LEVELS, SCORED_FILE


def load_queue():
    """The scored alert queue written by pipeline.py."""
    if not SCORED_FILE.exists():
        raise FileNotFoundError("No scored alerts yet. From the dev folder run:  python -m backend.component3_soc.pipeline")
    return pd.read_csv(SCORED_FILE)


def level_counts(queue):
    counts = queue["priority"].value_counts()
    return pd.DataFrame({"alerts": [int(counts.get(level, 0)) for level in LEVELS]}, index=LEVELS)


def why(row):
    """Points each factor contributed to this alert's score (a Series, in score points)."""
    parts = scoring.contributions(row["attack_severity"], row["detection_confidence"],
                                  row["asset_criticality"], row["attack_frequency"])
    return pd.Series(parts).round(2)


def what_if(attack_type, confidence, target_ip, repeats_in_window):
    """Score a made-up alert: the same steps the pipeline uses, one alert at a time."""
    severity = factors.get_severity(attack_type)
    asset_id, asset_name, asset, status = factors.get_asset(target_ip)
    frequency = factors.log_frequency(repeats_in_window)
    score = scoring.risk_score(severity, confidence, asset, frequency)
    level = scoring.priority_level(score)
    return {"severity": severity, "asset_id": asset_id, "asset_name": asset_name, "asset_status": status,
            "asset": asset, "frequency": frequency, "score": score, "level": level,
            "points": scoring.contributions(severity, confidence, asset, frequency),
            "advice": scoring.recommend(level, attack_type)}
