"""
window_evidence.py - EVIDENCE for the frequency window (60 s) and the cap (500).

For every attack type against every target it measures the gaps between consecutive alerts, then how many alerts
each candidate window (10 s, 60 s, 300 s) would count, and how many priority levels would change.
Run (from the dev folder):  python -m backend.component3_soc.analysis.window_evidence
"""
import numpy as np
import pandas as pd

from .. import factors, pipeline, scoring
from ..config import NOT_AN_ALERT, REPORT_DIR, WINDOW_CAP, WINDOW_SECONDS


def main():
    raw = pipeline.load_alerts()
    alerts = raw[(raw["predicted_type"] != NOT_AN_ALERT) & raw["event_time"].notna()].sort_values("event_time", kind="stable")
    gaps = alerts.groupby(["dst_ip", "predicted_type"])["event_time"].diff().dropna()
    lines = ["GAPS between consecutive alerts of the same attack type against the same target (seconds)",
             f"  alerts with a timestamp: {len(alerts):,}   gaps measured: {len(gaps):,}",
             f"  median {gaps.median():.3f}   90th pct {gaps.quantile(.9):.3f}   99th pct {gaps.quantile(.99):.3f}   max {gaps.max():.1f}"]
    for seconds in (1, 10, 60, 300):
        lines.append(f"  share of gaps <= {seconds:>3} s: {(gaps <= seconds).mean() * 100:5.1f}%")

    _, queue = pipeline.run(save=False)
    queue = queue.set_index("flow_id")
    levels = {}
    lines += ["", "COUNT per window, and effect on the priority level"]
    for seconds in (10, 60, 300):
        counts = factors.window_counts(alerts, seconds=seconds)
        lines.append(f"  window {seconds:>3} s: median count {counts.median():6.1f}  99th pct {counts.quantile(.99):7.1f}  max {counts.max():6.0f}")
        freq = queue["attack_frequency"].copy()
        timed = pd.Series(counts.to_numpy(), index=alerts["flow_id"].to_numpy()).map(factors.log_frequency)
        freq.loc[timed.index.intersection(freq.index)] = timed
        score = [scoring.risk_score(s, c, a, f) for s, c, a, f in
                 zip(queue.attack_severity, queue.detection_confidence, queue.asset_criticality, freq)]
        levels[seconds] = pd.Series([scoring.priority_level(x) for x in score], index=queue.index)
        if seconds == WINDOW_SECONDS:
            counts_60 = counts
    lines += ["", f"CAP check: 99th percentile of the {WINDOW_SECONDS} s counts = {counts_60.quantile(.99):.0f}; cap used = {WINDOW_CAP}"]
    for seconds in (10, 300):
        lines.append(f"  priority level differs between {WINDOW_SECONDS} s and {seconds} s windows for "
                     f"{(levels[seconds] != levels[WINDOW_SECONDS]).mean() * 100:.1f}% of alerts")
    text = "\n".join(lines)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "window_evidence.txt").write_text(text, encoding="utf-8")
    print(text)
    return {"ok": True, "share_le_60": float((gaps <= 60).mean()), "p99_count": float(counts_60.quantile(.99))}


if __name__ == "__main__":
    main()
