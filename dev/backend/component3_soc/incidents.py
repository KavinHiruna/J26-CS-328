"""
incidents.py - group the scored alerts into INCIDENTS for Component 4 (forensics).

An incident is a group of related alerts, not one flow. GROUPING RULE (our design choice, not a published standard):
  - same src_ip, same dst_ip and same predicted_type, AND
  - each alert at most WINDOW_SECONDS after the previous alert of that group; a larger gap starts a new incident.
    (The same 60 s window as the frequency factor: 97.4% of gaps between such alerts are <= 60 s,
     see analysis/window_evidence.py.)
  - alerts without event_time (DDoS_UDP and MITM) cannot be ordered in time, so they form ONE capture-wide group
    per src_ip, dst_ip, predicted_type, marked "time_basis": "no timestamp (capture-wide group)".

The incident's risk_score, priority, reason and recommendations are those of the HIGHEST-scoring alert in the group
(the worst alert decides how urgent the incident is; ties go to the lowest flow_id so the result is fixed).
"""
import pandas as pd

from . import soc_logic
from .config import WINDOW_SECONDS

GROUP_KEYS = ["src_ip", "dst_ip", "predicted_type"]
TIMED_BASIS = "timestamps"
UNTIMED_BASIS = "no timestamp (capture-wide group)"

# columns of the highest-scoring alert that the incident takes over (all from the scored queue)
TOP_ALERT_COLUMNS = ["asset_id", "asset_status", "risk_score", "priority", "attack_severity", "detection_confidence",
                     "asset_criticality", "attack_frequency", "recommendations"]


def group_alerts(queue, alerts):
    """Scored queue + Component 1's alert table -> one row per incident (pure function, no file access).
    event_time is not in the scored queue, so it is taken from `alerts` by flow_id."""
    data = queue.merge(alerts[["flow_id", "event_time"]], on="flow_id", how="left")
    data[["src_ip", "dst_ip"]] = data[["src_ip", "dst_ip"]].astype(str)

    # timed alerts: walk each src/dst/type group in time order; a new incident starts at a new group or a big gap
    timed = data[data["event_time"].notna()].sort_values(GROUP_KEYS + ["event_time", "flow_id"])
    new_group = (timed[GROUP_KEYS] != timed[GROUP_KEYS].shift()).any(axis=1)
    big_gap = timed["event_time"].diff() > WINDOW_SECONDS
    timed = timed.assign(group=(new_group | big_gap).cumsum())

    # untimed alerts: one capture-wide group per src/dst/type, numbered after the timed groups
    untimed = data[data["event_time"].isna()].sort_values(GROUP_KEYS + ["flow_id"])
    last_timed = int(timed["group"].max()) if len(timed) else 0
    untimed = untimed.assign(group=untimed.groupby(GROUP_KEYS, sort=True).ngroup() + last_timed + 1)
    data = pd.concat([timed, untimed])

    by_group = data.groupby("group", sort=False)
    incidents = by_group[GROUP_KEYS].first()
    incidents["start"] = by_group["event_time"].min()                    # NaN for untimed groups
    incidents["end"] = by_group["event_time"].max()
    incidents["alert_count"] = by_group.size()
    incidents["alert_ids"] = by_group["alert_id"].agg(list)              # in time order (flow_id order if untimed)

    # the highest-scoring alert of each group (ties: lowest flow_id)
    ranked = data.sort_values(["risk_score", "flow_id"], ascending=[False, True])
    top = ranked.groupby("group").head(1).set_index("group")
    incidents["top_alert_id"] = top["alert_id"]
    incidents[TOP_ALERT_COLUMNS] = top[TOP_ALERT_COLUMNS]

    # fixed order -> fixed IDs: timed by first event_time, then src_ip, dst_ip, type; untimed groups last
    incidents["untimed"] = incidents["start"].isna()
    incidents = incidents.sort_values(["untimed", "start"] + GROUP_KEYS, na_position="last").reset_index(drop=True)
    incidents.insert(0, "incident_id", [f"INC-{n:06d}" for n in range(1, len(incidents) + 1)])
    return incidents


def build_incident(group_row):
    """One row of group_alerts() -> the incident dict Component 4 reads (pure function, no file access)."""
    untimed = pd.isna(group_row["start"])
    steps = group_row["recommendations"]
    if isinstance(steps, str):                                           # the CSV stores the steps joined by " | "
        steps = steps.split(" | ")
    return {
        "incident_id": str(group_row["incident_id"]),
        "seed_ip": str(group_row["src_ip"]),
        "time_window": None if untimed else {"start": float(group_row["start"]), "end": float(group_row["end"])},
        "time_basis": UNTIMED_BASIS if untimed else TIMED_BASIS,
        "flagged_assets": [{"ip": str(group_row["dst_ip"]), "asset_id": str(group_row["asset_id"]),
                            "asset_status": str(group_row["asset_status"])}],
        "attack_type": str(group_row["predicted_type"]),
        "alert_count": int(group_row["alert_count"]),
        "alert_ids": [str(a) for a in group_row["alert_ids"]],
        "priority": str(group_row["priority"]),                         # of the highest-scoring alert
        "risk_score": float(group_row["risk_score"]),                   # of the highest-scoring alert
        "reason": {name: float(points) for name, points in soc_logic.why(group_row).items()},
        "recommendations": list(steps),
    }
