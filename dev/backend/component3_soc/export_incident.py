"""
export_incident.py - write one incident.json per INCIDENT (a group of related alerts) for Component 4 (forensics).
The grouping rule is in incidents.py.

Run from the dev folder:
    python -m backend.component3_soc.export_incident --summary                     (counts per priority)
    python -m backend.component3_soc.export_incident --incident INC-000123 [--out folder]
    python -m backend.component3_soc.export_incident --top 20 [--priority Critical] [--out folder]
Default folder: outputs/incidents/ inside this component folder (config.OUTPUT_DIR; one <incident_id>.json per incident)
"""
import argparse
import json
import sys
from pathlib import Path

from . import pipeline, soc_logic
from .config import LEVELS, OUTPUT_DIR
from .incidents import build_incident, group_alerts

INCIDENT_DIR = OUTPUT_DIR / "incidents"


def load_incidents():
    """Group the scored queue (soc_logic.load_queue: asks to run the pipeline first if missing) into incidents."""
    return group_alerts(soc_logic.load_queue(), pipeline.load_alerts())


def write_incident(incident, folder=INCIDENT_DIR):
    """Save one incident as <folder>/<incident_id>.json and return the path."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{incident['incident_id']}.json"
    path.write_text(json.dumps(incident, indent=2), encoding="utf-8")
    return path


def summary(incidents):
    """Incidents per priority level, and how many are timed or capture-wide."""
    counts = incidents["priority"].value_counts()
    untimed = int(incidents["untimed"].sum())
    lines = [f"{len(incidents):,} incidents from {int(incidents['alert_count'].sum()):,} alerts "
             f"({len(incidents) - untimed:,} timed, {untimed:,} untimed capture-wide groups)", "Incidents per priority:"]
    lines += [f"  {level:<9}{int(counts.get(level, 0)):>7,}" for level in LEVELS]
    return "\n".join(lines)


def select(incidents, incident_id=None, top=None, priority=None):
    """Pick one incident by id, or the `top` highest-risk incidents (optionally of one priority level)."""
    if incident_id:
        chosen = incidents[incidents["incident_id"] == incident_id]
        if chosen.empty:
            raise ValueError(f"Unknown incident: {incident_id}")
        return chosen
    if priority:
        incidents = incidents[incidents["priority"] == priority]
    ranked = incidents.sort_values(["risk_score", "incident_id"], ascending=[False, True])   # highest risk first
    return ranked.head(top) if top else ranked


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export incidents (groups of alerts) as JSON for Component 4.")
    parser.add_argument("--summary", action="store_true", help="print incident counts per priority")
    parser.add_argument("--incident", help="one incident id, e.g. INC-000123")
    parser.add_argument("--top", type=int, help="export the N highest-risk incidents")
    parser.add_argument("--priority", choices=LEVELS, help="only incidents of this level (with --top, or all of them)")
    parser.add_argument("--out", type=Path, default=INCIDENT_DIR, help="output folder")
    args = parser.parse_args(argv)
    if not (args.summary or args.incident or args.top or args.priority):
        parser.error("give --summary, --incident, --top or --priority")

    try:
        incidents = load_incidents()
        if args.summary:
            print(summary(incidents))
            if not (args.incident or args.top or args.priority):
                return 0
        rows = select(incidents, args.incident, args.top, args.priority)
    except (FileNotFoundError, ValueError) as error:                 # no scored queue yet, or an unknown incident id
        print(error)
        return 1
    for _, row in rows.iterrows():
        write_incident(build_incident(row), args.out)
    print(f"Wrote {len(rows):,} incident file(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
