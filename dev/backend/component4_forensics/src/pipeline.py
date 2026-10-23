"""
Shared pipeline runners.

    run_baseline  - the Week-1 prototype logic (naive shared-IP correlation,
                    keyword stage classifier, first-event RCA).
    run_improved  - Week-2 logic (incident-seeded correlation, source-aware
                    stage classification, origin-aware RCA).
"""

import json
import os

from log_loader import load_all_evidence, scope_evidence
from correlator import correlate_evidence, correlate_seeded
from timeline_rca import (build_timeline, classify_stage, classify_stage_legacy,
                          perform_rca, perform_rca_legacy)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
OUTPUT_DIR = os.path.join(ROOT, "output")

SCENARIOS = [
    "scenario1_rdp_to_breaker",
    "scenario2_vpn_lateral_ems",
    "scenario3_insider_modbus",
    "scenario4_c2_beacon_dnp3",
]


def load_scenario(name):
    """Load one scenario: returns (incident, scoped_evidence, ground_truth, file_paths)."""
    folder = os.path.join(DATA_DIR, name)
    paths = {
        "firewall.log": os.path.join(folder, "firewall.log"),
        "ids_alerts.log": os.path.join(folder, "ids_alerts.log"),
        "device.log": os.path.join(folder, "device.log"),
        "incident.json": os.path.join(folder, "incident.json"),
    }
    evidence = load_all_evidence(paths["firewall.log"], paths["ids_alerts.log"], paths["device.log"])
    with open(paths["incident.json"]) as f:
        incident = json.load(f)
    truth_path = os.path.join(folder, "ground_truth.json")
    truth = None
    if os.path.exists(truth_path):
        with open(truth_path) as f:
            truth = json.load(f)
    scoped = scope_evidence(evidence, incident["window_start"], incident["window_end"])
    return incident, scoped, truth, paths


def run_baseline(scoped, window_minutes=5):
    clusters = correlate_evidence(scoped, time_window_minutes=window_minutes)
    timeline = build_timeline(clusters, classifier=classify_stage_legacy)
    rca = perform_rca_legacy(timeline, scoped)
    return {"clusters": clusters, "timeline": timeline, "rca": rca}


def run_improved(scoped, seed_ips, window_minutes=5):
    clusters = correlate_seeded(scoped, seed_ips, time_window_minutes=window_minutes)
    timeline = build_timeline(clusters, classifier=classify_stage)
    rca = perform_rca(timeline, scoped, seed_ips)
    return {"clusters": clusters, "timeline": timeline, "rca": rca}
