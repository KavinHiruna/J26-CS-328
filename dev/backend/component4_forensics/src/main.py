"""
Energy Plant IIoT Forensic Investigation Framework - Prototype (Week 4)

Usage:
    python main.py                       run the default scenario
    python main.py scenario2_vpn_lateral_ems
    python main.py all                   run every scenario

Pipeline (triggered by the confirmed-incident file from Component 3):
    1-2  load + scope + normalise IT/OT evidence, hash source files (chain of custody)
    3    incident-seeded IT-OT correlation
    4    attack timeline reconstruction
    5    root cause analysis
    6-7  evidence data export + forensic report generation
"""

import hashlib
import json
import os
import sys
from datetime import datetime

from pipeline import SCENARIOS, OUTPUT_DIR, load_scenario, run_improved
from report_generator import generate_report
from timeline_rca import canonical_stage


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_scenario(name):
    print(f"\n=== {name} ===")
    incident, scoped, _, paths = load_scenario(name)

    print("[Stage 1-2] Collecting, scoping and normalising evidence (IT + OT)...")
    manifest = {
        "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files": {fname: sha256_file(p) for fname, p in paths.items()},
    }
    print(f"  -> incident {incident['incident_id']}, window {incident['window_start']} .. {incident['window_end']}")
    print(f"  -> {len(scoped)} evidence records in scope; {len(manifest['files'])} source files hashed")

    print("[Stage 3-5] Correlating, reconstructing timeline, analysing root cause...")
    result = run_improved(scoped, incident["seed_ips"])
    clusters, timeline, rca = result["clusters"], result["timeline"], result["rca"]
    relevant = sum(len(c.records) for c in clusters)
    print(f"  -> {len(clusters)} cluster(s); {relevant} relevant records; {len(scoped) - relevant} excluded as routine")
    print(f"  -> {len(timeline)} timeline events")
    print(f"  -> origin: {rca.origin_type} ({rca.entry_point_ip}); initial vector: {rca.initial_vector}")
    print(f"  -> compromised: {rca.compromised_energy_assets}")

    out_dir = os.path.join(OUTPUT_DIR, name)
    os.makedirs(out_dir, exist_ok=True)

    print("[Stage 6] Creating evidence visualizations...")
    figures = {}
    try:
        from visualize import generate_all
        figures = generate_all(out_dir, incident, timeline, rca, scoped)
        print(f"  -> {', '.join(figures.values())}, dashboard.html")
    except ImportError:
        print("  -> skipped: matplotlib / networkx not installed. Run:  pip install matplotlib networkx")

    print("[Stage 7] Generating forensic report...")
    report = generate_report(scoped, clusters, timeline, rca, incident, manifest, figures)
    md_path = os.path.join(out_dir, "forensic_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report)
    from report_html import write_html_report
    stage_order = []
    for t in timeline:
        st = canonical_stage(t.stage)
        if st != "Network Connection" and (not stage_order or stage_order[-1] != st):
            stage_order.append(st)
    times = [t.timestamp for t in timeline]
    fmt = "%H:%M:%S"
    secs = (datetime.strptime(times[-1], fmt) - datetime.strptime(times[0], fmt)).seconds if times else 0
    meta = {
        "priority": incident.get("priority"), "origin": rca.origin_type.capitalize(),
        "window": f"{incident['window_start']} to {incident['window_end']}",
        "collected": len(scoped), "relevant": relevant, "excluded": len(scoped) - relevant,
        "n_stages": len(stage_order), "duration": f"{secs // 60} min {secs % 60} s",
        "entry_ip": rca.entry_point_ip, "vector": rca.initial_vector,
        "compromised": f"{len(rca.compromised_energy_assets)}", "stage_order": stage_order,
    }
    html_path = write_html_report(md_path, meta)
    print(f"  -> {os.path.basename(html_path)} (single file, charts embedded)")
    with open(os.path.join(out_dir, "timeline.json"), "w", encoding="utf-8") as f:
        json.dump([t.__dict__ for t in timeline], f, indent=2)
    with open(os.path.join(out_dir, "evidence_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"  -> written to {out_dir}")


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else SCENARIOS[0]
    names = SCENARIOS if arg == "all" else [arg]
    for n in names:
        run_scenario(n)
    print("\nDone.")


if __name__ == "__main__":
    main()
