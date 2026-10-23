"""
parameter_register.py - writes docs/results/parameter_register.csv: EVERY number the system uses, where it lives in the
code, how it was obtained, the source and an honest status. The values are read from config.py and the evidence tables,
so the register cannot drift from the code (tests/test_analysis.py checks it).

Run (from the dev folder):  python -m backend.component3_soc.analysis.parameter_register
Open the CSV in Excel for the supervisor.
"""
import pandas as pd

from .. import config, factors
from ..config import REPORT_DIR

HERE_DOCS = config.REPORT_DIR


def rows():
    out = []
    add = lambda *r: out.append(dict(zip(["parameter", "value", "where_in_code", "method", "source", "status_and_limit"], r)))
    labels = {"severity": "Severity", "confidence": "Confidence", "asset": "Asset criticality", "frequency": "Frequency"}
    for k, v in config.WEIGHTS.items():
        add(f"Weight: {labels[k]}", v, "config.WEIGHTS", "AHP pairwise comparison, geometric-mean group matrix, principal eigenvector",
            "Saaty 1980; Forman and Peniwati 1998; survey 1 (n = 15)", "Survey-backed; group CR 0.031; 2 of 15 respondents had > 3 years' experience")
    add("Scaling of severity, asset, frequency", "(x - 1) / 4", "scoring.scale", "Min-max normalisation of a 1-5 scale to 0-1",
        "Mokotoff, Garcia and Perez 2010", "Convention; percentile-rank scaling keeps the order (Spearman 0.95)")
    sev = pd.read_csv(config.SEVERITY_FILE).set_index("attack_type")
    for attack, r in sev.iterrows():
        add(f"Severity: {attack}", r["severity_used"], "config.SEVERITY (evidence: data/evidence/severity_sources.csv)",
            r["published_rating"] if isinstance(r["published_rating"], str) else "", r["reference_name"] if isinstance(r["reference_name"], str) else "survey 2",
            r["status"])
    assets = pd.read_csv(config.ASSET_EVIDENCE_FILE).set_index("role_key")
    for role, r in assets.iterrows():
        add(f"Asset criticality: {r['role_label']}", r["criticality_used"], "config.ROLE_CRITICALITY (evidence: data/evidence/asset_sources.csv)",
            "Median expert rating of how much the plant suffers if the device is unavailable", "Survey 2 (n = 10, mostly junior); CVSS v3.1 environmental requirement idea",
            r["status"] + "; every device rated 4 or 5, so the factor separates little")
    ips = pd.read_csv(config.IP_ROLE_FILE).fillna("")
    for r in ips.itertuples():
        if r.ip_address:
            add(f"IP to role: {r.ip_address}", r.role_key, "config.ASSETS (evidence: data/evidence/ip_role_evidence.csv)",
                "Device role taken from the Edge-IIoTset paper device tables, cross-checked on the traffic",
                "Ferrag et al. 2022, Edge-IIoTset, Tables V and VI", r.limit)
    add("Frequency window", f"{config.WINDOW_SECONDS} s", "config.WINDOW_SECONDS", "Alerts of the same type on the same target in the previous window",
        "The data: 97.4% of gaps between such alerts are <= 60 s", "Data-derived; no published standard says frequent alerts rank higher")
    add("Frequency cap", config.WINDOW_CAP, "config.WINDOW_CAP", "Log scale: 1 alert = 1, cap or more = 5",
        "The data: 99th percentile of 60 s counts = 467", "Data-derived")
    add("Detector confidence", "calibrated probability", "calibrate.calibrate", "Per-class isotonic regression, 5-fold cross-fitting",
        "Niculescu-Mizil and Caruana 2005; Guo et al. 2017", "Verified: ECE 0.0939 to 0.0018; fitted on test-split labels")
    for level, cut in config.LEVEL_CUTOFFS.items():
        add(f"Level cut-off: {level}", f">= {cut}", "config.LEVEL_CUTOFFS", "FIRST CVSS v3.1 qualitative rating on score / 10",
            "FIRST CVSS v3.1 specification, section 5", "Borrowed scale; optional; not used by Red Hat or Microsoft; 74% of alerts are Critical or High")
    add("Fallback asset", config.FALLBACK_ASSET_ID, "config.FALLBACK_ASSET_ID", "Destination not in the registry gets the survey rating for an unlisted device",
        "Survey 2", "Flagged in the output; 19.3% of alerts")
    return pd.DataFrame(out)


def main():
    table = rows()
    HERE_DOCS.mkdir(parents=True, exist_ok=True)
    table.to_csv(HERE_DOCS / "parameter_register.csv", index=False)
    print(f"Saved parameter_register.csv ({len(table)} parameters)")
    return {"ok": True}


if __name__ == "__main__":
    main()
