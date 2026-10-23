"""
survey2_values.py - EVIDENCE for the severity and asset values that have no published source.

Survey 2 asked respondents to rate (1 to 5) the impact of SQL injection, Backdoor and Ransomware if they succeed,
and how much the plant would suffer if each kind of device were unavailable. The MEDIAN is used (the answers are
ordinal ratings, so a mean would treat 4 versus 5 as equal-sized steps); n and the inter-quartile range are shown.

Run (from the dev folder):  python -m backend.component3_soc.analysis.survey2_values
It recomputes the medians and checks that data/evidence/*.csv (what the pipeline reads) contain the same numbers.
"""
import pandas as pd

from ..config import ASSET_EVIDENCE_FILE, REPORT_DIR, SEVERITY_FILE, SURVEY2_FILE

SEVERITY_ITEMS = {"SQL_injection": ["sql"], "Backdoor": ["backdoor"], "Ransomware": ["ransomware"]}
ASSET_ITEMS = {"control_endpoint": ["control endpoint"], "sensor_client": ["sensor"], "unregistered": ["not in the inventory"]}


def ratings(df, keywords):
    """The 1-5 answers of the single survey column whose title contains one of the keywords."""
    columns = [c for c in df.columns if any(k in c.lower() for k in keywords)]
    if len(columns) != 1:
        raise ValueError(f"expected exactly one column for {keywords}, found {columns}")
    return pd.to_numeric(df[columns[0]].astype(str).str.extract(r"([1-5])")[0], errors="coerce").dropna()


def summary(values):
    return {"median": float(values.median()), "n": len(values), "q1": float(values.quantile(.25)), "q3": float(values.quantile(.75))}


def main():
    df = pd.read_csv(SURVEY2_FILE)
    severity = pd.read_csv(SEVERITY_FILE).set_index("attack_type")
    assets = pd.read_csv(ASSET_EVIDENCE_FILE).set_index("role_key")
    lines = [f"SURVEY 2: {len(df)} respondents (years of experience given by {df.iloc[:, -1].notna().sum()}; "
             "mostly junior practitioners and students)", "",
             f"{'item':<18}{'median':>7}{'n':>4}{'IQR':>10}   used by the pipeline"]
    all_match = True
    for table, items, used_col in [(severity, SEVERITY_ITEMS, "severity_used"), (assets, ASSET_ITEMS, "criticality_used")]:
        for name, keywords in items.items():
            s = summary(ratings(df, keywords))
            used = float(table.loc[name, used_col])
            match = abs(used - s["median"]) < 1e-9
            all_match &= match
            lines.append(f"{name:<18}{s['median']:>7g}{s['n']:>4}{s['q1']:>6g}-{s['q3']:<4g}   {used:g}  {'OK' if match else 'DIFFERENT'}")
    lines += ["", "ALL MATCH" if all_match else "MISMATCH: update data/evidence/*.csv"]
    text = "\n".join(lines)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "survey2_values.txt").write_text(text, encoding="utf-8")
    print(text)
    return {"ok": all_match}


if __name__ == "__main__":
    main()
