"""
Build sql_injection_rf.pkl and sql_feature_columns.pkl for the SQL Injection XAI dashboard.

WHAT THIS MODEL IS (read before citing it):
  * A Random Forest stand-in/baseline SQL-injection detector, trained so the dashboard's
    SHAP/LIME panels have a real fitted model to explain. It is NOT Student 1's IDS model.
  * Labels: EdgeIIoT_train_80 has only a binary Attack_label (no Attack_type). A request is
    labelled SQL injection (1) when Attack_label == 1 AND its http.request.full_uri targets
    DVWA's SQL-injection endpoint (/vulnerabilities/sqli or /vulnerabilities/sqli_blind) —
    i.e. the sqlmap campaign in the Edge-IIoT capture. Everything else is 0.
    The URL path itself is NOT one of the 54 model features, so labels are not a copy of the
    feature rules.
  * Features: the 54-column schema built by _build_sqli_features() in
    sql_injection_xai_dashboard_shap_lime_updated.py, reproduced line for line below so that
    training-time and dashboard-time features are identical.

Usage (re-run locally if your scikit-learn version differs from the one that built the pickles):
    python train_sql_injection_rf.py --data data/EdgeIIoT_train_80_with_incident_id.csv --out models
"""
from __future__ import annotations

import argparse
import json
import pickle
import re
from pathlib import Path
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

# ---- Copied from the dashboard (must stay identical) -----------------------------------
TEXT_COLUMNS = [
    "http.request.uri.query", "http.request.full_uri", "http.request.uri",
    "http.referer", "http.file_data", "http.request.method",
    "http.host", "url", "query", "payload", "raw_http_request", "http.request",
]
DEFAULT_SQL_FEATURES = [
    "query_length", "query_parameter_count", "uri_length", "http_get",
    "single_quote_count", "double_quote_count", "semicolon_count",
    "comment_count", "parenthesis_count", "equals_count", "sql_select",
    "sql_union", "sql_insert", "sql_update", "sql_delete", "sql_drop",
    "sql_alter", "sql_create", "sql_from", "sql_where", "sql_having",
    "sql_group_by", "sql_order_by", "sql_sleep", "sql_benchmark",
    "sql_pg_sleep", "sql_extractvalue", "sql_updatexml", "sql_cast",
    "sql_convert", "sql_concat", "sql_substring", "sql_database",
    "sql_schema", "sql_information_schema", "or_condition", "and_condition",
    "union_select", "percent_encoded_count", "hex_pattern_count",
    "sleep_function", "database_function", "extractvalue_function",
    "xml_function", "tcp.len", "tcp.dstport", "tcp.srcport",
    "tcp.flags.ack", "tcp.connection.syn", "tcp.connection.synack",
    "tcp.connection.fin", "tcp.connection.rst", "http.content_length",
    "tcp_payload_length",
]


def norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def find_col(df: pd.DataFrame, names: list[str]) -> str | None:
    lookup = {norm(c): c for c in df.columns}
    for name in names:
        if norm(name) in lookup:
            return lookup[norm(name)]
    return None


def usable(value: object) -> bool:
    if value is None or pd.isna(value):
        return False
    return str(value).strip().lower() not in {"", "nan", "none", "null"}


def make_builder(df: pd.DataFrame):
    """Return the dashboard's _build_sqli_features bound to this DataFrame's columns."""

    def _feature_text(selected_row):
        chunks = []
        for candidate in TEXT_COLUMNS:
            actual_col = find_col(df, [candidate])
            if actual_col and usable(selected_row.get(actual_col)):
                chunks.append(str(selected_row[actual_col]))
        return unquote_plus(" ".join(chunks)).lower()

    def _num(selected_row, names, default=0.0):
        col = find_col(df, names)
        if not col or not usable(selected_row.get(col)):
            return float(default)
        try:
            return float(selected_row[col])
        except (TypeError, ValueError):
            return float(default)

    def _payload_bytes(selected_row):
        """Byte length of the hex tcp.payload; falls back to tcp.len when the cell is not clean hex
        (e.g. '0' or spreadsheet-mangled values such as '5.86E+239')."""
        col = find_col(df, ["tcp.payload"])
        value = str(selected_row.get(col, "")).strip() if col else ""
        if len(value) > 1 and re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
            return float(len(value) // 2)
        return _num(selected_row, ["tcp.len"])

    uri_col = find_col(df, ["http.request.uri", "http.request.full_uri", "http.request.uri.query"])
    query_col = find_col(df, ["http.request.uri.query"])
    method_col = find_col(df, ["http.request.method"])

    def build(selected_row, feature_names):
        raw_text = _feature_text(selected_row)
        decoded = unquote_plus(raw_text)
        lower = decoded.lower()
        uri = str(selected_row.get(uri_col, "")) if uri_col else ""
        query = str(selected_row.get(query_col, "")) if query_col and usable(selected_row.get(query_col)) else uri
        method = str(selected_row.get(method_col, "")).strip().upper() if method_col else ""
        vals = {
            "query_length": len(query),
            "query_parameter_count": query.count("&") + (1 if query and "=" in query else 0),
            "uri_length": len(uri),
            "http_get": int(method == "GET"),
            "single_quote_count": decoded.count("'") + decoded.lower().count("%27"),
            "double_quote_count": decoded.count('"') + decoded.lower().count("%22"),
            "semicolon_count": decoded.count(";"),
            "comment_count": len(re.findall(r"--|/\*|\*/|#", decoded)),
            "parenthesis_count": decoded.count("(") + decoded.count(")"),
            "equals_count": decoded.count("="),
            "sql_select": int(bool(re.search(r"\bselect\b", lower))),
            "sql_union": int(bool(re.search(r"\bunion\b", lower))),
            "sql_insert": int(bool(re.search(r"\binsert\b", lower))),
            "sql_update": int(bool(re.search(r"\bupdate\b", lower))),
            "sql_delete": int(bool(re.search(r"\bdelete\b", lower))),
            "sql_drop": int(bool(re.search(r"\bdrop\b", lower))),
            "sql_alter": int(bool(re.search(r"\balter\b", lower))),
            "sql_create": int(bool(re.search(r"\bcreate\b", lower))),
            "sql_from": int(bool(re.search(r"\bfrom\b", lower))),
            "sql_where": int(bool(re.search(r"\bwhere\b", lower))),
            "sql_having": int(bool(re.search(r"\bhaving\b", lower))),
            "sql_group_by": int(bool(re.search(r"\bgroup\s+by\b", lower))),
            "sql_order_by": int(bool(re.search(r"\border\s+by\b", lower))),
            "sql_sleep": int(bool(re.search(r"\bsleep\s*\(", lower))),
            "sql_benchmark": int(bool(re.search(r"\bbenchmark\s*\(", lower))),
            "sql_pg_sleep": int(bool(re.search(r"\bpg_sleep\s*\(", lower))),
            "sql_extractvalue": int(bool(re.search(r"\bextractvalue\s*\(", lower))),
            "sql_updatexml": int(bool(re.search(r"\bupdatexml\s*\(", lower))),
            "sql_cast": int(bool(re.search(r"\bcast\s*\(", lower))),
            "sql_convert": int(bool(re.search(r"\bconvert\s*\(", lower))),
            "sql_concat": int(bool(re.search(r"\bconcat\s*\(", lower))),
            "sql_substring": int(bool(re.search(r"\bsubstring\s*\(", lower))),
            "sql_database": int(bool(re.search(r"\bdatabase\s*\(", lower))),
            "sql_schema": int(bool(re.search(r"\bschema\s*\(", lower))),
            "sql_information_schema": int("information_schema" in lower),
            "or_condition": int(bool(re.search(r"\bor\b", lower))),
            "and_condition": int(bool(re.search(r"\band\b", lower))),
            "union_select": int(bool(re.search(r"\bunion\b.*\bselect\b", lower, re.S))),
            "percent_encoded_count": len(re.findall(r"%[0-9a-fA-F]{2}", raw_text)),
            "hex_pattern_count": len(re.findall(r"\b0x[0-9a-fA-F]+\b", lower)),
            "sleep_function": int(bool(re.search(r"\b(?:sleep|pg_sleep|benchmark)\s*\(", lower))),
            "database_function": int(bool(re.search(r"\b(?:database|schema|user|version)\s*\(", lower))),
            "extractvalue_function": int(bool(re.search(r"\bextractvalue\s*\(", lower))),
            "xml_function": int(bool(re.search(r"\b(?:updatexml|extractvalue|xmltype)\s*\(", lower))),
            "tcp.len": _num(selected_row, ["tcp.len"]),
            "tcp.dstport": _num(selected_row, ["tcp.dstport"]),
            "tcp.srcport": _num(selected_row, ["tcp.srcport"]),
            "tcp.flags.ack": _num(selected_row, ["tcp.flags.ack"]),
            "tcp.connection.syn": _num(selected_row, ["tcp.connection.syn"]),
            "tcp.connection.synack": _num(selected_row, ["tcp.connection.synack"]),
            "tcp.connection.fin": _num(selected_row, ["tcp.connection.fin"]),
            "tcp.connection.rst": _num(selected_row, ["tcp.connection.rst"]),
            "http.content_length": _num(selected_row, ["http.content_length"]),
            "tcp_payload_length": _payload_bytes(selected_row),
        }
        return [vals.get(name, 0.0) for name in feature_names]

    return build
# ---------------------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/EdgeIIoT_train_80_with_incident_id.csv")
    ap.add_argument("--out", default="models")
    args = ap.parse_args()

    df = pd.read_csv(args.data, low_memory=False)
    print(f"Loaded {len(df):,} rows")

    full_uri = df["http.request.full_uri"].astype(str)
    y = ((df["Attack_label"] == 1) & full_uri.str.contains(r"/vulnerabilities/sqli", case=False, regex=True)).astype(int)
    print(f"SQLi-labelled requests: {int(y.sum()):,}  /  other: {int((y == 0).sum()):,}")

    build = make_builder(df)
    feats = DEFAULT_SQL_FEATURES
    X = pd.DataFrame([build(r, feats) for r in df.to_dict("records")], columns=feats, dtype=float)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    model = RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_leaf=2,
        class_weight="balanced", n_jobs=-1, random_state=42,
    )
    model.fit(X_tr, y_tr)

    proba = model.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    report = classification_report(y_te, pred, target_names=["Not SQLi", "SQL Injection"], digits=4, output_dict=True)
    print(classification_report(y_te, pred, target_names=["Not SQLi", "SQL Injection"], digits=4))
    print("Confusion matrix [[TN FP] [FN TP]]:", confusion_matrix(y_te, pred).tolist())
    print("ROC-AUC:", round(roc_auc_score(y_te, proba), 5))

    # Refit on all rows for the delivered artifact.
    model.fit(X, y)
    model.model_source_ = "Stand-in baseline RF (not Student 1 model)"

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "sql_injection_rf.pkl", "wb") as f:
        pickle.dump(model, f, protocol=4)
    with open(out / "sql_feature_columns.pkl", "wb") as f:
        pickle.dump(list(feats), f, protocol=4)

    imp = sorted(zip(feats, model.feature_importances_), key=lambda t: -t[1])[:10]
    card = {
        "model": "RandomForestClassifier (stand-in baseline, not Student 1's model)",
        "classes": {"0": "Not SQLi", "1": "SQL Injection"},
        "label_rule": "Attack_label == 1 AND http.request.full_uri matches /vulnerabilities/sqli",
        "n_rows": int(len(df)), "n_positive": int(y.sum()), "n_features": len(feats),
        "holdout_20pct": {
            "precision_sqli": round(report["SQL Injection"]["precision"], 4),
            "recall_sqli": round(report["SQL Injection"]["recall"], 4),
            "f1_sqli": round(report["SQL Injection"]["f1-score"], 4),
            "roc_auc": round(float(roc_auc_score(y_te, proba)), 5),
        },
        "top_feature_importances": {k: round(float(v), 4) for k, v in imp},
        "trained_with": {"scikit-learn": sklearn.__version__, "pickle_protocol": 4},
    }
    (out / "sql_model_card.json").write_text(json.dumps(card, indent=2))
    print(json.dumps(card, indent=2))


if __name__ == "__main__":
    main()
