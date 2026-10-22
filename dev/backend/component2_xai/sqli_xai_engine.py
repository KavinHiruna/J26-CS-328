"""
Component 2 - Evidence-Grounded Hybrid XAI for SQL Injection incidents (EdgeIIoT)
================================================================================

This module is UI-independent: the Streamlit page and the batch evaluation
script both import it. It explains the decision of a trained SQLi / IDS model
for one incident and checks how trustworthy that explanation is.

Novel contributions implemented here
------------------------------------
N1  Payload-Span Shapley (PSS)
    Exact Shapley values over *groups of evidence spans in the real payload*
    (quotes, comments, UNION, time-delay calls, ...). A group is "removed" by
    really sanitising those characters and re-extracting features, so the
    attribution is tied to the request text an analyst reads, not to abstract
    feature columns. Exact because the number of groups is small (<= 12).

N2  Span-grounded attribution map
    PSS values (and SHAP values when the `shap` package is installed) are
    projected back onto the exact characters of the request and rendered as a
    heat-map, so the analyst sees *which characters* drove the decision.

N3  Explanation Trust Score
    Combines (a) agreement between rule-based evidence and PSS, (b) agreement
    between PSS and SHAP / LIME, and (c) deletion fidelity measured against a
    random-deletion baseline. Low trust tells the analyst not to rely on the
    explanation.

N4  Exact minimal sanitisation counterfactual
    Using the PSS coalition table, finds the smallest set of evidence groups
    whose removal flips the decision ("the model would call this benign if
    only X and Y were removed"). If no subset flips it, the decision is driven
    by non-payload (network/size) features - itself an important finding.

N5  SQLi technique profiling and narrative
    Rule-based detection of UNION-based, boolean-blind, time-blind,
    error-based, stacked-query, comment-truncation, enumeration and
    obfuscation techniques, mapped to CWE-89 / CAPEC-66 / CAPEC-7 /
    MITRE ATT&CK T1190, plus an analyst-readable narrative and priority.

Nothing in this module invents model outputs: every probability, Shapley
value, SHAP value and LIME weight comes from the loaded model.

IMPORTANT: the feature builder must match the preprocessing used when the
model was trained. If your training code computed features differently,
pass your own function as `feature_builder=` (see SQLiXAIEngine).

FILE LOCATION : dev/backend/component2_xai/sqli_xai_engine.py
"""
from __future__ import annotations

import html
import itertools
import json
import math
import re
import warnings
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Column handling (EdgeIIoT field names, matched case/punctuation-insensitively)
# ---------------------------------------------------------------------------
ID_COLUMNS = ["Incident ID", "Incident_ID", "incident_id", "incident id"]
TARGET_COLUMNS = ["http.request.full_uri", "http.request.uri", "url",
                  "http.request.uri.query", "query"]
QUERY_COLUMNS = ["http.request.uri.query", "query", "query_string"]
BODY_COLUMNS = ["http.file_data", "payload", "raw_http_request", "http.request"]
REFERER_COLUMNS = ["http.referer"]
METHOD_COLUMNS = ["http.request.method"]
NUMERIC_SOURCES = {
    "tcp.len": ["tcp.len"],
    "tcp.dstport": ["tcp.dstport"],
    "tcp.srcport": ["tcp.srcport"],
    "tcp.flags.ack": ["tcp.flags.ack"],
    "tcp.connection.syn": ["tcp.connection.syn"],
    "tcp.connection.synack": ["tcp.connection.synack"],
    "tcp.connection.fin": ["tcp.connection.fin"],
    "tcp.connection.rst": ["tcp.connection.rst"],
    "http.content_length": ["http.content_length"],
}
EMPTY_VALUES = {"", "nan", "none", "null", "0", "0.0", "-"}


def norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def usable(value: object) -> bool:
    if value is None:
        return False
    try:
        if pd.isna(value):
            return False
    except (TypeError, ValueError):
        pass
    return str(value).strip().lower() not in EMPTY_VALUES


def find_col(columns: Iterable[str], names: list[str]) -> str | None:
    columns = list(columns)
    # an exact name wins: "Incident ID" and "Incident_ID" normalise to the same key
    for name in names:
        if name in columns:
            return name
    lookup = {norm(c): c for c in columns}
    for name in names:
        if norm(name) in lookup:
            return lookup[norm(name)]
    return None


def deep_decode(text: str, rounds: int = 3) -> tuple[str, int]:
    """URL-decode repeatedly (handles double encoding). Returns text and rounds that changed it."""
    changed = 0
    for _ in range(rounds):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
        changed += 1
    return text, changed


# ---------------------------------------------------------------------------
# Feature schema (54 features, same names/order as the project's SQLi model)
# ---------------------------------------------------------------------------
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

# Evidence families = the "players" of Payload-Span Shapley.
FAMILY_LABELS = {
    "quote": "Quote characters",
    "terminator": "Statement terminator (;)",
    "comment": "SQL comment markers",
    "syntax": "Parentheses / equals signs",
    "keyword": "SQL keywords",
    "union": "UNION ... SELECT",
    "logic": "AND / OR logic",
    "time_delay": "Time-delay functions",
    "error_xml": "Error / XML / cast functions",
    "db_recon": "Database enumeration / string functions",
    "encoding": "Hex / encoded content",
    "size": "Request size & method",
    "network": "TCP / network fields",
}
CONTENT_FAMILIES = [f for f in FAMILY_LABELS if f not in ("size", "network")]


def _kw(word: str) -> str:
    return rf"\b{word}\b"


def _fn(name: str) -> str:
    # Span covers only the function name, so sanitising it does not also remove "(".
    return rf"\b{name}(?=\s*\()"


# name -> (regex, kind, family). kind: "count" = number of matches, "flag" = 0/1.
CONTENT_RULES: dict[str, tuple[str, str, str]] = {
    "single_quote_count": (r"'|%27", "count", "quote"),
    "double_quote_count": (r'"|%22', "count", "quote"),
    "semicolon_count": (r";", "count", "terminator"),
    "comment_count": (r"--|/\*|\*/|#", "count", "comment"),
    "parenthesis_count": (r"[()]", "count", "syntax"),
    "equals_count": (r"=", "count", "syntax"),
    "sql_select": (_kw("select"), "flag", "keyword"),
    "sql_union": (_kw("union"), "flag", "union"),
    "sql_insert": (_kw("insert"), "flag", "keyword"),
    "sql_update": (_kw("update"), "flag", "keyword"),
    "sql_delete": (_kw("delete"), "flag", "keyword"),
    "sql_drop": (_kw("drop"), "flag", "keyword"),
    "sql_alter": (_kw("alter"), "flag", "keyword"),
    "sql_create": (_kw("create"), "flag", "keyword"),
    "sql_from": (_kw("from"), "flag", "keyword"),
    "sql_where": (_kw("where"), "flag", "keyword"),
    "sql_having": (_kw("having"), "flag", "keyword"),
    "sql_group_by": (r"\bgroup\s+by\b", "flag", "keyword"),
    "sql_order_by": (r"\border\s+by\b", "flag", "keyword"),
    "sql_sleep": (_fn("sleep"), "flag", "time_delay"),
    "sql_benchmark": (_fn("benchmark"), "flag", "time_delay"),
    "sql_pg_sleep": (_fn("pg_sleep"), "flag", "time_delay"),
    "sql_extractvalue": (_fn("extractvalue"), "flag", "error_xml"),
    "sql_updatexml": (_fn("updatexml"), "flag", "error_xml"),
    "sql_cast": (_fn("cast"), "flag", "error_xml"),
    "sql_convert": (_fn("convert"), "flag", "error_xml"),
    "sql_concat": (_fn("concat"), "flag", "db_recon"),
    "sql_substring": (_fn("substring"), "flag", "db_recon"),
    "sql_database": (_fn("database"), "flag", "db_recon"),
    "sql_schema": (_fn("schema"), "flag", "db_recon"),
    "sql_information_schema": (r"information_schema", "flag", "db_recon"),
    "or_condition": (_kw("or"), "flag", "logic"),
    "and_condition": (_kw("and"), "flag", "logic"),
    # groups -> only the two keywords are highlighted, not everything between them
    "union_select": (r"\b(union)\b[\s\S]*?\b(select)\b", "flag", "union"),
    "hex_pattern_count": (r"\b0x[0-9a-f]+\b", "count", "encoding"),
    "sleep_function": (r"\b(?:sleep|pg_sleep|benchmark)(?=\s*\()", "flag", "time_delay"),
    "database_function": (r"\b(?:database|schema|user|version)(?=\s*\()", "flag", "db_recon"),
    "extractvalue_function": (_fn("extractvalue"), "flag", "error_xml"),
    "xml_function": (r"\b(?:updatexml|extractvalue|xmltype)(?=\s*\()", "flag", "error_xml"),
}
COMPILED_RULES = {k: (re.compile(p, re.I), kind, fam) for k, (p, kind, fam) in CONTENT_RULES.items()}

OTHER_FAMILIES = {
    "query_length": "size", "query_parameter_count": "size", "uri_length": "size",
    "http_get": "size", "http.content_length": "size", "tcp_payload_length": "size",
    "percent_encoded_count": "encoding",
    "tcp.len": "network", "tcp.dstport": "network", "tcp.srcport": "network",
    "tcp.flags.ack": "network", "tcp.connection.syn": "network",
    "tcp.connection.synack": "network", "tcp.connection.fin": "network",
    "tcp.connection.rst": "network",
}


def feature_family(name: str) -> str:
    if name in CONTENT_RULES:
        return CONTENT_RULES[name][2]
    return OTHER_FAMILIES.get(name, "network")


FEATURE_LABELS = {
    "single_quote_count": "single quotes", "double_quote_count": "double quotes",
    "semicolon_count": "semicolons", "comment_count": "SQL comment markers",
    "parenthesis_count": "parentheses", "equals_count": "equals signs",
    "or_condition": "OR operator", "and_condition": "AND operator",
    "union_select": "UNION SELECT", "percent_encoded_count": "URL-encoded characters",
    "hex_pattern_count": "hex literals", "query_length": "query length",
    "uri_length": "URI length", "query_parameter_count": "number of parameters",
    "http_get": "GET method", "tcp_payload_length": "TCP payload length",
}


def feature_label(name: str) -> str:
    if name in FEATURE_LABELS:
        return FEATURE_LABELS[name]
    if name.startswith("sql_"):
        return name[4:].replace("_", " ").upper() + " keyword/function"
    return name


# ---------------------------------------------------------------------------
# Request view: the text an analyst reads + the numeric fields
# ---------------------------------------------------------------------------
@dataclass
class RequestView:
    text: str                      # decoded, lower-cased analysis text (spans index into this)
    display_text: str              # decoded, original case (same length as text)
    raw_text: str                  # undecoded text (for percent-encoding features)
    segments: list[tuple[str, int, int]]  # (label, start, end) inside text
    query: str
    uri: str
    method: str
    numeric: dict[str, float]
    decode_rounds: int = 0


class ColumnResolver:
    """Resolves EdgeIIoT column names once per column layout."""

    def __init__(self, columns: Iterable[str]):
        columns = list(columns)
        self.target = [c for c in (find_col(columns, [n]) for n in TARGET_COLUMNS) if c]
        self.query = find_col(columns, QUERY_COLUMNS)
        self.body = [c for c in (find_col(columns, [n]) for n in BODY_COLUMNS) if c]
        self.referer = find_col(columns, REFERER_COLUMNS)
        self.method = find_col(columns, METHOD_COLUMNS)
        self.numeric = {k: find_col(columns, v) for k, v in NUMERIC_SOURCES.items()}
        self.id_col = find_col(columns, ID_COLUMNS)

    def view(self, record) -> RequestView:
        get = record.get if hasattr(record, "get") else (lambda k, d=None: record[k])

        def first(cols):
            for c in cols:
                if c and usable(get(c, None)):
                    return str(get(c)).strip()
            return ""

        target = first(self.target)
        body = first(self.body)
        referer = str(get(self.referer)).strip() if self.referer and usable(get(self.referer, None)) else ""
        query = str(get(self.query)).strip() if self.query and usable(get(self.query, None)) else ""
        if not query and "?" in target:
            query = target.split("?", 1)[1].split("#", 1)[0]
        method = str(get(self.method)).strip().upper() if self.method and usable(get(self.method, None)) else ""

        parts, segments, raw_parts, cursor, rounds = [], [], [], 0, 0
        seen = set()
        for label, value in (("Request target", target), ("Body", body), ("Referer", referer)):
            if not value or value in seen:
                continue
            seen.add(value)
            decoded, r = deep_decode(value)
            rounds = max(rounds, r)
            if parts:
                cursor += 1  # newline separator
            segments.append((label, cursor, cursor + len(decoded)))
            parts.append(decoded)
            raw_parts.append(value)
            cursor += len(decoded)
        display = "\n".join(parts)

        numeric = {}
        for key, col in self.numeric.items():
            val = 0.0
            if col and usable(get(col, None)):
                try:
                    val = float(get(col))
                except (TypeError, ValueError):
                    val = 0.0
            numeric[key] = val
        # character-wise lower() keeps text and display_text the same length (span indices stay valid)
        lowered = "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in display)
        return RequestView(
            text=lowered, display_text=display, raw_text="\n".join(raw_parts),
            segments=segments, query=query, uri=target, method=method,
            numeric=numeric, decode_rounds=rounds,
        )


def blank_spans(text: str, spans: Iterable[tuple[int, int]]) -> str:
    chars = list(text)
    for s, e in spans:
        for i in range(max(0, s), min(len(chars), e)):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def find_spans(view_text: str) -> dict[str, list[tuple[int, int]]]:
    """Character spans of every content feature inside the analysis text."""
    spans: dict[str, list[tuple[int, int]]] = {}
    for name, (rx, _kind, _fam) in COMPILED_RULES.items():
        found = []
        for m in rx.finditer(view_text):
            if m.groups():
                found.extend(m.span(g) for g in range(1, len(m.groups()) + 1) if m.group(g))
            else:
                found.append(m.span())
        if found:
            spans[name] = found
    return spans


def default_feature_builder(view: RequestView, removed_families: frozenset = frozenset(),
                            family_spans: dict | None = None) -> dict[str, float]:
    """Compute the 54 SQLi features. `removed_families` are sanitised before extraction."""
    text = view.text
    if removed_families and family_spans:
        to_blank = [s for f in removed_families for s in family_spans.get(f, [])]
        text = blank_spans(text, to_blank)
    vals: dict[str, float] = {}
    for name, (rx, kind, _fam) in COMPILED_RULES.items():
        if kind == "count":
            vals[name] = float(len(rx.findall(text)))
        else:
            vals[name] = float(bool(rx.search(text)))
    vals["percent_encoded_count"] = (
        0.0 if "encoding" in removed_families
        else float(len(re.findall(r"%[0-9a-fA-F]{2}", view.raw_text)))
    )
    vals["query_length"] = float(len(view.query))
    vals["query_parameter_count"] = float(view.query.count("&") + (1 if "=" in view.query else 0))
    vals["uri_length"] = float(len(view.uri))
    vals["http_get"] = float(view.method == "GET")
    vals.update(view.numeric)
    vals["tcp_payload_length"] = view.numeric.get("tcp.len", 0.0) or float(len(view.raw_text))
    return vals


# ---------------------------------------------------------------------------
# Rule-based technique profiling (N5)
# ---------------------------------------------------------------------------
TECHNIQUES = [
    # key, label, regex, family, severity, CAPEC, recommendation
    ("union", "UNION-based injection",
     r"\bunion\b(?:\s+all)?[\s(]+select\b", "union", 0.85, "CAPEC-66",
     "Check whether the response returned extra columns/rows; review DB logs for UNION queries."),
    ("time_blind", "Time-based blind injection",
     r"\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b", "time_delay", 0.80, "CAPEC-7",
     "Compare server response time for this request with normal requests; look for repeated probes."),
    ("error_based", "Error-based injection",
     r"\b(?:extractvalue|updatexml|xmltype)\s*\(|\b(?:convert|cast)\s*\([^)]*select", "error_xml", 0.80, "CAPEC-66",
     "Check whether database error messages are returned to the client; disable verbose errors."),
    ("stacked", "Stacked queries",
     r";\s*(?:select|insert|update|delete|drop|create|alter|exec|declare)\b", "terminator", 0.95, "CAPEC-66",
     "Verify no data was modified; check DB audit logs for INSERT/UPDATE/DROP from the web account."),
    ("boolean_blind", "Boolean-based blind / tautology",
     r"\b(\d+)\s*=\s*\1\b|'([^']{0,20})'\s*=\s*'\2|\b(?:or|and)\s+['\"(]?\w+['\")]?\s*(?:=|like|<|>)", "logic", 0.70, "CAPEC-7",
     "Look for paired TRUE/FALSE requests from the same source that differ only in the condition."),
    ("enumeration", "Schema / version enumeration",
     r"information_schema|@@version|\b(?:database|schema|version|user)\s*\(", "db_recon", 0.75, "CAPEC-66",
     "Assume the attacker is mapping the database; check which tables were accessed afterwards."),
    ("comment_trunc", "Comment truncation",
     r"['\")]\s*(?:--|#|/\*)", "comment", 0.55, "CAPEC-66",
     "The rest of the original query was likely commented out; review the affected parameter."),
    ("quote_breakout", "Quote break-out",
     r"'\s*(?:or|and|union|;|\)|--|#)", "quote", 0.55, "CAPEC-66",
     "The parameter is probably concatenated into SQL; use parameterised queries."),
    ("nested", "Nested sub-query",
     r"\(\s*select\b", "keyword", 0.60, "CAPEC-66",
     "Sub-queries in user input are rarely legitimate; review the parameter handling."),
    ("obfuscation", "Obfuscation / encoding",
     r"\bchr\s*\(\s*\d+\s*\)\s*\|\||\bchar\s*\(\s*\d+|\b0x[0-9a-f]{4,}\b", "encoding", 0.45, "CAPEC-66",
     "Attacker is evading simple filters; signature-based WAF rules may have missed this."),
]
COMPILED_TECHNIQUES = [(k, l, re.compile(p, re.I), f, s, c, r) for k, l, p, f, s, c, r in TECHNIQUES]


def detect_techniques(view: RequestView) -> list[dict]:
    found = []
    for key, label, rx, fam, sev, capec, rec in COMPILED_TECHNIQUES:
        matches = list(rx.finditer(view.text))
        if not matches:
            continue
        s, e = matches[0].span()
        found.append({
            "key": key, "technique": label, "family": fam, "severity": sev,
            "capec": capec, "cwe": "CWE-89", "attack": "T1190",
            "evidence": view.display_text[s:e][:80], "matches": len(matches),
            "recommendation": rec,
        })
    if view.decode_rounds >= 2 and not any(t["key"] == "obfuscation" for t in found):
        found.append({
            "key": "obfuscation", "technique": "Obfuscation / encoding (double URL-encoding)",
            "family": "encoding", "severity": 0.45, "capec": "CAPEC-66", "cwe": "CWE-89",
            "attack": "T1190", "evidence": "payload needed %d decoding rounds" % view.decode_rounds,
            "matches": 1, "recommendation": "Decode inputs before WAF/IDS inspection; double encoding is an evasion technique.",
        })
    return sorted(found, key=lambda t: -t["severity"])


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------
@dataclass
class IncidentExplanation:
    incident_id: str
    predicted_label: str
    attack_class: str
    attack_probability: float
    confidence: float
    is_attack: bool
    probabilities: dict
    features: dict
    view: RequestView
    family_spans: dict
    pss: dict                      # family -> Shapley value (attack probability)
    pss_base: float                # v(empty) = probability with all payload evidence removed
    char_attribution: list         # per-character PSS attribution
    shap_values: dict | None
    shap_family: dict | None
    lime_weights: dict | None
    lime_family: dict | None
    techniques: list
    trust: dict
    counterfactual: dict
    priority: dict
    narrative: str
    messages: list = field(default_factory=list)

    def summary_row(self) -> dict:
        """Flat metrics for batch evaluation tables."""
        t = self.trust
        top = sorted(self.pss.items(), key=lambda kv: -kv[1])
        return {
            "incident_id": self.incident_id,
            "predicted_label": self.predicted_label,
            "attack_probability": round(self.attack_probability, 6),
            "is_attack": self.is_attack,
            "techniques": "; ".join(x["technique"] for x in self.techniques),
            "n_techniques": len(self.techniques),
            "pss_top_family": top[0][0] if top else "",
            "pss_payload_share": t.get("payload_share"),
            "rule_pss_agreement": t.get("rule_pss_agreement"),
            "pss_shap_agreement": t.get("pss_shap_agreement"),
            "pss_lime_agreement": t.get("pss_lime_agreement"),
            "deletion_drop_top": t.get("deletion_drop_top"),
            "deletion_drop_random": t.get("deletion_drop_random"),
            "fidelity_gain": t.get("fidelity_gain"),
            "trust_score": t.get("score"),
            "trust_level": t.get("level"),
            "counterfactual_found": self.counterfactual.get("found"),
            "counterfactual_size": len(self.counterfactual.get("removed_families", [])),
            "priority_score": self.priority.get("score"),
        }

    def to_json(self) -> str:
        data = asdict(self)
        data["view"] = {"segments": self.view.segments, "text": self.view.display_text,
                        "decode_rounds": self.view.decode_rounds}
        data.pop("char_attribution", None)
        return json.dumps(data, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
def infer_attack_index(classes: list, attack_class=None) -> int:
    """Index of the class meaning 'SQL injection / attack' in model.classes_."""
    if attack_class is not None:
        for i, c in enumerate(classes):
            if str(c).lower() == str(attack_class).lower():
                return i
        raise ValueError(f"attack_class {attack_class!r} not in model classes {classes}")
    for i, c in enumerate(classes):
        if re.search(r"sql|sqli|inject", str(c), re.I):
            return i
    for i, c in enumerate(classes):
        if str(c).lower() in {"1", "1.0", "true", "attack", "malicious"}:
            return i
    return len(classes) - 1


class SQLiXAIEngine:
    """
    model            fitted classifier with predict_proba (e.g. sql_injection_rf.pkl)
    feature_names    training feature order (defaults to model.feature_names_in_ or the 54-feature schema)
    background       DataFrame of real feature rows (from build_feature_matrix) used by SHAP/LIME
                     and for the random-deletion baseline. 200-500 rows is enough.
    attack_class     the class label meaning "SQL injection / attack". Inferred if None.
    feature_builder  optional replacement for default_feature_builder (must accept the same arguments)
    """

    def __init__(self, model, feature_names=None, background: pd.DataFrame | None = None,
                 attack_class=None, threshold: float = 0.5, max_players: int = 12,
                 random_state: int = 42, feature_builder: Callable | None = None):
        if not hasattr(model, "predict_proba"):
            raise ValueError("The model must provide predict_proba().")
        self.model = model
        if feature_names is None:
            feature_names = list(getattr(model, "feature_names_in_", DEFAULT_SQL_FEATURES))
        self.feature_names = [str(f) for f in feature_names]
        n_in = getattr(model, "n_features_in_", None)
        if n_in is not None and int(n_in) != len(self.feature_names):
            raise ValueError(f"Model expects {n_in} features but {len(self.feature_names)} feature names were given.")
        self.classes = list(getattr(model, "classes_", [0, 1]))
        self.attack_idx = self._infer_attack_idx(attack_class)
        self.attack_class = self.classes[self.attack_idx]
        self.threshold = threshold
        self.max_players = max_players
        self.rng = np.random.default_rng(random_state)
        self.random_state = random_state
        self.builder = feature_builder or default_feature_builder
        self.background = background[self.feature_names] if background is not None else None
        self._resolvers: dict[tuple, ColumnResolver] = {}
        self._tree_explainer = None
        self._lime_explainer = None
        unknown = [f for f in self.feature_names if f not in CONTENT_RULES and f not in OTHER_FAMILIES]
        self.unknown_features = unknown  # filled with 0 by the default builder

    # -- helpers ------------------------------------------------------------
    def _infer_attack_idx(self, attack_class) -> int:
        return infer_attack_index(self.classes, attack_class)

    def resolver(self, columns) -> ColumnResolver:
        key = tuple(columns)
        if key not in self._resolvers:
            self._resolvers[key] = ColumnResolver(columns)
        return self._resolvers[key]

    def _row_frame(self, rows: list[dict]) -> pd.DataFrame:
        return pd.DataFrame([[r.get(f, 0.0) for f in self.feature_names] for r in rows],
                            columns=self.feature_names, dtype=float)

    def _proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(np.asarray(X, dtype=float), columns=self.feature_names)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return np.asarray(self.model.predict_proba(X), dtype=float)

    def build_features(self, record) -> tuple[RequestView, dict]:
        cols = record.index if hasattr(record, "index") else record.keys()
        view = self.resolver(cols).view(record)
        return view, self.builder(view)

    def build_feature_matrix(self, df: pd.DataFrame) -> pd.DataFrame:
        """Feature rows for many dataset records (use for the background sample)."""
        res = self.resolver(df.columns)
        rows = [self.builder(res.view(r)) for r in df.to_dict("records")]
        return self._row_frame(rows)

    # -- N1: Payload-Span Shapley ---------------------------------------------
    def _family_spans(self, view: RequestView) -> dict[str, list[tuple[int, int]]]:
        fam: dict[str, list] = {}
        for feat, spans in find_spans(view.text).items():
            fam.setdefault(CONTENT_RULES[feat][2], []).extend(spans)
        if re.search(r"%[0-9a-fA-F]{2}", view.raw_text):
            fam.setdefault("encoding", [])  # player with no visible span (raw encoding)
        return fam

    def payload_span_shapley(self, view: RequestView, family_spans: dict):
        players = [f for f in CONTENT_FAMILIES if f in family_spans]
        if len(players) > self.max_players:  # keep the coalition table small
            keep = sorted(players, key=lambda f: -len(family_spans[f]))[: self.max_players - 1]
            merged = [f for f in players if f not in keep]
            family_spans = dict(family_spans)
            family_spans["other"] = [s for f in merged for s in family_spans[f]]
            players = keep + ["other"]
        n = len(players)
        masks = range(2 ** n)
        rows = []
        for mask in masks:  # bit set = family KEPT
            removed = frozenset(p for i, p in enumerate(players) if not (mask >> i) & 1)
            removed_expanded = removed
            if "other" in removed:
                removed_expanded = (removed - {"other"}) | {f for f in family_spans if f not in players}
            rows.append(self.builder(view, removed_expanded, family_spans))
        values = self._proba(self._row_frame(rows))[:, self.attack_idx]
        fact = [math.factorial(k) for k in range(n + 1)]
        phi = {}
        for i, p in enumerate(players):
            bit = 1 << i
            total = 0.0
            for mask in masks:
                if mask & bit:
                    continue
                s = bin(mask).count("1")
                total += fact[s] * fact[n - s - 1] / fact[n] * (values[mask | bit] - values[mask])
            phi[p] = float(total)
        return players, phi, values, family_spans

    def char_attribution(self, view: RequestView, family_spans: dict, family_values: dict) -> np.ndarray:
        attr = np.zeros(len(view.text))
        for fam, val in family_values.items():
            spans = family_spans.get(fam, [])
            n_chars = sum(e - s for s, e in spans)
            if not n_chars:
                continue
            for s, e in spans:
                attr[s:e] += val * (e - s) / n_chars / max(e - s, 1)
        return attr

    # -- optional SHAP / LIME --------------------------------------------------
    def shap_values(self, x: pd.DataFrame) -> np.ndarray:
        import shap  # optional dependency
        vals = None
        try:
            if self._tree_explainer is None:
                self._tree_explainer = shap.TreeExplainer(self.model)
            vals = self._tree_explainer.shap_values(x)
        except Exception:
            if self.background is None:
                raise
            bg = self.background.sample(min(100, len(self.background)), random_state=self.random_state)
            explainer = shap.Explainer(lambda X: self._proba(X)[:, self.attack_idx],
                                       shap.maskers.Independent(bg.to_numpy(float)))
            return np.asarray(explainer(x.to_numpy(float)).values)[0]
        if isinstance(vals, list):
            return np.asarray(vals[self.attack_idx])[0]
        vals = np.asarray(vals)
        if vals.ndim == 3:
            return vals[0, :, self.attack_idx]
        row = vals[0] if vals.ndim == 2 else vals
        # single-output explainers describe the positive (last) class
        return row if self.attack_idx == len(self.classes) - 1 else -row

    def lime_weights(self, x: pd.DataFrame) -> dict[str, float]:
        from lime.lime_tabular import LimeTabularExplainer  # optional dependency
        if self.background is None or len(self.background) < 20:
            raise ValueError("LIME needs a background sample of real feature rows (>= 20).")
        if self._lime_explainer is None:
            self._lime_explainer = LimeTabularExplainer(
                training_data=self.background.to_numpy(float),
                feature_names=self.feature_names,
                class_names=[str(c) for c in self.classes],
                mode="classification", discretize_continuous=True,
                random_state=self.random_state,
            )
        exp = self._lime_explainer.explain_instance(
            x.iloc[0].to_numpy(float), self._proba, labels=(self.attack_idx,),
            num_features=min(15, len(self.feature_names)), num_samples=2000,
        )
        return {self.feature_names[i]: float(w) for i, w in exp.as_map()[self.attack_idx]}

    @staticmethod
    def _by_family(values: dict[str, float]) -> dict[str, float]:
        out: dict[str, float] = {}
        for feat, v in values.items():
            fam = feature_family(feat)
            out[fam] = out.get(fam, 0.0) + float(v)
        return out

    # -- N3: trust ------------------------------------------------------------
    @staticmethod
    def _top_positive(values: dict[str, float], k: int = 3, rel: float = 0.05) -> set:
        pos = {f: v for f, v in values.items() if v > 0}
        if not pos:
            return set()
        cutoff = rel * max(pos.values())
        ranked = sorted(pos.items(), key=lambda kv: -kv[1])
        return {f for f, v in ranked[:k] if v >= cutoff}

    @staticmethod
    def _jaccard(a: set, b: set):
        if not a and not b:
            return None
        return len(a & b) / len(a | b)

    def _deletion_test(self, view, family_spans, families, p0) -> tuple[float, float]:
        families = [f for f in families if f in family_spans]
        if not families:
            return 0.0, 0.0
        x_del = self.builder(view, frozenset(families), family_spans)
        drop_top = p0 - float(self._proba(self._row_frame([x_del]))[0, self.attack_idx])
        n_chars = sum(e - s for f in families for s, e in family_spans[f])
        candidates = [i for i, ch in enumerate(view.text) if not ch.isspace()]
        rows = []
        if n_chars and candidates:
            for _ in range(10):  # random-deletion baseline with the same character budget
                pick = self.rng.choice(candidates, size=min(n_chars, len(candidates)), replace=False)
                fake = {"__rand__": [(int(i), int(i) + 1) for i in pick]}
                rows.append(self.builder(view, frozenset({"__rand__"}), fake))
        if not rows:
            return drop_top, 0.0
        p_rand = self._proba(self._row_frame(rows))[:, self.attack_idx]
        return drop_top, float(np.mean(p0 - p_rand))

    # -- main entry point -----------------------------------------------------
    def explain(self, record, incident_id: str | None = None,
                use_shap: bool = True, use_lime: bool = True) -> IncidentExplanation:
        messages = []
        view, feats = self.build_features(record)
        x = self._row_frame([feats])
        proba = self._proba(x)[0]
        pred_idx = int(np.argmax(proba))
        p_attack = float(proba[self.attack_idx])
        is_attack = pred_idx == self.attack_idx
        if incident_id is None:
            res = self.resolver(record.index if hasattr(record, "index") else record.keys())
            incident_id = str(record[res.id_col]) if res.id_col else "unknown"

        family_spans = self._family_spans(view)
        players, pss, coalition_values, family_spans = self.payload_span_shapley(view, family_spans)
        pss_base = float(coalition_values[0]) if len(coalition_values) else p_attack
        char_attr = self.char_attribution(view, family_spans, pss)

        shap_vals = shap_family = lime_w = lime_family = None
        if use_shap:
            try:
                sv = self.shap_values(x)
                shap_vals = {f: float(v) for f, v in zip(self.feature_names, sv)}
                shap_family = self._by_family(shap_vals)
            except ImportError:
                messages.append("SHAP not installed (pip install shap) - feature-level SHAP skipped.")
            except Exception as exc:
                messages.append(f"SHAP failed: {type(exc).__name__}: {exc}")
        if use_lime:
            try:
                lime_w = self.lime_weights(x)
                lime_family = self._by_family(lime_w)
            except ImportError:
                messages.append("LIME not installed (pip install lime) - LIME skipped.")
            except Exception as exc:
                messages.append(f"LIME skipped: {type(exc).__name__}: {exc}")

        techniques = detect_techniques(view)
        trust = self._trust(view, family_spans, pss, shap_family, lime_family, techniques, p_attack, pss_base, is_attack)
        counterfactual = self._counterfactual(players, coalition_values, pss, family_spans, view, is_attack)
        priority = self._priority(p_attack, techniques, trust)
        if self.unknown_features:
            messages.append("Features not produced by the default builder (set to 0): " + ", ".join(self.unknown_features))

        expl = IncidentExplanation(
            incident_id=str(incident_id), predicted_label=str(self.classes[pred_idx]),
            attack_class=str(self.attack_class), attack_probability=p_attack,
            confidence=float(proba[pred_idx]), is_attack=is_attack,
            probabilities={str(c): float(p) for c, p in zip(self.classes, proba)},
            features=feats, view=view,
            family_spans={k: v for k, v in family_spans.items()},
            pss=pss, pss_base=pss_base, char_attribution=char_attr.tolist(),
            shap_values=shap_vals, shap_family=shap_family,
            lime_weights=lime_w, lime_family=lime_family,
            techniques=techniques, trust=trust, counterfactual=counterfactual,
            priority=priority, narrative="", messages=messages,
        )
        expl.narrative = build_narrative(expl)
        return expl

    def _trust(self, view, family_spans, pss, shap_family, lime_family, techniques, p_attack, pss_base, is_attack):
        # "syntax" (=, parentheses) appears in every query, so it is left out of agreement checks.
        rule_fams = {t["family"] for t in techniques} - {"syntax"}
        pss_top = self._top_positive({k: v for k, v in pss.items() if k != "syntax"})
        t = {"rule_families": sorted(rule_fams), "pss_top_families": sorted(pss_top)}
        # overlap coefficient: rules may flag many families while PSS keeps only the top 3
        t["rule_pss_agreement"] = (len(rule_fams & pss_top) / min(len(rule_fams), len(pss_top))
                                   if rule_fams and pss_top else (None if not rule_fams and not pss_top else 0.0))
        content = lambda d: {k: v for k, v in (d or {}).items() if k in CONTENT_FAMILIES and k != "syntax"}
        t["pss_shap_agreement"] = self._jaccard(pss_top, self._top_positive(content(shap_family))) if shap_family else None
        t["pss_lime_agreement"] = self._jaccard(pss_top, self._top_positive(content(lime_family))) if lime_family else None
        # share of the attack probability explained by payload evidence (vs network/size features)
        t["payload_share"] = float(np.clip((p_attack - pss_base) / p_attack, 0, 1)) if p_attack > 1e-9 else 0.0
        if is_attack and pss_top:
            drop_top, drop_rand = self._deletion_test(view, family_spans, sorted(pss_top, key=lambda f: -pss[f]), p_attack)
            t["deletion_drop_top"], t["deletion_drop_random"] = drop_top, drop_rand
            t["fidelity_gain"] = float(np.clip((drop_top - drop_rand) / max(p_attack, 1e-9), -1, 1))
        else:
            t["deletion_drop_top"] = t["deletion_drop_random"] = t["fidelity_gain"] = None
        parts = [v for v in (t["rule_pss_agreement"], t["pss_shap_agreement"], t["pss_lime_agreement"]) if v is not None]
        if t["fidelity_gain"] is not None:
            parts.append(max(0.0, t["fidelity_gain"]))
        t["components_used"] = len(parts)
        t["score"] = float(np.mean(parts)) if parts else None
        s = t["score"]
        t["level"] = "Not assessed" if s is None else "High" if s >= 0.7 else "Medium" if s >= 0.4 else "Low"
        return t

    def _counterfactual(self, players, values, pss, family_spans, view, is_attack):
        if not is_attack:
            return {"found": False, "applicable": False,
                    "reason": "The model did not predict an attack, so no sanitisation counterfactual is needed."}
        n, full = len(players), (1 << len(players)) - 1
        best = None
        for size in range(1, n + 1):
            cands = []
            for removed in itertools.combinations(range(n), size):
                mask = full
                for i in removed:
                    mask &= ~(1 << i)
                if values[mask] < self.threshold:
                    cands.append((values[mask], removed))
            if cands:
                best = min(cands)
                break
        if best is None:
            return {"found": False, "applicable": True,
                    "reason": "Removing every payload evidence group does not drop the attack probability "
                              "below the threshold - the decision is driven by non-payload (network/size) features.",
                    "probability_all_removed": float(values[0]) if len(values) else None}
        prob, removed = best
        fams = [players[i] for i in removed]
        sanitized = blank_spans(view.display_text, [s for f in fams for s in family_spans.get(f, [])])
        return {"found": True, "applicable": True, "removed_families": fams,
                "removed_labels": [FAMILY_LABELS.get(f, f) for f in fams],
                "probability_after": float(prob), "sanitized_preview": sanitized[:600]}

    @staticmethod
    def _priority(p_attack, techniques, trust):
        sev = max((t["severity"] for t in techniques), default=0.3)
        score = p_attack * sev
        level = "Critical" if score >= 0.75 else "High" if score >= 0.55 else "Medium" if score >= 0.3 else "Low"
        note = ""
        if trust.get("level") == "Low":
            note = "Explanation trust is low - verify manually before acting."
        return {"score": float(score), "level": level, "max_technique_severity": sev, "note": note}


# ---------------------------------------------------------------------------
# Narrative + rendering
# ---------------------------------------------------------------------------
def build_narrative(e: IncidentExplanation) -> str:
    verdict = "an SQL injection / attack" if e.is_attack else "not an attack"
    lines = [f"Incident {e.incident_id}: the model classified this request as {verdict} "
             f"(predicted '{e.predicted_label}', P({e.attack_class}) = {e.attack_probability:.1%})."]
    pos = [(f, v) for f, v in sorted(e.pss.items(), key=lambda kv: -kv[1]) if v > 0.005]
    if pos:
        parts = []
        for fam, val in pos[:3]:
            spans = e.family_spans.get(fam, [])
            sample = ", ".join(sorted({e.view.display_text[s:t] for s, t in spans[:6]}))[:60]
            parts.append(f"{FAMILY_LABELS.get(fam, fam).lower()} (+{val:.1%}" + (f": {sample}" if sample else "") + ")")
        lines.append("Payload evidence that pushed the score up most: " + "; ".join(parts) + ".")
    share = e.trust.get("payload_share")
    if share is not None and e.is_attack:
        lines.append(f"About {share:.0%} of the attack probability comes from the payload text; "
                     f"the rest comes from size/network features.")
    if e.techniques:
        lines.append("Rule analysis identifies: " + ", ".join(t["technique"] for t in e.techniques[:4])
                     + " (CWE-89, MITRE ATT&CK T1190).")
    else:
        lines.append("No known SQLi technique pattern was found by the rules.")
    t = e.trust
    if t.get("score") is not None:
        lines.append(f"Explanation trust: {t['level']} ({t['score']:.2f}) based on {t['components_used']} independent check(s).")
    cf = e.counterfactual
    if cf.get("found"):
        lines.append("Counterfactual: removing only " + " and ".join(x.lower() for x in cf["removed_labels"])
                     + f" would lower the attack probability to {cf['probability_after']:.1%}.")
    elif cf.get("applicable"):
        lines.append("Counterfactual: " + cf["reason"])
    if e.techniques:
        lines.append("Suggested next step: " + e.techniques[0]["recommendation"])
    lines.append("This explains the model's behaviour for this record; it is not proof that the attack succeeded.")
    return " ".join(lines)


def render_attribution_html(e: IncidentExplanation) -> str:
    """Character-level heat map. Red = pushes towards attack, blue = pushes away."""
    text = e.view.display_text
    attr = np.asarray(e.char_attribution, dtype=float)
    peak = float(np.max(np.abs(attr))) if attr.size else 0.0
    out, i = [], 0
    while i < len(text):
        j = i + 1
        while j < len(text) and attr[j] == attr[i] and text[j] != "\n":
            j += 1
        chunk = html.escape(text[i:j])
        a = attr[i]
        if peak > 0 and abs(a) > 1e-12 and text[i] != "\n":
            alpha = 0.18 + 0.72 * abs(a) / peak
            rgb = "239,68,68" if a > 0 else "59,130,246"
            out.append(f'<span title="PSS {a:+.4f}" style="background:rgba({rgb},{alpha:.2f});'
                       f'border-radius:3px">{chunk}</span>')
        else:
            out.append(chunk)
        i = j
    return "".join(out).replace("\n", "<br>")


# ---------------------------------------------------------------------------
# Fast text pre-filter (used by the dashboard's "SQL-like text only" toggle)
# ---------------------------------------------------------------------------
CANDIDATE_PATTERN = (r"(?i)(?:%27|'|%22|\bunion\b|union%20|\bselect\b|select%20|sleep|benchmark|"
                     r"%23|--|information_schema|extractvalue|updatexml|xmltype|0x[0-9a-f]{4})")


def candidate_mask(df: pd.DataFrame) -> pd.Series:
    """True for rows whose request text contains SQL-like characters/words. Not a classifier."""
    res = ColumnResolver(df.columns)
    cols = [c for c in res.target + res.body + [res.query, res.referer] if c]
    mask = pd.Series(False, index=df.index)
    for c in dict.fromkeys(cols):
        mask |= df[c].astype("string").str.contains(CANDIDATE_PATTERN, regex=True, na=False)
    return mask
