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

Mitigations for the known PSS problems (search "FIX P<n>" in this file)
-----------------------------------------------------------------------
P1  Parameter "=" (name=) is normal HTTP syntax: it goes to the fixed "structure"
    family and is never a player. Only comparison "=" (1=1) stays as evidence.
P2  Robustness: PSS is re-run with a second removal method (delete instead of
    blank) and the rankings are compared; sanitised rows outside the background
    feature range are counted (out-of-range warning).
P3  Groups follow a fixed SQLi taxonomy (TAXONOMY); an alternative "coarse"
    grouping exists for the sensitivity test in evaluate_sqli_xai.py.
P4  Groups never overlap: each character belongs to one group (FAMILY_PRIORITY).
P5  Payload vs network split: a two-player Shapley split of P(attack) into
    baseline + SQL payload evidence + network/size features.
P6  At most 11 groups -> at most 2,048 model calls; n_players is reported.
P7  The same deletion test is run with the groups SHAP and LIME rank highest,
    so PSS can be compared fairly with SHAP and LIME in the evaluation.

Feature DEFINITIONS are never changed by these fixes (equals_count still counts
every "="), so the model always receives inputs built like its training data.

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
    "syntax": "Parentheses / comparison =",       # FIX P1: only SQL comparison "=" (1=1), not "name="
    "keyword": "SQL keywords",
    "union": "UNION ... SELECT",
    "logic": "AND / OR logic",
    "time_delay": "Time-delay functions",
    "error_xml": "Error / XML / cast functions",
    "db_recon": "Database enumeration / string functions",
    "encoding": "Hex / encoded content",
    "structure": "Parameter syntax (name=)",       # FIX P1: normal request structure, never a player
    "size": "Request size & method",
    "network": "TCP / network fields",
}
NON_PLAYER_FAMILIES = ("structure", "size", "network")
CONTENT_FAMILIES = [f for f in FAMILY_LABELS if f not in NON_PLAYER_FAMILIES]

# FIX P1: an "=" that directly follows a parameter name at the start of a name=value pair
# (start of text, "?", "&" or a new line) is normal HTTP syntax, not SQL evidence.
# It stays in the request in every coalition, so the features still match training.
PARAM_ASSIGN = re.compile(r"(?:^|[?&\n])[a-z0-9_.\-\[\]%]{1,64}(=)", re.I | re.M)

# FIX P4: every character belongs to exactly ONE evidence group. When two groups
# match the same characters, the more specific group (earlier in this list) wins.
FAMILY_PRIORITY = ["structure", "union", "time_delay", "error_xml", "db_recon", "encoding",
                   "keyword", "logic", "comment", "terminator", "quote", "syntax"]

# FIX P3: groups are fixed to a published SQLi taxonomy (write this table in the thesis).
TAXONOMY = {
    "quote": "OWASP SQLi - string break-out; CAPEC-66",
    "terminator": "OWASP SQLi - stacked queries; CAPEC-66",
    "comment": "OWASP SQLi - comment truncation; CAPEC-66",
    "syntax": "CAPEC-7 boolean blind - comparison / tautology (1=1)",
    "keyword": "OWASP SQLi - injected query keywords; CAPEC-66",
    "union": "OWASP SQLi - UNION-based; CAPEC-66",
    "logic": "CAPEC-7 boolean blind - AND / OR conditions",
    "time_delay": "CAPEC-7 time-based blind - SLEEP / BENCHMARK",
    "error_xml": "OWASP SQLi - error-based (EXTRACTVALUE / UPDATEXML)",
    "db_recon": "CAPEC-66 - database / schema enumeration",
    "encoding": "CAPEC-267 alternate encoding (hex / URL encoding)",
}

# FIX P3: an alternative, coarser grouping used ONLY for the sensitivity test in the
# evaluation script (do the conclusions stay the same with a different grouping?).
GROUPINGS = {
    "default": {f: f for f in CONTENT_FAMILIES},
    "coarse": {
        "quote": "breakout", "comment": "breakout", "terminator": "breakout",
        "logic": "boolean", "syntax": "boolean",
        "keyword": "query", "union": "query",
        "time_delay": "functions", "error_xml": "functions", "db_recon": "functions",
        "encoding": "encoding",
    },
}
FAMILY_LABELS.update({
    "breakout": "Break-out & truncation (quotes, comments, ;)",
    "boolean": "Boolean / comparison logic",
    "query": "Injected query (keywords, UNION)",
    "functions": "Database functions",
    "other": "Other evidence",
})


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


REMOVAL_MODES = ("blank", "delete")


def blank_spans(text: str, spans: Iterable[tuple[int, int]], mode: str = "blank") -> str:
    """
    Remove the characters inside `spans`.
    mode="blank"  -> replace them with spaces (keeps word boundaries; default)
    mode="delete" -> cut them out completely (FIX P2: second removal method for the robustness check)
    New lines are always kept.
    """
    chars = list(text)
    drop = "" if mode == "delete" else " "
    for s, e in spans:
        for i in range(max(0, s), min(len(chars), e)):
            if chars[i] != "\n":
                chars[i] = drop
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
                            family_spans: dict | None = None, removal: str = "blank") -> dict[str, float]:
    """
    Compute the 54 SQLi features. `removed_families` are sanitised before extraction.
    The feature DEFINITIONS never change (equals_count still counts every "="), so the
    model always sees inputs built exactly like its training data.
    """
    text = view.text
    if removed_families and family_spans:
        to_blank = [s for f in removed_families for s in family_spans.get(f, [])]
        text = blank_spans(text, to_blank, mode=removal)
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
    decomposition: dict | None = None   # FIX P5: payload vs network/size two-player Shapley split
    robustness: dict | None = None      # FIX P2: second removal method + out-of-range check
    n_players: int = 0                  # FIX P6: number of evidence groups (2^n model calls)
    structure_spans: list = field(default_factory=list)   # FIX P1: parameter "=" kept fixed

    def summary_row(self) -> dict:
        """Flat metrics for batch evaluation tables."""
        t = self.trust
        top = sorted(self.pss.items(), key=lambda kv: -kv[1])
        d = self.decomposition or {}
        r = self.robustness or {}
        return {
            "n_players": self.n_players,
            "n_param_equals_excluded": len(self.structure_spans),
            "split_payload": d.get("payload"),
            "split_network": d.get("network"),
            "split_base": d.get("base"),
            "removal_top_agree": r.get("top_agree"),
            "removal_rank_corr": r.get("rank_corr"),
            "ood_fraction": r.get("ood_fraction"),
            "deletion_drop_shap_top": t.get("deletion_drop_shap_top"),
            "deletion_drop_lime_top": t.get("deletion_drop_lime_top"),
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
    grouping         "default" (taxonomy groups) or "coarse" (sensitivity test, FIX P3)
    removal          "blank" (spaces, default) or "delete" - how evidence is removed (FIX P2)
    check_robustness also run PSS with the other removal method and an out-of-range check (FIX P2)
    split_samples    background rows used for the payload-vs-network split (FIX P5)
    """

    def __init__(self, model, feature_names=None, background: pd.DataFrame | None = None,
                 attack_class=None, threshold: float = 0.5, max_players: int = 12,
                 random_state: int = 42, feature_builder: Callable | None = None,
                 grouping: str = "default", removal: str = "blank",
                 check_robustness: bool = True, split_samples: int = 100):
        if grouping not in GROUPINGS:
            raise ValueError(f"grouping must be one of {list(GROUPINGS)}")
        if removal not in REMOVAL_MODES:
            raise ValueError(f"removal must be one of {REMOVAL_MODES}")
        self.grouping = grouping
        self.group_map = GROUPINGS[grouping]
        self.removal = removal
        self.check_robustness = check_robustness
        self.split_samples = split_samples
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
        self.custom_builder = feature_builder is not None
        self.background = background[self.feature_names] if background is not None else None
        self._last_coalition_X = None
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

    def _build(self, view, removed=frozenset(), spans=None, removal: str | None = None) -> dict:
        """Call the feature builder; the removal method is passed only to the default builder."""
        if self.custom_builder:
            return self.builder(view, removed, spans)
        return self.builder(view, removed, spans, removal=removal or self.removal)

    # -- N1: Payload-Span Shapley ---------------------------------------------
    def _family_spans(self, view: RequestView) -> dict[str, list[tuple[int, int]]]:
        """
        Evidence groups -> character spans.
        FIX P1: parameter "=" (name=) goes to the fixed "structure" family, never a player.
        FIX P4: each character is given to exactly one group (FAMILY_PRIORITY), so groups never overlap.
        FIX P3: groups are then mapped with the chosen grouping ("default" or "coarse").
        """
        text = view.text
        raw: dict[str, list] = {}
        for feat, spans in find_spans(text).items():
            raw.setdefault(CONTENT_RULES[feat][2], []).extend(spans)
        raw["structure"] = [m.span(1) for m in PARAM_ASSIGN.finditer(text)]

        owner = [None] * len(text)
        for fam in FAMILY_PRIORITY:
            for s, e in raw.get(fam, []):
                for i in range(max(0, s), min(len(text), e)):
                    if owner[i] is None:
                        owner[i] = fam

        fam_spans: dict[str, list] = {}
        i = 0
        while i < len(text):                       # contiguous runs of the same owner -> spans
            f = owner[i]
            j = i + 1
            while j < len(text) and owner[j] == f:
                j += 1
            if f is not None:
                group = f if f in NON_PLAYER_FAMILIES else self.group_map.get(f, f)
                fam_spans.setdefault(group, []).append((i, j))
            i = j
        if re.search(r"%[0-9a-fA-F]{2}", view.raw_text):
            fam_spans.setdefault(self.group_map.get("encoding", "encoding"), [])  # raw encoding, no visible span
        return fam_spans

    def payload_span_shapley(self, view: RequestView, family_spans: dict, removal: str | None = None):
        # players = every evidence group found, in a fixed order (structure/size/network are never players)
        order = list(dict.fromkeys(self.group_map.get(f, f) for f in CONTENT_FAMILIES))
        players = [g for g in order if g in family_spans]
        # FIX P6: with the 11 taxonomy groups there are at most 2^11 = 2,048 combinations, so this cap
        # (default 12) never triggers in practice; it only protects custom groupings.
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
                removed_expanded = (removed - {"other"}) | {f for f in family_spans
                                                            if f not in players and f not in NON_PLAYER_FAMILIES}
            rows.append(self._build(view, removed_expanded, family_spans, removal))
        X_coal = self._row_frame(rows)
        if removal is None or removal == self.removal:
            self._last_coalition_X = X_coal       # kept for the out-of-range check (FIX P2)
        values = self._proba(X_coal)[:, self.attack_idx]
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

    # -- FIX P5: payload vs network/size split ----------------------------------
    def payload_network_split(self, view: RequestView, feats: dict, family_spans: dict,
                              players: list, p_attack: float, p_no_payload: float) -> dict | None:
        """
        Two-player Shapley split of P(attack):
          player "payload" = all SQL evidence groups in the request text
          player "network" = TCP / size features (ports, tcp.len, lengths, method)
        "Removing" the network player = replacing those features with values from real
        background rows and averaging. Result: P(attack) = base + payload + network (exact).
        """
        if self.background is None or len(self.background) == 0:
            return None
        net = [f for f in self.feature_names if feature_family(f) in ("size", "network")]
        if not net:
            return None
        bg = self.background.sample(min(self.split_samples, len(self.background)),
                                    random_state=self.random_state)
        x_full = self._row_frame([feats])
        removed = frozenset(p for p in players)
        if "other" in removed:
            removed = (removed - {"other"}) | {f for f in family_spans
                                               if f not in players and f not in NON_PLAYER_FAMILIES}
        x_nopay = self._row_frame([self._build(view, removed, family_spans)])

        def with_bg_network(x_one: pd.DataFrame) -> float:
            X = pd.concat([x_one] * len(bg), ignore_index=True)
            X[net] = bg[net].to_numpy()
            return float(self._proba(X)[:, self.attack_idx].mean())

        v_pn, v_n = p_attack, p_no_payload                      # network kept
        v_p, v_0 = with_bg_network(x_full), with_bg_network(x_nopay)  # network replaced
        phi_payload = 0.5 * ((v_p - v_0) + (v_pn - v_n))
        phi_network = 0.5 * ((v_n - v_0) + (v_pn - v_p))
        return {"base": v_0, "payload": float(phi_payload), "network": float(phi_network),
                "p_attack": float(p_attack), "network_features": net,
                "background_rows": int(len(bg))}

    # -- FIX P2: removal robustness + out-of-range check ------------------------
    def removal_robustness(self, view: RequestView, family_spans: dict, pss: dict) -> dict:
        """
        (a) Re-run PSS with the OTHER removal method (spaces vs delete) and compare the rankings.
        (b) Check how many coalition rows have feature values outside the background (training-like)
            range while the real request is inside it -> "unusual input" warning.
        """
        out: dict = {"checked": False}
        if self.custom_builder:
            out["note"] = "Custom feature builder: robustness check skipped."
            return out
        other = "delete" if self.removal == "blank" else "blank"
        _, pss_alt, _, _ = self.payload_span_shapley(view, family_spans, removal=other)
        out.update(checked=True, other_method=other, pss_other={k: float(v) for k, v in pss_alt.items()})
        if pss:
            top_a = max(pss, key=pss.get)
            top_b = max(pss_alt, key=pss_alt.get) if pss_alt else None
            out["top_agree"] = bool(top_a == top_b)
            keys = list(pss)
            if len(keys) >= 2:
                a = pd.Series([pss[k] for k in keys]).rank()
                b = pd.Series([pss_alt.get(k, 0.0) for k in keys]).rank()
                corr = a.corr(b)
                out["rank_corr"] = None if pd.isna(corr) else float(corr)
            else:
                out["rank_corr"] = 1.0
            out["top_overlap"] = self._jaccard(self._top_positive(pss), self._top_positive(pss_alt))
        if self.background is not None and self._last_coalition_X is not None:
            lo, hi = self.background.min(), self.background.max()
            Xc = self._last_coalition_X
            real = Xc.iloc[-1]                                  # last mask = all groups kept = real request
            real_inside = (real >= lo) & (real <= hi)
            outside = ((Xc < lo) | (Xc > hi)) & real_inside     # only count features the real request has in range
            rows_out = outside.any(axis=1)
            out["ood_fraction"] = float(rows_out.mean())
            out["ood_features"] = sorted({c for c in Xc.columns if outside[c].any()})
        return out

    @staticmethod
    def _regroup(values: dict | None, group_map: dict) -> dict | None:
        if values is None:
            return None
        out: dict = {}
        for k, v in values.items():
            g = group_map.get(k, k)
            out[g] = out.get(g, 0.0) + float(v)
        return out

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
        x_del = self._build(view, frozenset(families), family_spans)
        drop_top = p0 - float(self._proba(self._row_frame([x_del]))[0, self.attack_idx])
        n_chars = sum(e - s for f in families for s, e in family_spans[f])
        fixed = {i for s, e in family_spans.get("structure", []) for i in range(s, e)}  # never delete name= signs
        candidates = [i for i, ch in enumerate(view.text) if not ch.isspace() and i not in fixed]
        rows = []
        if n_chars and candidates:
            for _ in range(10):  # random-deletion baseline with the same character budget
                pick = self.rng.choice(candidates, size=min(n_chars, len(candidates)), replace=False)
                fake = {"__rand__": [(int(i), int(i) + 1) for i in pick]}
                rows.append(self._build(view, frozenset({"__rand__"}), fake))
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
        structure_spans = list(family_spans.get("structure", []))

        shap_vals = shap_family = lime_w = lime_family = None
        if use_shap:
            try:
                sv = self.shap_values(x)
                shap_vals = {f: float(v) for f, v in zip(self.feature_names, sv)}
                shap_family = self._regroup(self._by_family(shap_vals), self.group_map)
            except ImportError:
                messages.append("SHAP not installed (pip install shap) - feature-level SHAP skipped.")
            except Exception as exc:
                messages.append(f"SHAP failed: {type(exc).__name__}: {exc}")
        if use_lime:
            try:
                lime_w = self.lime_weights(x)
                lime_family = self._regroup(self._by_family(lime_w), self.group_map)
            except ImportError:
                messages.append("LIME not installed (pip install lime) - LIME skipped.")
            except Exception as exc:
                messages.append(f"LIME skipped: {type(exc).__name__}: {exc}")

        # FIX P5: payload vs network/size split
        decomposition = None
        try:
            decomposition = self.payload_network_split(view, feats, family_spans, players, p_attack, pss_base)
        except Exception as exc:
            messages.append(f"Payload/network split skipped: {type(exc).__name__}: {exc}")
        if decomposition is None:
            messages.append("Payload/network split needs a background sample (not available).")

        # FIX P2: second removal method + out-of-range check
        robustness = None
        if self.check_robustness:
            try:
                robustness = self.removal_robustness(view, family_spans, pss)
            except Exception as exc:
                messages.append(f"Robustness check skipped: {type(exc).__name__}: {exc}")

        techniques = detect_techniques(view)
        trust = self._trust(view, family_spans, pss, shap_family, lime_family, techniques, p_attack, pss_base,
                            is_attack, robustness)
        counterfactual = self._counterfactual(players, coalition_values, pss, family_spans, view, is_attack)
        priority = self._priority(p_attack, techniques, trust)
        if self.unknown_features:
            messages.append("Features not produced by the default builder (set to 0): " + ", ".join(self.unknown_features))
        if structure_spans:
            messages.append(f"{len(structure_spans)} parameter '=' sign(s) (name=) treated as normal request "
                            "structure: kept in every combination, not counted as SQL evidence.")

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
            decomposition=decomposition, robustness=robustness, n_players=len(players),
            structure_spans=structure_spans,
        )
        expl.narrative = build_narrative(expl)
        return expl

    def _trust(self, view, family_spans, pss, shap_family, lime_family, techniques, p_attack, pss_base,
               is_attack, robustness=None):
        # "syntax" (parentheses / comparison =) is left out of agreement checks: rules report
        # tautologies under "logic", so comparing it would punish correct explanations.
        rule_fams = {self.group_map.get(t["family"], t["family"]) for t in techniques} - {"syntax"}
        pss_top = self._top_positive({k: v for k, v in pss.items() if k != "syntax"})
        t = {"rule_families": sorted(rule_fams), "pss_top_families": sorted(pss_top)}
        # overlap coefficient: rules may flag many families while PSS keeps only the top 3
        t["rule_pss_agreement"] = (len(rule_fams & pss_top) / min(len(rule_fams), len(pss_top))
                                   if rule_fams and pss_top else (None if not rule_fams and not pss_top else 0.0))
        players = set(pss)
        content = lambda d: {k: v for k, v in (d or {}).items() if k in players and k != "syntax"}
        shap_top = self._top_positive(content(shap_family)) if shap_family else set()
        lime_top = self._top_positive(content(lime_family)) if lime_family else set()
        t["pss_shap_agreement"] = self._jaccard(pss_top, shap_top) if shap_family else None
        t["pss_lime_agreement"] = self._jaccard(pss_top, lime_top) if lime_family else None
        # share of the attack probability explained by payload evidence (vs network/size features)
        t["payload_share"] = float(np.clip((p_attack - pss_base) / p_attack, 0, 1)) if p_attack > 1e-9 else 0.0
        t["deletion_drop_shap_top"] = t["deletion_drop_lime_top"] = None
        if is_attack and pss_top:
            drop_top, drop_rand = self._deletion_test(view, family_spans, sorted(pss_top, key=lambda f: -pss[f]), p_attack)
            t["deletion_drop_top"], t["deletion_drop_random"] = drop_top, drop_rand
            t["fidelity_gain"] = float(np.clip((drop_top - drop_rand) / max(p_attack, 1e-9), -1, 1))
            # FIX P7: same deletion test using the groups SHAP / LIME rank highest -> fair comparison
            if shap_top:
                t["deletion_drop_shap_top"] = self._deletion_test(view, family_spans, sorted(shap_top), p_attack)[0]
            if lime_top:
                t["deletion_drop_lime_top"] = self._deletion_test(view, family_spans, sorted(lime_top), p_attack)[0]
        else:
            t["deletion_drop_top"] = t["deletion_drop_random"] = t["fidelity_gain"] = None
        # FIX P2: does the explanation survive a different removal method?
        r = robustness or {}
        t["removal_agreement"] = r.get("top_overlap") if r.get("checked") else None
        t["ood_fraction"] = r.get("ood_fraction")
        parts = [v for v in (t["rule_pss_agreement"], t["pss_shap_agreement"], t["pss_lime_agreement"],
                             t["removal_agreement"]) if v is not None]
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
    d = e.decomposition
    if d:
        lines.append(f"Split of P({e.attack_class}) = {d['p_attack']:.1%}: average-request baseline {d['base']:.1%}, "
                     f"SQL evidence in the payload {d['payload']:+.1%}, network/size features {d['network']:+.1%}.")
    else:
        share = e.trust.get("payload_share")
        if share is not None and e.is_attack:
            lines.append(f"About {share:.0%} of the attack probability comes from the payload text; "
                         f"the rest comes from size/network features.")
    if e.structure_spans:
        lines.append(f"{len(e.structure_spans)} normal parameter '=' sign(s) were not counted as SQL evidence.")
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
    r = e.robustness or {}
    if r.get("checked") and r.get("top_agree") is False:
        lines.append("Caution: the top evidence group changes when removed characters are deleted instead of "
                     "blanked, so the ranking is not robust.")
    if (r.get("ood_fraction") or 0) > 0.5:
        lines.append(f"Caution: {r['ood_fraction']:.0%} of the sanitised versions fall outside the background "
                     "feature range, so the model is being asked about unusual inputs.")
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
