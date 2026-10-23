"""
Component 2 - Web Injection XAI (SQL injection · XSS · Uploading)  (BACKEND, UI-independent)

FILE LOCATION : dev/backend/component2_xai/web_injection_xai.py
USED BY       : frontend/pages/com2_attack/sqli_xai_novelty_page.py (Web Injection dashboard)
                backend/component2_xai/model/train_web_injection_rf.py (training)

Extends the SQLi engine (sqli_xai_engine.py) to the three web-injection attacks:

  * one feature builder = the 54 SQLi features + XSS features + upload features,
    computed from the same RequestView, so the SQLi Payload-Span Shapley still works;
  * label rules for EdgeIIoT exports that only have the binary Attack_label;
  * a multi-class model adapter so SQLiXAIEngine can explain P(SQL injection) of the
    multi-class model (PSS, trust score, counterfactual) without any change;
  * a payload inspector that highlights SQL / XSS / upload evidence in the request;
  * rule-based technique cards for XSS (CWE-79) and malicious upload (CWE-434).
"""
from __future__ import annotations

import html
import re

import numpy as np
import pandas as pd

import sqli_xai_engine as X

# ---------------------------------------------------------------------------
# Classes
# ---------------------------------------------------------------------------
OTHER = "Other"                       # not a web-injection request (benign or another attack)
SQLI, XSS, UPLOAD = "SQL_injection", "XSS", "Uploading"
ATTACK_TYPES = [SQLI, XSS, UPLOAD]
CLASSES = [OTHER] + ATTACK_TYPES
DISPLAY = {OTHER: "Not web injection", SQLI: "SQL injection", XSS: "XSS", UPLOAD: "Malicious upload"}

# ---------------------------------------------------------------------------
# Label rules (EdgeIIoT_train_80 has only Attack_label 0/1)
#   SQLi   : attack + URI targets DVWA's SQLi pages (same rule as sql_model_card.json)
#   XSS    : attack + script / event-handler / javascript: payload in the request
#   Upload : attack + request to the DVWA upload directory or upload page
#            (in this capture: executing the uploaded web shell hackable/uploads/hack.php)
# ---------------------------------------------------------------------------
LABEL_SQLI = r"/vulnerabilities/sqli"
LABEL_XSS = r"<\s*/?\s*script|%3c\s*script|javascript\s*:|\bon(?:error|load|mouseover)\s*=|/vulnerabilities/xss"
LABEL_UPLOAD = r"/hackable/uploads/|/vulnerabilities/upload"


def web_labels(df: pd.DataFrame) -> pd.Series | None:
    """Class name per row, or None when the file lacks Attack_label / request columns."""
    if "Attack_label" not in df.columns or "http.request.full_uri" not in df.columns:
        return None
    attack = pd.to_numeric(df["Attack_label"], errors="coerce").fillna(0).astype(int) == 1
    uri = df["http.request.full_uri"].astype(str)
    text = uri
    for c in ("http.request.uri.query", "http.file_data"):
        if c in df.columns:
            text = text + " " + df[c].astype(str)
    y = pd.Series(OTHER, index=df.index)
    y[attack & uri.str.contains(LABEL_UPLOAD, case=False, regex=True)] = UPLOAD
    y[attack & text.str.contains(LABEL_XSS, case=False, regex=True)] = XSS
    y[attack & uri.str.contains(LABEL_SQLI, case=False, regex=True)] = SQLI   # most specific wins
    return y


# ---------------------------------------------------------------------------
# Extra features: (regex, kind, family) like sqli_xai_engine.CONTENT_RULES
# ---------------------------------------------------------------------------
XSS_RULES = {
    "xss_script_tag": (r"<\s*/?\s*script\b", "count", "xss"),
    "xss_event_handler": (r"\bon(?:error|load|mouseover|focus|click|submit)\s*=", "flag", "xss"),
    "xss_js_uri": (r"javascript\s*:", "flag", "xss"),
    "xss_html_tag": (r"<\s*(?:img|iframe|svg|body|input|object|embed|a)\b", "flag", "xss"),
    "xss_dom_sink": (r"document\.(?:cookie|location|write)|\balert\s*\(|window\.location|\beval\s*\(", "flag", "xss"),
    "xss_angle_brackets": (r"[<>]", "count", "xss"),
}
UPLOAD_PATH_RULES = {   # matched on the request path (URI without query)
    "upload_dir": (r"/(?:hackable/)?uploads?/|/upload(?:s|ed)?(?:\.|/|$)", "flag", "upload"),
    "exec_extension": (r"\.(?:php\d?|phtml|asp|aspx|jsp|cgi|pl|sh|py)$", "flag", "upload"),
}
UPLOAD_BODY_RULES = {   # matched on the request body
    "multipart_body": (r"multipart/form-data|content-disposition", "flag", "upload"),
    "server_code_in_body": (r"<\?php|\beval\s*\(|\bsystem\s*\(|\bshell_exec\b|base64_decode", "flag", "upload"),
}
_XSS = {k: (re.compile(p, re.I), kind) for k, (p, kind, _f) in XSS_RULES.items()}
_UP_PATH = {k: re.compile(p, re.I) for k, (p, _k, _f) in UPLOAD_PATH_RULES.items()}
_UP_BODY = {k: re.compile(p, re.I) for k, (p, _k, _f) in UPLOAD_BODY_RULES.items()}
EXTRA_FEATURES = list(XSS_RULES) + list(UPLOAD_PATH_RULES) + list(UPLOAD_BODY_RULES) + ["body_length"]
WEB_FEATURES = list(X.DEFAULT_SQL_FEATURES) + EXTRA_FEATURES

# Register the new features with the SQLi engine so feature_family()/labels know them.
# (They are not Payload-Span Shapley players; PSS stays over the SQL evidence groups.)
X.OTHER_FAMILIES.update({f: "xss" for f in XSS_RULES})
X.OTHER_FAMILIES.update({f: "upload" for f in list(UPLOAD_PATH_RULES) + list(UPLOAD_BODY_RULES) + ["body_length"]})
X.FAMILY_LABELS.setdefault("xss", "XSS markup / script")
X.FAMILY_LABELS.setdefault("upload", "Upload path / file content")


def _path(uri: str) -> str:
    m = re.match(r"(?:https?://[^/]+)?(/[^?#]*)", uri.strip())
    return m.group(1) if m else ""


def _segment(view: X.RequestView, label: str) -> str:
    for name, s, e in view.segments:
        if name == label:
            return view.text[s:e]
    return ""


def web_feature_builder(view: X.RequestView, removed_families: frozenset = frozenset(),
                        family_spans: dict | None = None) -> dict[str, float]:
    """SQLi features (with PSS sanitisation) + XSS + upload features from the same request view."""
    vals = X.default_feature_builder(view, removed_families, family_spans)
    text = view.text
    if removed_families and family_spans:
        text = X.blank_spans(text, [s for f in removed_families for s in family_spans.get(f, [])])
    for name, (rx, kind) in _XSS.items():
        vals[name] = float(len(rx.findall(text))) if kind == "count" else float(bool(rx.search(text)))
    path = _path(view.uri)
    for name, rx in _UP_PATH.items():
        vals[name] = float(bool(rx.search(path)))
    body = _segment(view, "Body")
    for name, rx in _UP_BODY.items():
        vals[name] = float(bool(rx.search(body)))
    vals["body_length"] = float(len(body))
    return vals


def build_matrix(df: pd.DataFrame, feature_names=WEB_FEATURES) -> pd.DataFrame:
    res = X.ColumnResolver(df.columns)
    rows = [web_feature_builder(res.view(r)) for r in df.to_dict("records")]
    return pd.DataFrame([[r.get(f, 0.0) for f in feature_names] for r in rows], columns=list(feature_names), dtype=float)


# ---------------------------------------------------------------------------
# Multi-class model -> binary "class vs rest" view for SQLiXAIEngine
# ---------------------------------------------------------------------------
class ClassVsRest:
    """Wraps a multi-class classifier so P(one class) looks like a binary model [rest, class]."""

    def __init__(self, model, cls):
        self.model = model
        self.cls = cls
        self.idx = list(model.classes_).index(cls)
        # readable names: the SQLi engine prints them in its narrative and JSON
        self.classes_ = np.array([f"Not {DISPLAY.get(cls, cls)}", DISPLAY.get(cls, cls)])
        self.n_features_in_ = getattr(model, "n_features_in_", None)
        self.feature_importances_ = getattr(model, "feature_importances_", None)

    def predict_proba(self, X_):
        p = np.asarray(self.model.predict_proba(X_))[:, self.idx]
        return np.column_stack([1 - p, p])


def class_shap(explainer, x: pd.DataFrame, cls_idx: int) -> np.ndarray:
    """SHAP values of one class for every row of x, from a shap.TreeExplainer of the multi-class model."""
    vals = explainer.shap_values(x)
    if isinstance(vals, list):
        return np.asarray(vals[cls_idx])
    vals = np.asarray(vals)
    return vals[:, :, cls_idx] if vals.ndim == 3 else vals


class WebSQLiEngine(X.SQLiXAIEngine):
    """SQLiXAIEngine whose SHAP uses the fast TreeExplainer of the wrapped multi-class forest."""

    def shap_values(self, x: pd.DataFrame) -> np.ndarray:
        import shap  # optional dependency
        if self._tree_explainer is None:
            self._tree_explainer = shap.TreeExplainer(self.model.model)
        return class_shap(self._tree_explainer, x, self.model.idx)[0]


def make_sqli_engine(model, feature_names, background=None, threshold=0.5) -> X.SQLiXAIEngine:
    """SQLi evidence engine (PSS, trust, counterfactual) over the multi-class model's P(SQLi)."""
    return WebSQLiEngine(ClassVsRest(model, SQLI), feature_names=feature_names, background=background,
                         attack_class=DISPLAY[SQLI], threshold=threshold, feature_builder=web_feature_builder)


# ---------------------------------------------------------------------------
# Pre-filter, payload inspector and technique cards
# ---------------------------------------------------------------------------
CANDIDATE_PATTERN = X.CANDIDATE_PATTERN[:-1] + r"|<\s*script|%3cscript|javascript:|onerror=|upload)"


def candidate_mask(df: pd.DataFrame) -> pd.Series:
    """Rows whose request text looks SQL-, XSS- or upload-related. A fast filter, not a classifier."""
    res = X.ColumnResolver(df.columns)
    cols = [c for c in res.target + res.body + [res.query, res.referer] if c]
    mask = pd.Series(False, index=df.index)
    for c in dict.fromkeys(cols):
        mask |= df[c].astype("string").str.contains(CANDIDATE_PATTERN, regex=True, na=False)
    return mask


INSPECT_COLORS = {"sql": "#e04848", "xss": "#e08a00", "upload": "#7c3aed"}
_INSPECT = (
    [("sql", rx) for name, (rx, _k, fam) in X.COMPILED_RULES.items()
     if fam not in ("syntax", "logic")]                         # '=' and 'and/or' are everywhere
    + [("xss", rx) for rx, _k in _XSS.values() if rx.pattern != "[<>]"]
    + [("upload", re.compile(r"/(?:hackable/)?uploads?/[^\s?]*|[\w.-]+\.(?:php\d?|phtml|asp|aspx|jsp|cgi)\b", re.I))]
    + [("upload", rx) for rx in _UP_BODY.values()]
)


def inspect_spans(view: X.RequestView) -> list[tuple[int, int, str]]:
    spans = []
    for kind, rx in _INSPECT:
        for m in rx.finditer(view.text):
            if m.groups():
                spans.extend((m.start(g), m.end(g), kind) for g in range(1, len(m.groups()) + 1) if m.group(g))
            else:
                spans.append((m.start(), m.end(), kind))
    return sorted(spans)


def render_inspector_html(view: X.RequestView) -> str:
    """Request text with SQL (red), XSS (amber) and upload (purple) evidence highlighted."""
    text = view.display_text
    kinds = [None] * len(text)
    for s, e, kind in inspect_spans(view):
        for i in range(s, min(e, len(text))):
            kinds[i] = kinds[i] or kind
    out, i = [], 0
    while i < len(text):
        j = i + 1
        while j < len(text) and kinds[j] == kinds[i] and text[j] != "\n":
            j += 1
        chunk = html.escape(text[i:j])
        k = kinds[i]
        out.append(f'<span title="{k} evidence" style="background:{INSPECT_COLORS[k]}33;border-bottom:2px solid '
                   f'{INSPECT_COLORS[k]};border-radius:3px">{chunk}</span>' if k and text[i] != "\n" else chunk)
        i = j
    return "".join(out).replace("\n", "<br>") or "<i>(no HTTP request text in this record)</i>"


WEB_TECHNIQUES = [
    # key, label, regex, where, severity, cwe, capec, recommendation
    ("xss_reflected", "Reflected XSS - script injection", r"<\s*script\b[^>]*>", "text", 0.75, "CWE-79", "CAPEC-63",
     "Encode output for the HTML context and set a Content-Security-Policy; check whether the payload was reflected."),
    ("xss_event", "XSS via event handler / HTML tag", r"<\s*(?:img|svg|iframe|body|input)\b[^>]*\bon\w+\s*=", "text",
     0.75, "CWE-79", "CAPEC-63", "Strip event-handler attributes from user input; use a vetted HTML sanitiser."),
    ("xss_js_uri", "XSS via javascript: URI", r"javascript\s*:", "text", 0.65, "CWE-79", "CAPEC-63",
     "Allow only http/https URLs in user-supplied links."),
    ("xss_cookie", "Session theft attempt (document.cookie)", r"document\.cookie", "text", 0.85, "CWE-79", "CAPEC-63",
     "Set HttpOnly on session cookies and rotate sessions of users who loaded this page."),
    ("webshell_exec", "Web shell execution from upload directory",
     r"/(?:hackable/)?uploads?/[^?\s]*\.(?:php\d?|phtml|asp|aspx|jsp|cgi)", "path", 0.95, "CWE-434", "CAPEC-650",
     "Remove the file, block script execution in the upload directory and look for earlier upload POSTs."),
    ("upload_probe", "Upload endpoint probing", r"upload", "path", 0.45, "CWE-434", "CAPEC-650",
     "Restrict upload endpoints to authenticated users; validate file type by content, not name."),
    ("server_code", "Server-side code in request body", r"<\?php|\beval\s*\(|\bsystem\s*\(|base64_decode", "body",
     0.90, "CWE-434", "CAPEC-650", "Treat as an attempted web-shell upload; inspect the stored file and server logs."),
]
_WEB_TECH = [(k, l, re.compile(p, re.I), w, s, c, cap, r) for k, l, p, w, s, c, cap, r in WEB_TECHNIQUES]


def detect_web_techniques(view: X.RequestView) -> list[dict]:
    """XSS / upload technique cards (same dict shape as sqli_xai_engine.detect_techniques)."""
    where = {"text": view.text, "path": _path(view.uri).lower(), "body": _segment(view, "Body")}
    found = []
    for key, label, rx, w, sev, cwe, capec, rec in _WEB_TECH:
        m = rx.search(where[w])
        if not m:
            continue
        if key == "upload_probe" and any(f["key"] == "webshell_exec" for f in found):
            continue
        found.append({"key": key, "technique": label, "family": "xss" if cwe == "CWE-79" else "upload",
                      "severity": sev, "cwe": cwe, "capec": capec, "attack": "T1190" if cwe == "CWE-79" else "T1505.003",
                      "evidence": m.group(0)[:80], "matches": len(rx.findall(where[w])), "recommendation": rec})
    return sorted(found, key=lambda t: -t["severity"])


def all_techniques(view: X.RequestView) -> list[dict]:
    return sorted(X.detect_techniques(view) + detect_web_techniques(view), key=lambda t: -t["severity"])
