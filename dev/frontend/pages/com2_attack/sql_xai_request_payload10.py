"""
SQL Injection XAI Dashboard
- Select records from SQL_injection_train_80.csv
- Train a local text classifier only when valid labelled examples are available
- Never invent predictions, confidence scores, SHAP values, or LIME weights
Run: python -m streamlit run sql_injection_xai_dashboard.py
"""
from __future__ import annotations

import html
import re
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit

import numpy as np
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SQL Injection XAI",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(r"D:\4Y1S\research\xai_iiot_prototype")
UNAVAILABLE = "Not available in dataset"
LABEL_CANDIDATES = [
    "attack_type", "attack type", "label", "class", "target",
    "attack_label", "attack label", "is_sqli", "sqli", "category",
]
TEXT_CANDIDATES = [
    "http.request.uri.query", "http.request_uri_query", "http.query",
    "query_string", "query", "http.request.full_uri", "http.request_full_uri",
    "http.request.uri", "http.request_uri", "url", "payload", "tcp.payload",
    "http.file_data", "raw_http_request", "http.request", "request",
]

st.markdown("""
<style>
.stApp {background:#0b1119;color:#e7eef7}
[data-testid="stHeader"] {background:transparent}
.block-container {max-width:1500px;padding-top:1.2rem}
.panel {background:#101b28;border:1px solid #26384c;border-radius:10px;padding:16px;margin-bottom:12px}
.panel-title {font-size:1.05rem;font-weight:750;border-bottom:1px solid #2b3e52;padding-bottom:10px;margin-bottom:10px}
.small-muted {color:#9fb2c7;font-size:.82rem}
.payload {background:#08111b;border:1px solid #385069;border-radius:8px;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;font-family:Consolas,monospace;font-size:.9rem}
.token {border:1px solid;border-radius:4px;padding:1px 3px;font-weight:700}
.metric-card {background:#101b28;border:1px solid #26384c;border-radius:9px;padding:13px;min-height:92px}
.metric-label {font-size:.76rem;color:#93a8bd;margin-bottom:8px}
.metric-value {font-size:1.15rem;font-weight:800;overflow-wrap:anywhere}
</style>
""", unsafe_allow_html=True)


def norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def get_col(df: pd.DataFrame, names: list[str]) -> str | None:
    lookup = {norm(c): c for c in df.columns}
    for name in names:
        if norm(name) in lookup:
            return lookup[norm(name)]
    return None


def usable(value: object) -> bool:
    if value is None or pd.isna(value):
        return False
    return str(value).strip().lower() not in {"", "nan", "none", "null", "0", "unknown"}


def row_value(row: pd.Series, names: list[str], default: str = UNAVAILABLE) -> str:
    col = get_col(pd.DataFrame(columns=row.index), names)
    if col is None:
        return default
    val = row[col]
    return str(val).strip() if usable(val) else default


def request_text(row: pd.Series) -> str:
    # Prefer query/payload fields. Fall back to URI/full URL, but never use a made-up sample.
    for name in TEXT_CANDIDATES:
        col = get_col(pd.DataFrame(columns=row.index), [name])
        if col is not None and usable(row[col]):
            value = str(row[col]).strip()
            if value and value.lower() not in {"0", "nan", "none", "null"}:
                return value
    return ""


def extract_query(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.query:
            return parsed.query
    except ValueError:
        pass
    return value.split("?", 1)[1].split("#", 1)[0] if "?" in value else ""


def make_request(row: pd.Series) -> dict[str, str]:
    full_url = row_value(row, ["http.request.full_uri", "http.request_full_uri", "http.full_uri", "full_uri", "url"], "")
    host = row_value(row, ["http.host", "http.host.header", "http_host", "host"], "")
    uri = row_value(row, ["http.request.uri", "http.request_uri", "request.uri", "http.uri", "uri"], "")
    url = full_url if full_url != "" else (f"http://{host}{uri}" if host and uri else uri or UNAVAILABLE)
    query = row_value(row, ["http.request.uri.query", "http.request_uri_query", "http.query", "query_string", "query"], "")
    if not query:
        query = extract_query(full_url) or extract_query(uri) or UNAVAILABLE
    return {
        "method": row_value(row, ["http.request.method", "http.request_method", "request.method", "method"]),
        "url": url,
        "query": query,
        "source_ip": row_value(row, ["ip.src_host", "ip.src", "source_ip", "src_ip"]),
        "destination_ip": row_value(row, ["ip.dst_host", "ip.dst", "destination_ip", "dst_ip"]),
        "user_agent": row_value(row, ["http.user_agent", "http.user_agent.header", "user_agent"]),
        "timestamp": row_value(row, ["frame.time", "timestamp", "datetime", "time"]),
    }


PATTERNS = {
    "Quote / string delimiter": re.compile(r"'|%27|%22|\"", re.I),
    "SQL keyword": re.compile(r"\b(select|union|insert|update|delete|drop|where|from|having|order\s+by)\b", re.I),
    "Logical operator": re.compile(r"\b(and|or)\b", re.I),
    "Boolean expression": re.compile(r"\b\d+\s*=\s*\d+\b|\bcase\s+when\b", re.I),
    "SQL comment": re.compile(r"--|/\*|\*/|#"),
    "Database function": re.compile(r"\b(chr|char|concat|xmltype|upper|substring|ascii|benchmark|sleep|pg_sleep)\s*\(", re.I),
    "Nested query": re.compile(r"\(\s*select\b", re.I),
}


def payload_evidence(payload: str) -> list[tuple[str, str, str]]:
    decoded = unquote_plus(payload)
    results = []
    for title, pattern in PATTERNS.items():
        matches = pattern.findall(decoded)
        if matches:
            examples = sorted({m if isinstance(m, str) else m[0] for m in matches}, key=str.lower)[:5]
            results.append((title, f"Matched {len(matches)} occurrence(s): {', '.join(examples)}", "Observed text indicator"))
    return results


def highlighted_html(payload: str) -> str:
    # HTML escape first. Highlight only regex-matched snippets in the decoded display string.
    text = html.escape(unquote_plus(payload), quote=False)
    pattern = re.compile(
        r"(?P<quote>'[^']*'|&quot;[^&]*&quot;)|"
        r"(?P<keyword>\b(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|WHERE|FROM|HAVING|ORDER\s+BY)\b)|"
        r"(?P<logic>\b(?:AND|OR)\b)|"
        r"(?P<function>\b(?:CHR|CHAR|XMLType|UPPER|SLEEP|PG_SLEEP|BENCHMARK)\s*\([^)]*\))|"
        r"(?P<boolean>\b\d+\s*=\s*\d+\b|\bCASE\s+WHEN\b)|"
        r"(?P<comment>--|/\*|\*/|#)",
        re.I,
    )
    colors = {"quote": "#ff626b", "keyword": "#35b8ff", "logic": "#f6a23a",
              "function": "#35d07f", "boolean": "#b77aff", "comment": "#e0b84d"}
    out, last = [], 0
    for match in pattern.finditer(text):
        out.append(text[last:match.start()])
        color = colors[match.lastgroup]
        out.append(f'<span class="token" style="color:{color};border-color:{color};background:{color}18">{match.group(0)}</span>')
        last = match.end()
    out.append(text[last:])
    return "".join(out)


def infer_label_column(df: pd.DataFrame) -> str | None:
    # Prefer descriptive class/type labels. Binary Attack_label can be used only as generic attack/benign.
    for candidate in ["attack_type", "attack type", "class", "label", "target", "category", "is_sqli", "sqli", "attack_label"]:
        col = get_col(df, [candidate])
        if col:
            return col
    return None


def label_kind(series: pd.Series, column: str) -> tuple[pd.Series | None, str]:
    clean = series.astype("string").str.strip()
    valid = clean.notna() & ~clean.str.lower().isin(["", "nan", "none", "null"])
    clean = clean[valid]
    unique = list(pd.unique(clean))
    if len(unique) < 2:
        return None, "The selected label column contains fewer than two classes."
    cname = norm(column)
    lower = {str(v).lower() for v in unique}
    if cname in {"attacklabel", "isattack", "malicious", "is malicious"} or lower.issubset({"0", "1", "true", "false"}):
        # A binary label only means SQLi if dataset documentation explicitly says so.
        mapped = clean.map(lambda x: "Attack" if str(x).lower() in {"1", "true"} else "Benign")
        return mapped, "Binary label interpreted as Attack vs Benign, not SQL injection specifically."
    return clean.astype(str), "Using the dataset's original class labels."


def get_training_data(df: pd.DataFrame, text_col: str, label_col: str):
    labels, label_note = label_kind(df[label_col], label_col)
    if labels is None:
        return None, None, label_note
    valid_mask = df[text_col].notna() & labels.index.isin(df.index)
    X = df.loc[valid_mask, text_col].astype(str).str.strip()
    y = labels.loc[X.index]
    keep = X.ne("") & ~X.str.lower().isin(["0", "nan", "none", "null"])
    X, y = X[keep], y[keep]
    counts = y.value_counts()
    if len(counts) < 2 or counts.min() < 2:
        return None, None, f"Need at least two examples per class for a stratified train/test split. Current counts: {counts.to_dict()}"
    return X, y, label_note


@st.cache_resource(show_spinner=False)
def fit_model(texts: tuple[str, ...], labels: tuple[str, ...]):
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

    X_train, X_test, y_train, y_test = train_test_split(
        list(texts), list(labels), test_size=0.25, random_state=42, stratify=list(labels)
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=1, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=1500, class_weight="balanced")),
    ])
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    p, r, f1, _ = precision_recall_fscore_support(y_test, pred, average="weighted", zero_division=0)
    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(p), "recall": float(r), "f1": float(f1),
        "test_size": len(y_test), "labels": list(model.classes_),
        "confusion": confusion_matrix(y_test, pred, labels=model.classes_).tolist(),
    }
    return model, metrics


def get_model_explanations(model, payload: str):
    """Return genuine SHAP and LIME explanations, or a clear dependency/error message."""
    shap_result, lime_result = None, None
    messages = []
    try:
        import shap
        # Linear model + text pipeline: explain the classifier in TF-IDF feature space.
        vectorizer = model.named_steps["tfidf"]
        classifier = model.named_steps["classifier"]
        matrix = vectorizer.transform([payload])
        feature_names = vectorizer.get_feature_names_out()
        class_index = list(classifier.classes_).index(model.predict([payload])[0])
        coefs = classifier.coef_[0] if len(classifier.classes_) == 2 else classifier.coef_[class_index]
        # SHAP LinearExplainer operates on dense arrays; cap dimensions to the strongest
        # non-zero local terms to avoid converting a huge sparse vocabulary to dense.
        row = matrix.tocsr()
        indices = row.indices
        if len(indices):
            chosen = sorted(indices, key=lambda i: abs(float(row[0, i] * coefs[i])), reverse=True)[:80]
            dense = np.asarray(row[:, chosen].toarray(), dtype=float)
            background = np.zeros_like(dense)
            explainer = shap.LinearExplainer(
                (np.asarray(coefs[chosen], dtype=float), np.zeros(len(chosen))),
                background,
            )
            values = np.asarray(explainer.shap_values(dense)).reshape(-1)
            shap_result = sorted(
                [(str(feature_names[chosen[i]]), float(values[i])) for i in range(len(chosen))],
                key=lambda item: abs(item[1]), reverse=True
            )[:12]
        else:
            messages.append("No non-zero TF-IDF features were produced for this payload.")
    except Exception as exc:
        messages.append(f"SHAP explanation unavailable: {type(exc).__name__}: {exc}")

    try:
        from lime.lime_text import LimeTextExplainer
        explainer = LimeTextExplainer(class_names=[str(c) for c in model.classes_], random_state=42)
        explanation = explainer.explain_instance(
            payload, model.predict_proba, num_features=10, num_samples=1000
        )
        lime_result = [(str(feature), float(weight)) for feature, weight in explanation.as_list()]
    except Exception as exc:
        messages.append(f"LIME explanation unavailable: {type(exc).__name__}: {exc}")
    return shap_result, lime_result, messages


# Dataset discovery: search known project folders, then ask the user to upload the requested CSV.
candidates = [
    PROJECT_ROOT / "data" / "SQL_injection_train_80.csv",
    APP_DIR / "data" / "SQL_injection_train_80.csv",
    APP_DIR / "SQL_injection_train_80.csv",
    APP_DIR.parent / "data" / "SQL_injection_train_80.csv",
    APP_DIR.parent / "SQL_injection_train_80.csv",
    Path.cwd() / "data" / "SQL_injection_train_80.csv",
    Path.cwd() / "SQL_injection_train_80.csv",
]
found = next((p for p in candidates if p.is_file()), None)

st.title("🛡️ SQL Injection Incident Analysis (XAI)")
st.caption("Dataset-driven request inspection, trained classification, and explainability. Model outputs appear only after a valid training run.")

with st.sidebar:
    st.header("Dataset & Model")
    if found:
        st.success(f"Found: {found}")
        use_upload = st.checkbox("Use a different CSV file", value=False)
    else:
        st.info("SQL_injection_train_80.csv was not found automatically. Upload it below.")
        use_upload = True
    uploaded = st.file_uploader("SQL injection dataset (CSV)", type=["csv"]) if use_upload else None
    st.caption("Training requires a usable label column and enough examples from at least two classes.")
    train_clicked = st.button("Train / retrain model", type="primary", use_container_width=True)

if uploaded is not None:
    try:
        df = pd.read_csv(uploaded, low_memory=False)
        dataset_name = uploaded.name
    except Exception as exc:
        st.error(f"Could not read uploaded CSV: {exc}")
        st.stop()
elif found:
    try:
        df = pd.read_csv(found, low_memory=False)
        dataset_name = found.name
    except Exception as exc:
        st.error(f"Could not read {found}: {exc}")
        st.stop()
else:
    st.warning("Upload SQL_injection_train_80.csv in the sidebar to continue.")
    st.stop()

if df.empty:
    st.error("The selected CSV is empty.")
    st.stop()

st.caption(f"Dataset: `{dataset_name}` · {len(df):,} rows · {len(df.columns):,} columns")
text_col = get_col(df, TEXT_CANDIDATES)
if text_col is None:
    st.error("No recognised HTTP query, URL, request, or payload column was found. Available columns are shown below; update TEXT_CANDIDATES if your dataset uses a different name.")
    st.dataframe(pd.DataFrame({"Available columns": df.columns}), use_container_width=True)
    st.stop()

label_col = infer_label_column(df)
if label_col:
    st.caption(f"Detected label column: `{label_col}`")
else:
    st.warning("No recognised label column was found. Request evidence can still be inspected, but supervised model training and model explanations are unavailable.")

# Keep a per-session model only for the current dataset signature.
signature = f"{dataset_name}:{len(df)}:{','.join(map(str, df.columns))}:{label_col}:{text_col}"
if st.session_state.get("model_signature") != signature:
    st.session_state.pop("model", None)
    st.session_state.pop("metrics", None)
    st.session_state.pop("label_note", None)
    st.session_state["model_signature"] = signature

if train_clicked:
    if not label_col:
        st.error("Training stopped: no label column is available.")
    else:
        X, y, note = get_training_data(df, text_col, label_col)
        if X is None:
            st.error(f"Training stopped: {note}")
        else:
            with st.spinner("Training and evaluating a TF-IDF + Logistic Regression baseline..."):
                try:
                    trained, metrics = fit_model(tuple(X.tolist()), tuple(y.astype(str).tolist()))
                    st.session_state["model"] = trained
                    st.session_state["metrics"] = metrics
                    st.session_state["label_note"] = note
                    st.success("Training and hold-out evaluation completed.")
                except Exception as exc:
                    st.error(f"Training failed: {type(exc).__name__}: {exc}")

# Record selection; index selection is from the loaded CSV, never a synthetic record.
record_idx = st.selectbox(
    "Select dataset record",
    options=list(range(len(df))),
    format_func=lambda i: f"Row {i} · source index {df.index[i]}",
)
row = df.iloc[int(record_idx)]
req = make_request(row)
payload = request_text(row)
if payload:
    # If the selected source is a URL, display its query when available, otherwise the actual source value.
    payload_query = extract_query(payload)
    display_payload = payload_query if payload_query else payload
else:
    display_payload = ""

model = st.session_state.get("model")
metrics = st.session_state.get("metrics")
prediction = None
confidence = None
probabilities = None
if model is not None and payload:
    try:
        prediction = str(model.predict([payload])[0])
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba([payload])[0]
            confidence = float(np.max(probabilities))
    except Exception as exc:
        st.warning(f"Prediction unavailable for this record: {type(exc).__name__}: {exc}")

# Overview metrics
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Selected record</div><div class="metric-value">#{int(record_idx)}</div></div>', unsafe_allow_html=True)
with c2:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Model prediction</div><div class="metric-value">{html.escape(prediction or "Not available")}</div></div>', unsafe_allow_html=True)
with c3:
    conf_text = f"{confidence:.1%}" if confidence is not None else "Not available"
    st.markdown(f'<div class="metric-card"><div class="metric-label">Model confidence</div><div class="metric-value">{conf_text}</div></div>', unsafe_allow_html=True)
with c4:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Payload availability</div><div class="metric-value">{"Available" if payload else "Missing"}</div></div>', unsafe_allow_html=True)

if metrics:
    st.subheader("Training evaluation (hold-out set)")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Accuracy", f"{metrics['accuracy']:.3f}")
    m2.metric("Precision", f"{metrics['precision']:.3f}")
    m3.metric("Recall", f"{metrics['recall']:.3f}")
    m4.metric("F1-score", f"{metrics['f1']:.3f}")
    st.caption(f"Test records: {metrics['test_size']}. Label interpretation: {st.session_state.get('label_note', '')}")
    with st.expander("Confusion matrix and class order"):
        st.write("Class order:", metrics["labels"])
        st.dataframe(pd.DataFrame(metrics["confusion"], index=metrics["labels"], columns=metrics["labels"]))

left, right = st.columns([1, 1.05], gap="medium")
with left:
    st.markdown('<div class="panel"><div class="panel-title">▤ HTTP Request Details</div>', unsafe_allow_html=True)
    for label, value in [
        ("Method", req["method"]), ("URL", req["url"]), ("Query string", req["query"]),
        ("Source IP", req["source_ip"]), ("Destination IP", req["destination_ip"]),
        ("User-Agent", req["user_agent"]), ("Timestamp", req["timestamp"]),
    ]:
        st.markdown(f"**{label}**  \n{value}")
        st.divider()
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="panel"><div class="panel-title">⌕ Evidence & Justification</div>', unsafe_allow_html=True)
    if payload:
        evidence = payload_evidence(payload)
        if evidence:
            for title, desc, severity in evidence:
                st.markdown(f"**{title}**  \n{desc}  \n<small class='small-muted'>Text pattern only — not proof of successful exploitation.</small>", unsafe_allow_html=True)
                st.divider()
        else:
            st.info("No configured SQLi indicators were found in the selected payload. This does not prove the request is benign.")
    else:
        st.warning("No usable request/query/payload text exists in this record. Evidence analysis is unavailable.")
    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.markdown('<div class="panel"><div class="panel-title">&lt;/&gt; Payload with Highlighted Indicators</div>', unsafe_allow_html=True)
    if display_payload:
        st.markdown(f'<div class="payload">{highlighted_html(display_payload)}</div>', unsafe_allow_html=True)
        st.caption("Highlighting is a rule-based view of text indicators, separate from the ML prediction.")
    else:
        st.info("This dataset record has no usable request payload. The dashboard will not insert a demonstration payload.")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="panel"><div class="panel-title">▥ Model Explanation (SHAP)</div>', unsafe_allow_html=True)
    if model is None:
        st.info("Train the model first. SHAP values are not displayed until a real model is trained and a payload is available.")
    elif not payload:
        st.info("No payload is available for this row, so a local SHAP explanation cannot be generated.")
    else:
        with st.spinner("Calculating SHAP explanation..."):
            shap_result, lime_result, explanation_messages = get_model_explanations(model, payload)
        if shap_result:
            st.caption("Top local feature contributions in the TF-IDF model feature space. Positive/negative values are relative to the selected model output; inspect the class semantics before interpreting direction.")
            shap_df = pd.DataFrame(shap_result, columns=["Text feature (n-gram)", "SHAP value"])
            st.bar_chart(shap_df.set_index("Text feature (n-gram)")["SHAP value"])
            st.dataframe(shap_df, use_container_width=True, hide_index=True)
        else:
            st.warning("A SHAP explanation could not be produced for this model/request.")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="panel"><div class="panel-title">⌁ Local Explanation (LIME)</div>', unsafe_allow_html=True)
    if model is None:
        st.info("Train the model first. LIME weights are not displayed before a real prediction model exists.")
    elif not payload:
        st.info("No payload is available for this row, so a local LIME explanation cannot be generated.")
    else:
        # Reuse explanations computed above when available; otherwise compute explicitly.
        if "lime_result" not in locals():
            with st.spinner("Calculating LIME explanation..."):
                _, lime_result, explanation_messages = get_model_explanations(model, payload)
        if lime_result:
            lime_df = pd.DataFrame(lime_result, columns=["Text segment", "LIME weight"])
            st.bar_chart(lime_df.set_index("Text segment")["LIME weight"])
            st.dataframe(lime_df, use_container_width=True, hide_index=True)
        else:
            st.warning("A LIME explanation could not be produced for this model/request.")
        if "explanation_messages" in locals() and explanation_messages:
            with st.expander("Explainability diagnostics"):
                for message in explanation_messages:
                    st.write(message)
    st.markdown("</div>", unsafe_allow_html=True)

if prediction is None:
    st.warning("No ML prediction is shown. Select a record with a usable payload and train a model using a valid labelled dataset.")
elif st.session_state.get("label_note", "").startswith("Binary label"):
    st.info("The model predicts the dataset's generic Attack/Benign label. It must not be described as a SQL-injection-specific detector unless the dataset labels establish that meaning.")

with st.expander("Dataset row (raw values)"):
    st.dataframe(row.to_frame(name="Selected value"), use_container_width=True)
