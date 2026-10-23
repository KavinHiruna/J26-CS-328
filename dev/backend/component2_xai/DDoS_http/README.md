# DDoS HTTP Flood — XAI (Component 2)

Binary detector (Normal vs. DDoS HTTP Flood) for Edge-IIoTset packet records,
with explanations at three levels:

| Level | Method | Where in the dashboard |
|---|---|---|
| Per packet | SHAP TreeExplainer (falls back to exact tree-path contributions if `shap` is missing) | Packet Explanation → waterfall + plain-language "Why?" |
| Per packet | LIME local surrogate | Packet Explanation → LIME |
| Per packet | Global surrogate's IF-THEN path | Packet Explanation → Surrogate rule |
| Global | Mean \|SHAP\|, beeswarm, dependence plots | Global Explainability |
| Global | Gini vs. permutation vs. SHAP importance agreement | Global Explainability |
| Global | Depth-4 surrogate decision tree (with fidelity score) | Global Explainability |

## ★ Novelty — Multi-method XAI Consensus

Each packet is explained by four independent methods — SHAP (or exact
tree-path contributions), LIME, occlusion against typical-normal values, and
the global surrogate tree. `consensus.py` measures how much they agree and
produces an **XAI Consensus Score (XCS)** in [0, 1]:

| Component | Meaning |
|---|---|
| Rank agreement | mean pairwise Spearman ρ of \|attributions\| over each pair's top features |
| Top-k overlap | mean pairwise overlap of each method's top-5 features |
| Direction agreement | share of method votes matching the majority sign (→ flood / → normal) on the consensus top-5 |
| Verdict agreement | share of surrogate / LIME-local verdicts matching the Random Forest |

XCS = 0.25 × each component (weights in `config.CONSENSUS_WEIGHTS`).
Trust: **High** ≥ 0.75 (safe to automate), **Medium** ≥ 0.50 (corroborate),
**Low** < 0.50 (escalate to an analyst).

The dashboard tab "🤝 XAI Consensus ★ Novelty" shows the per-packet score,
method-by-feature heatmap and consensus explanation; triages all flagged
traffic by trust level; and evaluates on held-out packets whether low XCS
identifies the model's misclassifications (error-detection AUROC).

## Folder layout

```
dev/
├── backend/component2_xai/DDoS_http/
│   ├── config.py        paths, dropped columns, hyper-parameters
│   ├── data_loader.py   reads Edge-IIoTset CSVs, keeps Normal + DDoS_HTTP rows, de-duplicates
│   ├── features.py      FeatureEncoder (numeric / hex / categorical columns)
│   ├── xai_methods.py   SHAP, tree-path contributions, LIME, surrogate tree
│   ├── consensus.py     ★ novelty: multi-method XAI consensus score
│   ├── train.py         training + evaluation + global explanations -> artifacts/
│   ├── service.py       DDoSHttpXAI class used by the dashboard
│   └── artifacts/       created by train.py
└── frontend/pages/com2_attack/ddos_http.py   Streamlit dashboard
```

## 1. Install

```bash
pip install -r backend/component2_xai/DDoS_http/requirements.txt
```

## 2. Train (needs real DDoS HTTP Flood data)

The per-sensor CSVs (Distance, Heart_Rate, Modbus, …) contain **only Normal traffic**.
Add the attack file from Edge-IIoTset `Attack traffic/DDoS_HTTP_Flood_attack.csv`
(or use `DNN-EdgeIIoT-dataset.csv`, which contains both classes).

From `D:\4Y1S\research\J26-CS-328\dev\backend`:

```bat
python -m component2_xai.DDoS_http.train --data ^
  "D:\path\to\Edge-IIoTset\Normal traffic" ^
  "D:\path\to\Edge-IIoTset\Attack traffic\DDoS_HTTP_Flood_attack.csv"
```

`--data` takes any mix of files and folders; rows that are not `Normal` or
`DDoS_HTTP` are ignored.

Preprocessing follows the Edge-IIoTset paper: the paper's identifier/payload
columns are dropped (IPs, ports, timestamps, URIs, payloads), plus raw TCP
sequence numbers and checksums; duplicates are removed; text and hex fields are
encoded consistently for training and inference.

## 3. Run the dashboard

From `dev/`:

```bash
streamlit run frontend/pages/com2_attack/ddos_http.py
```

or open it from your multipage app. Use **Sample test traffic** (held-out
packets saved at training time) or upload any CSV with the Edge-IIoTset columns.

## Using the backend directly

```python
from component2_xai.DDoS_http import DDoSHttpXAI
xai = DDoSHttpXAI()
scored = xai.predict(raw_df)            # attack_probability, prediction, risk_level
exp = xai.explain(raw_df.iloc[[0]])     # contributions + narrative
lime = xai.explain_lime(raw_df.iloc[[0]])
```
