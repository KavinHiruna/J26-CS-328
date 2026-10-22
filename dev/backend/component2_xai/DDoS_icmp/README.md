# Component 2 – DDoS ICMP Flood XAI (backend)

| File | Purpose |
|---|---|
| `config.py` | Parameter-sheet features, domain rules, severity bands, **Component 2 novelty text** |
| `features.py` | Edge-IIoTset CSV -> ICMP flood features (ip.proto, icmp.type/code, frame.len, time delta, pkt/s, B/s, flow stats, TTL, unique sources, source concentration) |
| `model.py` | `ModelAdapter` (bundle / bare model / Pipeline + optional feature or label encoder), `train_model` |
| `explain.py` | SHAP (Tree/Kernel, Shapley-sampling fallback) and LIME (LIME-style surrogate fallback) |
| `novelty.py` | N1 consensus, N2 knowledge-grounded alignment, N3 counterfactual, N4 DDoS-vs-DoS, N5 severity/mitigation/narrative |
| `incident.py` | Scoring, search syntax, single-incident report, JSON/Markdown export |
| `demo_data.py` | Synthetic ICMP floods for demos only (rows flagged `synthetic=1`) |
| `train.py` | CLI training |
| `models/ddos_icmp_model.joblib` | **Demo** model (trained on synthetic floods) – replace it |

Train on the real data (run inside `dev/backend`):

```
python -m component2_xai.DDoS_icmp.train --csv "<Edge-IIoTset>/Attack traffic/DDoS_ICMP_Flood_attack.csv" --csv "<normal>/Distance.csv" --csv "<normal>/Flame_Sensor.csv"
```

Run the dashboard: `streamlit run frontend/pages/com2_attack/ddos_icmp.py` (or open it from your multipage app).
Requirements: `streamlit>=1.30 pandas numpy scikit-learn joblib plotly shap lime`
