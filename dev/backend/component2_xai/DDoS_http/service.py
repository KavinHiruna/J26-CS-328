"""
Runtime service used by the Streamlit dashboard (and optionally a REST API).

    from component2_xai.DDoS_http import DDoSHttpXAI
    xai = DDoSHttpXAI()                       # loads artifacts/
    scored = xai.predict(raw_df)              # per-packet verdicts
    exp = xai.explain(raw_df.iloc[[0]])       # SHAP / tree-path explanation
    lime = xai.explain_lime(raw_df.iloc[[0]]) # LIME explanation
"""
from __future__ import annotations

import json
from functools import cached_property

import joblib
import numpy as np
import pandas as pd

from . import config
from .data_loader import derive_attack_type
from .features import FeatureEncoder
from . import consensus as xcs
from .xai_methods import HAS_LIME, HAS_SHAP, describe_split, lime_explain, local_attributions


class ModelNotTrainedError(RuntimeError):
    pass


class DDoSHttpXAI:
    def __init__(self, threshold: float = 0.5):
        if not config.MODEL_PATH.exists():
            raise ModelNotTrainedError(
                f"No trained model at {config.MODEL_PATH}. Run:\n"
                "  python -m component2_xai.DDoS_http.train --data <Edge-IIoTset CSVs>")
        self.threshold = threshold
        self.attack_class = 1        # model class meaning "DDoS HTTP flood"
        self.use_shap = True         # False -> exact tree-path contributions
        self.model = joblib.load(config.MODEL_PATH)
        self.encoder: FeatureEncoder = joblib.load(config.ENCODER_PATH)
        self.surrogate = joblib.load(config.SURROGATE_PATH)
        self.background: pd.DataFrame = joblib.load(config.BACKGROUND_PATH)
        self.metrics = json.loads(config.METRICS_PATH.read_text())
        self.global_xai = json.loads(config.GLOBAL_XAI_PATH.read_text())
        self.baselines = json.loads(config.BASELINE_PATH.read_text())
        self._shap_explainer = None

    # ----------------------------------------------------------- properties
    @property
    def feature_names(self) -> list[str]:
        return self.encoder.feature_names

    @property
    def capabilities(self) -> dict:
        return {"shap": HAS_SHAP, "lime": HAS_LIME,
                "attribution_method": "SHAP (TreeExplainer)" if HAS_SHAP and self.use_shap
                else "Tree-path contributions"}

    @property
    def attack_idx(self) -> int:
        return list(self.model.classes_).index(self.attack_class)

    @cached_property
    def shap_sample(self) -> dict:
        d = np.load(config.SHAP_SAMPLE_PATH, allow_pickle=False)
        return {"X": pd.DataFrame(d["X"], columns=[str(f) for f in d["features"]]),
                "values": d["values"], "y": d["y"], "base": float(d["base"][0]),
                "method": str(d["method"][0])}

    def sample_traffic(self) -> pd.DataFrame:
        return pd.read_csv(config.SAMPLE_TRAFFIC_PATH, low_memory=False, dtype=str)

    def _shap(self):
        if HAS_SHAP and self.use_shap and self._shap_explainer is None:
            import shap
            self._shap_explainer = shap.TreeExplainer(self.model)
        return self._shap_explainer

    # ---------------------------------------------------------- prediction
    def encode(self, raw: pd.DataFrame) -> pd.DataFrame:
        raw = raw.copy()
        raw.columns = [c.strip() for c in raw.columns]
        return self.encoder.transform(raw)

    def predict(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Score raw Edge-IIoTset rows. Returns one row per packet."""
        X = self.encode(raw)
        proba = self.model.predict_proba(X)[:, self.attack_idx]
        out = pd.DataFrame({
            "attack_probability": proba,
            "prediction": np.where(proba >= self.threshold, config.CLASS_NAMES[1], config.CLASS_NAMES[0]),
            "is_attack": proba >= self.threshold,
        }, index=raw.index)
        out["risk_level"] = pd.cut(proba, [-0.01, 0.3, 0.5, 0.8, 1.01],
                                   labels=["Low", "Elevated", "High", "Critical"]).astype(str)
        labels = derive_attack_type(raw)
        if config.LABEL_COL in labels.columns:
            truth = labels[config.LABEL_COL].astype(str).str.upper().str.contains("DDOS_HTTP")
            out["actual"] = np.where(truth, config.CLASS_NAMES[1], config.CLASS_NAMES[0])
        for col in ("frame.time", "ip.src_host", "ip.dst_host", "tcp.dstport",
                    "http.request.method", "http.request.version", "tcp.len"):
            if col in raw.columns:
                out[col] = raw[col].values
        return out

    # ------------------------------------------------------- explanations
    def explain(self, raw_row: pd.DataFrame, top_k: int = 12) -> dict:
        """Additive explanation of one packet (SHAP, or tree-path fallback)."""
        X = self.encode(raw_row.iloc[[0]])
        values, base, method = local_attributions(self.model, X, self._shap(), self.use_shap)
        values = values[0]
        proba = float(self.model.predict_proba(X)[0, self.attack_idx])
        contribs = []
        for i, f in enumerate(self.feature_names):
            enc_val = float(X.iloc[0, i])
            contribs.append({
                "feature": f,
                "description": config.FEATURE_DESCRIPTIONS.get(f, f),
                "value": self.encoder.decode_value(f, enc_val),
                "encoded_value": enc_val,
                "contribution": float(values[i]),
                "normal_median": self.baselines["Normal"][f]["median"],
                "attack_median": self.baselines["DDoS HTTP Flood"][f]["median"],
            })
        contribs.sort(key=lambda c: -abs(c["contribution"]))
        result = {
            "method": method,
            "base_value": float(base),
            "probability": proba,
            "prediction": config.CLASS_NAMES[int(proba >= self.threshold)],
            "contributions": contribs[:top_k],
            "other_contribution": float(sum(c["contribution"] for c in contribs[top_k:])),
        }
        result["narrative"] = self.narrative(result)
        return result

    def explain_lime(self, raw_row: pd.DataFrame, num_features: int = 10) -> dict:
        X = self.encode(raw_row.iloc[[0]])
        weights, intercept, local_pred = lime_explain(self.model, self.background, X.iloc[0],
                                                      self.encoder.categorical_mask(), config.CLASS_NAMES,
                                                      num_features=num_features)
        return {"method": "LIME", "intercept": intercept, "weights": weights, "local_pred": local_pred}

    def surrogate_path(self, raw_row: pd.DataFrame) -> list[str]:
        """The global surrogate's IF-THEN path for this packet."""
        X = self.encode(raw_row.iloc[[0]])
        t = self.surrogate.tree_
        node, steps = 0, []
        while t.children_left[node] != -1:
            f = self.feature_names[t.feature[node]]
            thr, v = t.threshold[node], X.iloc[0][f]
            go_left = v <= thr
            steps.append(f"{describe_split(f, thr, go_left, self.encoder.vocab)}   (this packet: {self.encoder.decode_value(f, v)})")
            node = t.children_left[node] if go_left else t.children_right[node]
        val = t.value[node, 0, :]
        cls = self.surrogate.classes_[int(np.argmax(val))]
        steps.append(f"→ {config.CLASS_NAMES[int(cls)]}")
        return steps

    # ------------------------------------------- NOVELTY: XAI consensus
    @property
    def method_labels(self) -> dict:
        return {xcs.METHOD_RF: self.capabilities["attribution_method"], xcs.METHOD_LIME: "LIME",
                xcs.METHOD_OCC: "Occlusion", xcs.METHOD_SUR: "Surrogate tree"}

    @cached_property
    def _normal_baseline(self) -> np.ndarray:
        return np.array([self.baselines["Normal"][f]["median"] for f in self.feature_names])

    def _fast_attributions(self, X: pd.DataFrame, rf_values: np.ndarray | None = None):
        if rf_values is None:
            rf_values, _, _ = local_attributions(self.model, X, self._shap(), self.use_shap)
        occ = xcs.occlusion_attributions(self.model, X, self._normal_baseline)
        sur, sur_verdict = xcs.surrogate_attributions(self.surrogate, X)
        return rf_values, occ, sur, sur_verdict

    def consensus(self, raw_row: pd.DataFrame, use_lime: bool = True) -> dict:
        """Full multi-method consensus for one packet (adds LIME when installed)."""
        X = self.encode(raw_row.iloc[[0]])
        p = float(self.model.predict_proba(X)[0, self.attack_idx])
        rf_v = int(p >= self.threshold)
        rf, occ, sur, sur_v = self._fast_attributions(X)
        attrs = {xcs.METHOD_RF: rf[0], xcs.METHOD_OCC: occ[0], xcs.METHOD_SUR: sur[0]}
        verdicts = {"Surrogate tree": int(sur_v[0])}
        if use_lime and HAS_LIME:
            lime = self.explain_lime(raw_row, num_features=min(15, len(self.feature_names)))
            attrs[xcs.METHOD_LIME] = xcs.lime_to_vector(lime["weights"], self.feature_names)
            if lime["local_pred"] is not None:
                verdicts["LIME local model"] = int(lime["local_pred"] >= 0.5)
        out = xcs.consensus_for_packet(attrs, rf_v, verdicts, self.feature_names)
        out.update(probability=p, prediction=config.CLASS_NAMES[rf_v],
                   recommendation=xcs.recommendation(out, bool(rf_v)),
                   method_labels=self.method_labels)
        for r in out["ranking"]:
            r["description"] = config.FEATURE_DESCRIPTIONS.get(r["feature"], r["feature"])
            r["value"] = self.encoder.decode_value(r["feature"], float(X.iloc[0][r["feature"]]))
        return out

    def _batch(self, X: pd.DataFrame, rf_values: np.ndarray | None = None) -> pd.DataFrame:
        proba = self.model.predict_proba(X)[:, self.attack_idx]
        rf, occ, sur, sur_v = self._fast_attributions(X, rf_values)
        rows = []
        for i in range(len(X)):
            rf_v = int(proba[i] >= self.threshold)
            c = xcs.consensus_for_packet(
                {xcs.METHOD_RF: rf[i], xcs.METHOD_OCC: occ[i], xcs.METHOD_SUR: sur[i]},
                rf_v, {"Surrogate tree": int(sur_v[i])}, self.feature_names)
            top = c["ranking"][0]["feature"] if c["ranking"] else ""
            rows.append({"attack_probability": float(proba[i]), "prediction": config.CLASS_NAMES[rf_v],
                         "xcs": c["score"], "trust": c["trust"], **{f"c_{k}": v for k, v in c["components"].items()},
                         "consensus_top_feature": top,
                         **{f"pair_{k}": v["spearman"] for k, v in c["pairs"].items()}})
        return pd.DataFrame(rows, index=X.index)

    def batch_consensus(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Fast consensus (RF attribution + occlusion + surrogate) for many packets."""
        return self._batch(self.encode(raw))

    @cached_property
    def global_consensus(self) -> pd.DataFrame:
        """Consensus study on held-out packets saved at training time."""
        s = self.shap_sample
        n = min(config.CONSENSUS_GLOBAL_SAMPLE, len(s["X"]))
        X = s["X"].iloc[:n][self.feature_names]
        values = s["values"][:n] if s["method"] == self.capabilities["attribution_method"] else None
        out = self._batch(X, values)
        out["actual"] = np.where(s["y"][:n] == 1, config.CLASS_NAMES[1], config.CLASS_NAMES[0])
        out["correct"] = out["prediction"] == out["actual"]
        return out

    # ------------------------------------------------------------ narrative
    def narrative(self, exp: dict, k: int = 3) -> str:
        verdict = exp["prediction"]
        p = exp["probability"]
        towards = [c for c in exp["contributions"] if c["contribution"] > 0][:k]
        against = [c for c in exp["contributions"] if c["contribution"] < 0][:k]

        def fmt(c):
            return f"**{c['description']}** (`{c['feature']}` = {c['value']})"

        lines = [f"The model classifies this packet as **{verdict}** "
                 f"with an attack probability of **{p:.1%}** "
                 f"(baseline {exp['base_value']:.1%})."]
        if towards:
            lines.append("Pushing towards HTTP flood: " + "; ".join(fmt(c) for c in towards) + ".")
        if against:
            lines.append("Pushing towards normal traffic: " + "; ".join(fmt(c) for c in against) + ".")
        return " ".join(lines)

    # ---------------------------------------------------------- indicators
    def flood_indicators(self, raw: pd.DataFrame, scored: pd.DataFrame) -> dict:
        """Traffic-level signals typical of an HTTP GET/POST flood."""
        def col(name):
            return raw[name].astype(str).str.strip() if name in raw.columns else pd.Series("", index=raw.index)

        method = col("http.request.method")
        is_http_req = method.str.upper().isin(["GET", "POST", "HEAD", "PUT"])
        flags = col("tcp.flags")
        syn = col("tcp.connection.syn").isin(["1", "1.0"])
        attack = scored["is_attack"]
        src = col("ip.src_host")
        top_src = src[attack].value_counts().head(5)
        return {
            "packets": int(len(raw)),
            "flagged": int(attack.sum()),
            "flagged_ratio": float(attack.mean()) if len(raw) else 0.0,
            "http_request_ratio": float(is_http_req.mean()) if len(raw) else 0.0,
            "http_methods": method[is_http_req].str.upper().value_counts().to_dict(),
            "syn_ratio": float(syn.mean()) if len(raw) else 0.0,
            "tcp_flag_mix": flags.value_counts().head(8).to_dict(),
            "top_flagged_sources": top_src.to_dict(),
            "distinct_sources_flagged": int(src[attack].nunique()),
        }
