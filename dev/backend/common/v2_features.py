"""
Shared V2 feature engineering — replicates Component 1's preprocessing pipeline.

The 71 features in feature_names_15class_v2.json are produced by:
1. Dropping identifiers, IPs, timestamps, raw payloads, labels
2. Numeric columns → fillna(0)
3. Mostly-numeric text → coerce to numeric
4. Categorical text with ≤50 categories → one-hot encode ({col}_{value})
5. Categorical text with >50 categories → label encode (frequency order)
6. Dropped text columns → add {col}_len (string length) and {col}_code (freq-based ID)

All models (XAI IDS, HTTP Flood, Network Flood, TCP SYN, UDP Flood, Web Injection)
use this module so they share the same feature space as Component 1.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

# Path to the canonical feature names list from Component 1
_FEATURE_NAMES_PATH = (
    Path(__file__).resolve().parents[1]
    / "component1_detection"
    / "Component1_IDS"
    / "feature_names_15class_v2.json"
)

# Columns dropped before feature engineering (identifiers, IPs, timestamps, raw payloads, labels)
DROP_COLUMNS = [
    "frame.time", "ip.src_host", "ip.dst_host",
    "arp.dst.proto_ipv4", "arp.src.proto_ipv4",
    "http.file_data", "http.request.uri.query", "http.referer",
    "http.request.full_uri", "tcp.payload", "mqtt.msg",
    "Attack_label", "Attack_type",
]

# Text columns whose raw values are dropped but contribute _len / _code features
TEXT_COLUMNS = [
    "http.file_data", "http.request.uri.query", "http.referer",
    "http.request.full_uri", "tcp.payload", "mqtt.msg",
]

# Columns that are one-hot encoded — known from the v2 training output
ONE_HOT_COLUMNS = {
    "http.request.method": [
        "http.request.method_0",
        "http.request.method_0.0",
        "http.request.method_GET",
        "http.request.method_POST",
        "http.request.method_TRACE",
    ],
    "http.request.version": [
        "http.request.version_0",
        "http.request.version_0.0",
        "http.request.version_By Dr HTTP/1.1",
        "http.request.version_HTTP/1.0",
        "http.request.version_HTTP/1.1",
        'http.request.version_Src=javascript:alert(\'Vulnerable\')__Img Src=\\" HTTP/1.1',
    ],
}

# Minimum frequency for a text value to get a stable code (Component 1 uses 5)
MIN_TEXT_FREQ = 5


def load_v2_feature_names() -> list[str]:
    with open(_FEATURE_NAMES_PATH) as f:
        return json.load(f)


# Pre-load
V2_FEATURE_NAMES: list[str] = load_v2_feature_names()


def _one_hot_categories(col: str) -> dict[str, str]:
    """Return {suffix_after_col_: original_value} for a one-hot source column."""
    out = {}
    prefix = col + "_"
    for feat in V2_FEATURE_NAMES:
        if feat.startswith(prefix):
            out[feat] = feat[len(prefix):]
    return out


class V2FeatureEncoder:
    """Transforms raw Edge-IIoTset DataFrames into the 71-feature V2 space."""

    def __init__(self):
        self.feature_names: list[str] = list(V2_FEATURE_NAMES)
        self.text_code_maps: dict[str, dict[str, int]] = {}
        self.label_encode_maps: dict[str, dict[str, int]] = {}
        self._fitted = False

    def _direct_numeric_cols(self) -> list[str]:
        """Feature names that map 1:1 to raw CSV columns (not one-hot, not _len/_code)."""
        one_hot_feats = set()
        for feats in ONE_HOT_COLUMNS.values():
            one_hot_feats.update(feats)
        text_derived = set()
        for tc in TEXT_COLUMNS:
            text_derived.add(f"{tc}_len")
            text_derived.add(f"{tc}_code")
        return [f for f in self.feature_names if f not in one_hot_feats and f not in text_derived]

    def fit(self, df: pd.DataFrame) -> "V2FeatureEncoder":
        """Learn frequency-based code maps for text columns from training data."""
        # Text _code maps: values appearing ≥MIN_TEXT_FREQ times get an integer ID
        for col in TEXT_COLUMNS:
            if col in df.columns:
                s = df[col].astype(str).str.strip()
                vc = s.value_counts()
                freq = vc[vc >= MIN_TEXT_FREQ]
                self.text_code_maps[col] = {v: i for i, v in enumerate(freq.index)}
            else:
                self.text_code_maps[col] = {}

        # Label-encode maps for columns with >50 categories
        # These are columns present in feature_names that are NOT one-hot source columns
        # and are text in the raw data (they get label-encoded by frequency)
        for col in self._direct_numeric_cols():
            if col not in df.columns:
                continue
            s = df[col]
            num = pd.to_numeric(s, errors="coerce")
            if num.notna().mean() > 0.99:
                continue  # numeric column, no encoding needed
            # Text column with >50 categories → label encode
            tokens = s.astype(str).str.strip()
            cats = sorted(tokens.unique())
            if len(cats) > 50:
                self.label_encode_maps[col] = {v: i for i, v in enumerate(cats)}

        self._fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transform a raw DataFrame into the 71-feature V2 space."""
        if not self._fitted:
            raise RuntimeError("Call fit() before transform()")

        out = {}
        n = len(df)

        # 1. Direct numeric / label-encoded columns
        for col in self._direct_numeric_cols():
            if col not in df.columns:
                out[col] = np.zeros(n, dtype=np.float32)
                continue

            if col in self.label_encode_maps:
                tokens = df[col].astype(str).str.strip()
                codes = tokens.map(self.label_encode_maps[col])
                out[col] = codes.fillna(-1).astype(np.float32).to_numpy()
            else:
                num = pd.to_numeric(df[col], errors="coerce")
                out[col] = num.fillna(0).astype(np.float32).to_numpy()

        # 2. One-hot encoded columns
        for src_col, feat_list in ONE_HOT_COLUMNS.items():
            if src_col in df.columns:
                tokens = df[src_col].astype(str).str.strip()
            else:
                tokens = pd.Series("0", index=df.index)
            cats = _one_hot_categories(src_col)
            for feat_name in feat_list:
                val = cats.get(feat_name, feat_name.split("_", 1)[-1] if "_" in feat_name else "")
                out[feat_name] = (tokens == val).astype(np.float32).to_numpy()

        # 3. Text-derived _len and _code features
        for col in TEXT_COLUMNS:
            len_feat = f"{col}_len"
            code_feat = f"{col}_code"
            if col in df.columns:
                s = df[col].astype(str).str.strip()
                out[len_feat] = s.str.len().astype(np.float32).to_numpy()
                code_map = self.text_code_maps.get(col, {})
                codes = s.map(code_map)
                out[code_feat] = codes.fillna(-1).astype(np.float32).to_numpy()
            else:
                out[len_feat] = np.zeros(n, dtype=np.float32)
                out[code_feat] = np.full(n, -1, dtype=np.float32)

        return pd.DataFrame(out, index=df.index)[self.feature_names]

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        return self.fit(df).transform(df)

    def decode_value(self, col: str, code: float) -> str:
        """Turn an encoded value back into something a human can read."""
        if col in self.label_encode_maps:
            inverse = {v: k for k, v in self.label_encode_maps[col].items()}
            return inverse.get(int(code), "<unseen>")
        for tc in TEXT_COLUMNS:
            if col == f"{tc}_code":
                inverse = {v: k for k, v in self.text_code_maps.get(tc, {}).items()}
                label = inverse.get(int(code), "<unseen>")
                return label[:40] if len(label) > 40 else label
        return f"{code:g}"

    @property
    def categorical_cols(self) -> list[str]:
        """Columns that are categorically encoded (for dashboard display)."""
        cats = list(self.label_encode_maps.keys())
        for tc in TEXT_COLUMNS:
            cats.append(f"{tc}_code")
        return cats

    @property
    def vocab(self) -> dict[str, dict[str, int]]:
        """Compatibility with Component 2 FeatureEncoder.vocab."""
        v = {}
        for col, mapping in self.label_encode_maps.items():
            v[col] = mapping
        for tc in TEXT_COLUMNS:
            code_col = f"{tc}_code"
            if tc in self.text_code_maps:
                v[code_col] = self.text_code_maps[tc]
        return v
