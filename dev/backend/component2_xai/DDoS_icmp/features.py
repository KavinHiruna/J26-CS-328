"""
Feature encoding for raw Edge-IIoTset packet rows.

Uses the Component 1 V2 feature set (71 features from feature_names_15class_v2.json)
for consistency across all XAI dashboards. Falls back to the original per-column
auto-detection when the V2 feature names file is unavailable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from . import config

try:
    from backend.common.v2_features import V2FeatureEncoder
    _HAS_V2 = True
except ImportError:
    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from common.v2_features import V2FeatureEncoder
        _HAS_V2 = True
    except ImportError:
        _HAS_V2 = False

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
UNKNOWN_CODE = -1


def _to_number(value) -> float | None:
    if value is None:
        return 0.0
    if isinstance(value, (int, float, np.integer, np.floating)):
        return 0.0 if pd.isna(value) else float(value)
    s = str(value).strip()
    if s == "" or s.lower() in {"nan", "none", "-"}:
        return 0.0
    if _HEX_RE.match(s):
        return float(int(s, 16))
    try:
        return float(s)
    except ValueError:
        return None


def _parse_series(series: pd.Series) -> tuple[pd.Series, pd.Series]:
    num = pd.to_numeric(series, errors="coerce")
    missing = series.isna()
    pending = num.isna() & ~missing
    if pending.any():
        strs = series[pending].astype(str).str.strip()
        empty = strs.eq("") | strs.str.lower().isin(["nan", "none", "-"])
        num.loc[strs.index[empty]] = 0.0
        hex_mask = strs.str.match(_HEX_RE) & ~empty
        if hex_mask.any():
            num.loc[strs.index[hex_mask]] = strs[hex_mask].map(lambda x: float(int(x, 16)))
    num = num.astype(float)
    num[missing] = 0.0
    is_text = num.isna()
    return num, is_text


def _normalise_token(value) -> str:
    num = _to_number(value)
    if num is not None:
        return str(int(num)) if float(num).is_integer() else repr(num)
    return str(value).strip()


def _tokens(series: pd.Series) -> pd.Series:
    num, is_text = _parse_series(series)
    out = pd.Series(index=series.index, dtype=object)
    nums = num[~is_text]
    integral = nums == np.floor(nums)
    out[nums.index[integral]] = nums[integral].astype(np.int64).astype(str)
    out[nums.index[~integral]] = nums[~integral].map(repr)
    out[is_text] = series[is_text].astype(str).str.strip()
    return out


@dataclass
class FeatureEncoder:
    """Wraps the V2FeatureEncoder to produce the canonical 71-feature space.

    Falls back to the original per-column auto-detection if V2 is unavailable.
    """

    feature_names: list[str] = field(default_factory=list)
    numeric_cols: list[str] = field(default_factory=list)
    categorical_cols: list[str] = field(default_factory=list)
    vocab: dict[str, dict[str, int]] = field(default_factory=dict)
    dropped_constant: list[str] = field(default_factory=list)
    _v2: V2FeatureEncoder | None = field(default=None, repr=False)

    # ------------------------------------------------------------------ fit
    def fit(self, df: pd.DataFrame) -> "FeatureEncoder":
        if _HAS_V2:
            self._v2 = V2FeatureEncoder()
            self._v2.fit(df)
            self.feature_names = self._v2.feature_names
            self.categorical_cols = self._v2.categorical_cols
            self.vocab = self._v2.vocab
            self.numeric_cols = [f for f in self.feature_names if f not in set(self.categorical_cols)]
            self.dropped_constant = []
            return self

        # Fallback: original auto-detection
        cols = [c for c in df.columns if c not in config.DROP_COLUMNS]
        self.numeric_cols, self.categorical_cols, self.vocab = [], [], {}
        self.dropped_constant = []

        for col in cols:
            series = df[col]
            parsed, is_text = _parse_series(series)
            if is_text.any():
                tokens = _tokens(series)
                counts = tokens.value_counts()
                if len(counts) <= 1:
                    self.dropped_constant.append(col)
                    continue
                self.categorical_cols.append(col)
                self.vocab[col] = {tok: i for i, tok in enumerate(counts.index)}
            else:
                if parsed.nunique() <= 1:
                    self.dropped_constant.append(col)
                    continue
                self.numeric_cols.append(col)

        keep = set(self.numeric_cols) | set(self.categorical_cols)
        self.feature_names = [c for c in cols if c in keep]
        return self

    # ------------------------------------------------------------ transform
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        if self._v2 is not None:
            return self._v2.transform(df)

        out = {}
        for col in self.feature_names:
            if col not in df.columns:
                out[col] = np.zeros(len(df), dtype=float)
                continue
            if col in self.vocab:
                mapping = self.vocab[col]
                zero_code = mapping.get("0", UNKNOWN_CODE)
                tokens = _tokens(df[col])
                codes = tokens.map(mapping)
                codes[tokens.eq("0") & codes.isna()] = zero_code
                out[col] = codes.fillna(UNKNOWN_CODE).astype(float).to_numpy()
            else:
                parsed, _ = _parse_series(df[col])
                out[col] = parsed.fillna(0.0).to_numpy()
        return pd.DataFrame(out, index=df.index)[self.feature_names]

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        return self.fit(df).transform(df)

    # -------------------------------------------------------------- helpers
    def decode_value(self, col: str, code: float) -> str:
        if self._v2 is not None:
            return self._v2.decode_value(col, code)
        if col in self.vocab:
            inverse = {v: k for k, v in self.vocab[col].items()}
            return inverse.get(int(code), "<unseen>")
        return f"{code:g}"

    def categorical_mask(self) -> list[bool]:
        return [c in self.vocab for c in self.feature_names]
