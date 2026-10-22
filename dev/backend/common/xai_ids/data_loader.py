"""Loads the Edge-IIoT CSV and derives the incident fields the dashboard shows."""
import hashlib
import json
import threading
from pathlib import Path

import numpy as np
import pandas as pd

from . import config


def _norm(name):
    """'Attack Type', 'attack_type', ' Attack-Type ' -> 'attacktype'."""
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def _find(columns, candidates):
    by_norm = {}
    for c in columns:
        by_norm.setdefault(_norm(c), c)
    for cand in candidates:
        if cand in columns:
            return cand
        if _norm(cand) in by_norm:
            return by_norm[_norm(cand)]
    return None


def _parse_times(series):
    s = series.astype(str).str.strip()
    # Edge-IIoT often stores only "<year> HH:MM:SS" with no month/day; pandas would
    # silently put all of those on 1 January, so treat values without a full date as invalid.
    has_date = s.str.contains(
        r"\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|[A-Za-z]{3,9}\s+\d{1,2}", regex=True)
    if has_date.mean() < config.MIN_VALID_TIME_RATIO:
        return None, float(has_date.mean())
    try:
        parsed = pd.to_datetime(s, errors="coerce", format="mixed")
    except (TypeError, ValueError):
        parsed = pd.to_datetime(s, errors="coerce")
    ok = parsed.notna() & (parsed.dt.year > 2000)
    return parsed, ok.mean() if len(s) else 0.0


def _status_for(incident_id, attack_type):
    if attack_type == "Normal":
        return "Normal"
    h = int(hashlib.md5(str(incident_id).encode()).hexdigest()[:8], 16) % 10
    return "Open" if h < 4 else ("Investigating" if h < 7 else "Resolved")


def _mask(series):
    """Boolean Series -> NumPy bool array (handles pandas' nullable/arrow booleans)."""
    return series.fillna(False).to_numpy(dtype=bool)


def _pick_id_column(df, cols):
    exact = _find(cols, config.INCIDENT_ID_CANDIDATES)
    options = [c for c in cols if "incident" in _norm(c)]
    if exact and exact not in options:
        options.insert(0, exact)
    if not options:
        return None
    if len(options) > 1:
        # prefer a column whose values are unique, then one that isn't purely numeric
        def score(c):
            s = df[c]
            return (s.is_unique, not pd.api.types.is_numeric_dtype(s))
        options.sort(key=score, reverse=True)
        print(f"[data] several incident ID columns {options}; using '{options[0]}'", flush=True)
    return options[0]


class StatusStore:
    """Analyst status changes, persisted to a small JSON file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.data = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except json.JSONDecodeError:
                self.data = {}

    def set(self, incident_id, status):
        with self._lock:
            self.data[str(incident_id)] = status
            self.path.write_text(json.dumps(self.data, indent=1))


class IncidentDataset:
    def __init__(self, name, csv_path):
        self.name = name
        self.path = Path(csv_path)
        if not self.path.exists():
            raise FileNotFoundError(
                f"Dataset not found: {self.path}\n"
                "Edit DATASETS in config.py or set the XAI_IDS_DATASET environment variable."
            )
        print(f"[data] loading {self.path} ...", flush=True)
        df = pd.read_csv(self.path, low_memory=False)
        print(f"[data] {len(df):,} rows x {df.shape[1]} columns", flush=True)

        # Clean header names (stray spaces, Excel's UTF-8 BOM)
        df.columns = [str(c).replace("\ufeff", "").strip() for c in df.columns]
        cols = list(df.columns)
        print(f"[data] columns: {cols}", flush=True)

        self.label_col = _find(cols, [config.LABEL_COLUMN] + config.LABEL_CANDIDATES)
        self.binary_col = _find(cols, [config.BINARY_LABEL_COLUMN] + config.BINARY_LABEL_CANDIDATES)
        if self.label_col is None and self.binary_col is not None:
            # Only a 0/1 label: show traffic as Normal vs Attack
            print(f"[data] no multi-class label column; using '{self.binary_col}' as Normal/Attack",
                  flush=True)
            b = pd.to_numeric(df[self.binary_col], errors="coerce").fillna(0)
            df["Attack_type"] = np.where(b > 0, "Attack", "Normal")
            self.label_col = "Attack_type"
        if self.label_col is None:
            raise ValueError(
                "No label column found. Set LABEL_COLUMN in config.py to the name of the column "
                f"that holds the attack type. Columns in this file: {cols}")
        if config.LABEL_NAMES:
            # label-encoded classes (0, 1, 2 ...) -> names
            df[self.label_col] = df[self.label_col].map(
                lambda v: config.LABEL_NAMES.get(str(v).strip().split(".")[0], v))
        self.id_col = _pick_id_column(df, cols)
        self.time_col = _find(cols, config.TIME_CANDIDATES)
        self.src_col = _find(cols, config.SRC_IP_CANDIDATES)
        self.dst_col = _find(cols, config.DST_IP_CANDIDATES)

        df[self.label_col] = df[self.label_col].astype(str).str.strip()
        # Normalise the benign class name so Normal-specific logic works ("normal", "BENIGN", "0")
        benign = {"normal", "benign", "normal/benign"}
        df[self.label_col] = df[self.label_col].where(
            ~df[self.label_col].str.lower().isin(benign), "Normal")
        self.exclude_cols = {self.label_col, self.binary_col} - {None}

        # Incident IDs
        if self.id_col is None:
            df["incident_id"] = [f"INC-{i + 1:07d}" for i in range(len(df))]
            self.id_col = "incident_id"
        df[self.id_col] = df[self.id_col].astype(str).str.strip()

        # Timestamps
        self.synthetic_time = True
        if self.time_col is not None:
            parsed, ratio = _parse_times(df[self.time_col])
            if ratio >= config.MIN_VALID_TIME_RATIO:
                df["_ts"] = parsed.ffill().bfill()
                self.synthetic_time = False
        if self.synthetic_time:
            start = pd.Timestamp(config.SYNTHETIC_START)
            df["_ts"] = start + pd.to_timedelta(
                np.arange(len(df)) * config.SYNTHETIC_INTERVAL_SEC, unit="s")
            print("[data] frame.time not usable - assigned synthetic timestamps "
                  f"from {start} every {config.SYNTHETIC_INTERVAL_SEC}s", flush=True)

        df["_severity"] = df[self.label_col].map(config.SEVERITY_MAP).fillna(config.DEFAULT_SEVERITY)
        df["_status"] = [_status_for(i, t) for i, t in zip(df[self.id_col], df[self.label_col])]
        df["_src"] = df[self.src_col].astype(str) if self.src_col else "-"
        uri_col = _find(cols, config.SQLI_URI_CANDIDATES)
        is_sqli = df[self.label_col].str.lower().isin(config.SQLI_TYPES)
        if uri_col is not None:
            hits = df[uri_col].astype(str).str.contains(config.SQLI_URI_PATTERN, case=False, regex=False)
            is_sqli |= hits & (df[self.label_col] != "Normal")
        df["_is_sqli"] = is_sqli.to_numpy(dtype=bool)
        is_ddos_http = df[self.label_col].str.lower().isin(config.DDOS_HTTP_TYPES)
        if uri_col is not None:
            flood = df[uri_col].astype(str).str.strip().str.match(config.DDOS_HTTP_URI_REGEX, case=False)
            is_ddos_http |= flood & (df[self.label_col] != "Normal")
        df["_is_ddos_http"] = is_ddos_http.to_numpy(dtype=bool)
        df["_row"] = np.arange(len(df))

        self.df = df
        self.ts_ns = df["_ts"].to_numpy(dtype="datetime64[ns]")
        self.id_index = pd.Series(np.arange(len(df)), index=df[self.id_col].to_numpy(dtype=object))
        self.attack_types = sorted(df[self.label_col].unique(), key=lambda t: (t != "Normal", t))
        self.status_store = StatusStore(config.STATUS_STORE)
        status_col = df.columns.get_loc("_status")
        for inc, st in self.status_store.data.items():
            pos = self.row_position(inc)
            if pos is not None:
                df.iat[pos, status_col] = st

        # Record lists per attack type for the sidebar stepper
        self.rows_by_type = {"__all__": np.arange(len(df))}
        for t, idx in df.groupby(self.label_col).indices.items():
            self.rows_by_type[t] = np.sort(idx)

    # ------------------------------------------------------------------
    def summary(self):
        return {
            "name": self.name,
            "path": str(self.path),
            "rows": int(len(self.df)),
            "attack_types": self.attack_types,
            "counts": {k: int(len(v)) for k, v in self.rows_by_type.items() if k != "__all__"},
            "min_time": self.df["_ts"].min().isoformat(),
            "max_time": self.df["_ts"].max().isoformat(),
            "synthetic_time": self.synthetic_time,
        }

    def row_position(self, incident_id):
        if incident_id not in self.id_index.index:
            return None
        v = self.id_index[incident_id]
        return int(v if np.isscalar(v) else v.iloc[0])

    def incident_row(self, pos):
        r = self.df.iloc[pos]
        t = r[self.label_col]
        return {
            "row": int(pos),
            "incident_id": r[self.id_col],
            "time": r["_ts"].strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": r["_src"],
            "dst_ip": str(r[self.dst_col]) if self.dst_col else "-",
            "type": t,
            "type_display": config.TYPE_DISPLAY.get(t, t.replace("_", " ")),
            "severity": r["_severity"],
            "status": r["_status"],
            "is_sqli": bool(r["_is_sqli"]),
            "is_ddos_http": bool(r["_is_ddos_http"]),
        }

    def search(self, start=None, end=None, traffic_type="All", severity="All",
               status="All", incident_id=None, page=1, page_size=config.PAGE_SIZE):
        df = self.df
        if incident_id:
            q = incident_id.strip().lower()
            ids = df[self.id_col].str.lower()
            mask = _mask(ids == q)
            if not mask.any():
                mask = _mask(ids.str.contains(q, regex=False))
        else:
            lo = np.searchsorted(self.ts_ns, np.datetime64(start)) if start else 0
            hi = np.searchsorted(self.ts_ns, np.datetime64(end), side="right") if end else len(df)
            if self._sorted:
                mask = np.zeros(len(df), bool)
                mask[lo:hi] = True
            else:
                ts = self.ts_ns
                mask = np.ones(len(df), bool)
                if start:
                    mask &= ts >= np.datetime64(start)
                if end:
                    mask &= ts <= np.datetime64(end)
            if traffic_type and traffic_type != "All":
                mask &= _mask(df[self.label_col] == traffic_type)
            if severity and severity != "All":
                mask &= _mask(df["_severity"] == severity)
            if status and status != "All":
                mask &= _mask(df["_status"] == status)

        positions = np.flatnonzero(mask)
        total = int(len(positions))
        page = max(1, int(page))
        chunk = positions[(page - 1) * page_size: page * page_size]
        sub = df.iloc[chunk]
        breakdown = df.iloc[positions][self.label_col].value_counts().to_dict() if total else {}
        return {
            "total": total,
            "page": page,
            "pages": max(1, -(-total // page_size)),
            "page_size": page_size,
            "breakdown": {k: int(v) for k, v in breakdown.items()},
            "incidents": [self.incident_row(int(p)) for p in sub["_row"].to_numpy()],
        }

    @property
    def _sorted(self):
        if not hasattr(self, "_is_sorted"):
            self._is_sorted = bool(np.all(self.ts_ns[1:] >= self.ts_ns[:-1]))
        return self._is_sorted

    def set_status(self, incident_id, status):
        pos = self.row_position(incident_id)
        if pos is None:
            return False
        self.df.iat[pos, self.df.columns.get_loc("_status")] = status
        self.status_store.set(incident_id, status)
        return True
