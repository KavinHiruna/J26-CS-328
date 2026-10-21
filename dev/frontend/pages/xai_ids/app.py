"""
XAI-IDS dashboard - Explainable AI for Intrusion Detection.

Run:  python app.py      then open http://127.0.0.1:5000
"""
import os
import sys
import threading

from flask import Flask, jsonify, render_template, request

import config
from data_loader import IncidentDataset
from model import Detector

app = Flask(__name__, template_folder="xai_ids_templates", static_folder="xai_ids_static")

_state = {"datasets": {}, "detectors": {}, "errors": {}}
_lock = threading.Lock()


def get_dataset(name=None):
    name = name or next(iter(config.DATASETS))
    if name not in config.DATASETS:
        raise KeyError(f"Unknown dataset '{name}'")
    with _lock:
        if name not in _state["datasets"]:
            _state["datasets"][name] = IncidentDataset(name, config.DATASETS[name])
        return _state["datasets"][name]


def get_detector(name=None):
    ds = get_dataset(name)
    with _lock:
        if ds.name not in _state["detectors"]:
            _state["detectors"][ds.name] = Detector(ds)
        return _state["detectors"][ds.name]


@app.errorhandler(Exception)
def handle_error(e):
    code = getattr(e, "code", 500)
    return jsonify({"error": str(e)}), code if isinstance(code, int) else 500


@app.route("/")
def index():
    return render_template("index.html", datasets=list(config.DATASETS))


@app.route("/api/meta")
def meta():
    ds = get_dataset(request.args.get("dataset"))
    det = get_detector(ds.name)
    out = ds.summary()
    out["model"] = {"type": type(det.model).__name__, "features": len(det.features), **det.info}
    out["severities"] = ["Low", "Medium", "High", "Critical"]
    out["statuses"] = ["Open", "Investigating", "Resolved", "Normal"]
    out["type_display"] = {t: config.TYPE_DISPLAY.get(t, t.replace("_", " ")) for t in ds.attack_types}
    return jsonify(out)


@app.route("/api/incidents")
def incidents():
    a = request.args
    ds = get_dataset(a.get("dataset"))
    start = f"{a['from_date']}T{a.get('from_time', '00:00')}" if a.get("from_date") else None
    end = f"{a['to_date']}T{a.get('to_time', '23:59')}:59" if a.get("to_date") else None
    return jsonify(ds.search(
        start=start, end=end,
        traffic_type=a.get("type", "All"), severity=a.get("severity", "All"),
        status=a.get("status", "All"), incident_id=a.get("incident_id"),
        page=int(a.get("page", 1)),
    ))


@app.route("/api/record")
def record():
    """Sidebar stepper: n-th record (1-based) within the chosen attack type."""
    ds = get_dataset(request.args.get("dataset"))
    t = request.args.get("type", "__all__")
    rows = ds.rows_by_type.get(t)
    if rows is None:
        return jsonify({"error": f"No records of type {t}"}), 404
    n = max(1, min(int(request.args.get("n", 1)), len(rows)))
    inc = ds.incident_row(int(rows[n - 1]))
    return jsonify({"n": n, "total": int(len(rows)), "incident": inc})


def _pos(ds):
    if request.args.get("incident_id"):
        pos = ds.row_position(request.args["incident_id"])
        if pos is None:
            raise LookupError("Incident not found")
        return pos
    return int(request.args["row"])


@app.route("/api/analyze")
def analyze():
    det = get_detector(request.args.get("dataset"))
    pos = _pos(det.ds)
    return jsonify({"incident": det.ds.incident_row(pos), "prediction": det.predict(pos)})


@app.route("/api/explain")
def explain():
    det = get_detector(request.args.get("dataset"))
    pos = _pos(det.ds)
    return jsonify({"incident": det.ds.incident_row(pos), "prediction": det.predict(pos),
                    "explanation": det.explain(pos)})


@app.route("/api/incident/<incident_id>")
def incident_detail(incident_id):
    ds = get_dataset(request.args.get("dataset"))
    pos = ds.row_position(incident_id)
    if pos is None:
        return jsonify({"error": "Incident not found"}), 404
    raw = ds.df.iloc[pos]
    fields = {c: str(raw[c]) for c in ds.df.columns if not c.startswith("_")}
    return jsonify({"incident": ds.incident_row(pos), "fields": fields})


@app.route("/api/incident/<incident_id>/status", methods=["POST"])
def update_status(incident_id):
    ds = get_dataset(request.args.get("dataset"))
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in {"Open", "Investigating", "Resolved", "Normal"}:
        return jsonify({"error": "Invalid status"}), 400
    if not ds.set_status(incident_id, status):
        return jsonify({"error": "Incident not found"}), 404
    return jsonify({"ok": True, "incident": ds.incident_row(ds.row_position(incident_id))})


if __name__ == "__main__":
    # Load data and the model before serving so the first page load is fast.
    try:
        get_detector()
    except FileNotFoundError as e:
        print(f"\nERROR: {e}\n", file=sys.stderr)
        sys.exit(1)
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  XAI-IDS running at http://127.0.0.1:{port}\n", flush=True)
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
