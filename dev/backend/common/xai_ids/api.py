"""
XAI-IDS REST API (Flask blueprint).

All routes are under /api. Use create_app() for a standalone server, or register
`bp` on an existing Flask app to serve it from a larger backend.
"""
import threading

from flask import Blueprint, Flask, jsonify, request

from . import config
from .data_loader import IncidentDataset
from .detector import Detector

bp = Blueprint("xai_ids", __name__, url_prefix="/api")

_state = {"datasets": {}, "detectors": {}}
_lock = threading.Lock()
STATUSES = ["Open", "Investigating", "Resolved", "Normal"]


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


@bp.errorhandler(Exception)
def handle_error(e):
    code = getattr(e, "code", None)
    if isinstance(e, (KeyError, LookupError)):
        code = 404
    return jsonify({"error": str(e).strip("'\"")}), code if isinstance(code, int) else 500


@bp.route("/health")
def health():
    return jsonify({"ok": True, "loaded": list(_state["detectors"])})


@bp.route("/datasets")
def datasets():
    return jsonify({"datasets": list(config.DATASETS), "default": next(iter(config.DATASETS))})


@bp.route("/meta")
def meta():
    ds = get_dataset(request.args.get("dataset"))
    det = get_detector(ds.name)
    out = ds.summary()
    out["model"] = {"type": type(det.model).__name__, "features": len(det.features), **det.info}
    out["severities"] = ["Low", "Medium", "High", "Critical"]
    out["statuses"] = STATUSES
    out["type_display"] = {t: config.TYPE_DISPLAY.get(t, t.replace("_", " ")) for t in ds.attack_types}
    return jsonify(out)


@bp.route("/incidents")
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


@bp.route("/record")
def record():
    """Sidebar stepper: n-th record (1-based) within the chosen attack type."""
    ds = get_dataset(request.args.get("dataset"))
    t = request.args.get("type", "__all__")
    rows = ds.rows_by_type.get(t)
    if rows is None:
        return jsonify({"error": f"No records of type {t}"}), 404
    n = max(1, min(int(request.args.get("n", 1)), len(rows)))
    return jsonify({"n": n, "total": int(len(rows)), "incident": ds.incident_row(int(rows[n - 1]))})


def _pos(ds):
    if request.args.get("incident_id"):
        pos = ds.row_position(request.args["incident_id"])
        if pos is None:
            raise LookupError("Incident not found")
        return pos
    return int(request.args["row"])


@bp.route("/analyze")
def analyze():
    det = get_detector(request.args.get("dataset"))
    pos = _pos(det.ds)
    return jsonify({"incident": det.ds.incident_row(pos), "prediction": det.predict(pos)})


@bp.route("/explain")
def explain():
    det = get_detector(request.args.get("dataset"))
    pos = _pos(det.ds)
    return jsonify({"incident": det.ds.incident_row(pos), "prediction": det.predict(pos),
                    "explanation": det.explain(pos)})


@bp.route("/incident/<incident_id>")
def incident_detail(incident_id):
    ds = get_dataset(request.args.get("dataset"))
    pos = ds.row_position(incident_id)
    if pos is None:
        return jsonify({"error": "Incident not found"}), 404
    raw = ds.df.iloc[pos]
    fields = {c: str(raw[c]) for c in ds.df.columns if not c.startswith("_")}
    return jsonify({"incident": ds.incident_row(pos), "fields": fields})


@bp.route("/incident/<incident_id>/status", methods=["POST"])
def update_status(incident_id):
    ds = get_dataset(request.args.get("dataset"))
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in STATUSES:
        return jsonify({"error": "Invalid status"}), 400
    if not ds.set_status(incident_id, status):
        return jsonify({"error": "Incident not found"}), 404
    return jsonify({"ok": True, "incident": ds.incident_row(ds.row_position(incident_id))})


def create_app():
    app = Flask(__name__)
    app.register_blueprint(bp)

    @app.after_request
    def cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = config.CORS_ORIGINS
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp

    @app.route("/")
    def root():
        return jsonify({"service": "XAI-IDS backend", "api": "/api", "health": "/api/health"})

    return app
