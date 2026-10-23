"""
service.py - Component 3 as a small SERVICE: Component 1 POSTs one alert at a time, we score it on arrival.

Run from the dev folder:      python -m backend.component3_soc.service        (http://127.0.0.1:8765)

  POST /alert    one alert as JSON (docs/interfaces.md):
                 {"flow_id": 1042, "src_ip": "192.168.0.170", "dst_ip": "192.168.0.128",
                  "predicted_type": "Ransomware", "confidence": 0.97, "event_time": 61234.5}
                 event_time (seconds) is optional; without it we use "capture_count" if given, else 1,
                 and mark the frequency as a fallback.
  GET  /alerts?limit=50     latest scored alerts      GET /health   counters      POST /reset   start fresh
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import factors, scoring
from .config import LIVE_FILE, NOT_AN_ALERT, OUTPUT_DIR, WINDOW_SECONDS

HOST, PORT = "127.0.0.1", 8765
LOCK = threading.Lock()
COUNTER = factors.WindowCounter()
STATE = {"received": 0, "benign": 0, "scored": 0, "rejected": 0, "recent": []}


def score_alert(message):
    """Score one alert message. Returns the result dict, or None if the flow is benign.
    Raises ValueError for a bad message (missing field, unknown attack type, number out of range)."""
    with LOCK:
        STATE["received"] += 1                       # every message counts, good or bad
    for field in ("src_ip", "dst_ip", "predicted_type", "confidence"):
        if field not in message:
            raise ValueError(f"missing field: {field}")
    attack_type = str(message["predicted_type"])
    if attack_type == NOT_AN_ALERT:
        with LOCK:
            STATE["benign"] += 1
        return None

    severity = factors.get_severity(attack_type)
    asset_id, asset_name, asset, status = factors.get_asset(message["dst_ip"])
    event_time = message.get("event_time")
    with LOCK:
        if event_time is not None:
            count = COUNTER.add(message["dst_ip"], attack_type, float(event_time))
            basis = f"time window ({WINDOW_SECONDS} s)"
        else:
            count = int(message.get("capture_count", 1))
            basis = "fallback: no timestamp, capture-wide count"
    frequency = factors.log_frequency(count)
    confidence = float(message["confidence"])
    score = scoring.risk_score(severity, confidence, asset, frequency)       # also checks every range
    level = scoring.priority_level(score)
    result = {"alert_id": f"FLOW-{message.get('flow_id', STATE['received'])}", "received_at": time.strftime("%H:%M:%S"),
              "src_ip": str(message["src_ip"]), "dst_ip": str(message["dst_ip"]), "predicted_type": attack_type,
              "confidence": confidence, "severity": severity, "asset_id": asset_id, "asset_name": asset_name,
              "asset_status": status, "asset_criticality": asset, "frequency_count": count, "frequency_basis": basis,
              "frequency": frequency, "risk_score": score, "priority": level,
              "recommendations": scoring.recommend(level, attack_type)}
    with LOCK:
        STATE["scored"] += 1
        STATE["recent"].append(result)
        del STATE["recent"][:-500]
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(LIVE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(result) + "\n")
    return result


def reset():
    with LOCK:
        COUNTER.reset()
        STATE.update(received=0, benign=0, scored=0, rejected=0, recent=[])
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        LIVE_FILE.write_text("", encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):          # keep the console quiet
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        if self.path == "/reset":
            reset()
            return self._send(200, {"status": "reset"})
        if self.path != "/alert":
            return self._send(404, {"error": "unknown path"})
        try:
            result = score_alert(json.loads(body))
        except (ValueError, TypeError, KeyError) as error:      # json errors are ValueErrors too
            with LOCK:
                STATE["rejected"] += 1
            return self._send(400, {"status": "rejected", "reason": str(error)})
        if result is None:
            return self._send(200, {"status": "benign, dropped"})
        self._send(200, {"status": "scored", "risk_score": result["risk_score"], "priority": result["priority"]})

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            with LOCK:
                return self._send(200, {k: v for k, v in STATE.items() if k != "recent"})
        if url.path == "/alerts":
            limit = int(parse_qs(url.query).get("limit", ["50"])[0])
            with LOCK:
                return self._send(200, STATE["recent"][-limit:])
        self._send(404, {"error": "unknown path"})


def make_server(host=HOST, port=PORT):
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    reset()
    print(f"Component 3 service listening on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        make_server().serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
