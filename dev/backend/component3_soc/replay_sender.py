"""
replay_sender.py - DEMO helper that plays the role of Component 1: sends recorded alerts to the Component 3 service.

Start the service first (python -m backend.component3_soc.service), then in another terminal, from the dev folder:
    python -m backend.component3_soc.replay_sender --limit 300 --delay 0.02
It sends alerts that carry a timestamp, oldest first, using the calibrated confidence.
(The real Component 1 would send the same JSON for every flow it classifies.)
"""
import argparse
import json
import time
import urllib.request

from . import pipeline
from .calibrate import calibrate
from .service import HOST, PORT


def post(path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else b""
    request = urllib.request.Request(f"http://{HOST}:{PORT}{path}", data=data, headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(request, timeout=5).read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=300, help="how many alerts to send")
    parser.add_argument("--delay", type=float, default=0.02, help="seconds to wait between alerts")
    args = parser.parse_args()

    alerts = pipeline.load_alerts()
    alerts["confidence"] = calibrate(alerts)
    alerts = alerts[alerts["event_time"].notna()].sort_values(["event_time", "flow_id"]).head(args.limit)
    post("/reset")
    for row in alerts.itertuples():
        reply = post("/alert", {"flow_id": int(row.flow_id), "src_ip": row.src_ip, "dst_ip": row.dst_ip,
                                "predicted_type": row.predicted_type, "confidence": float(row.confidence),
                                "event_time": float(row.event_time)})
        print(row.flow_id, row.predicted_type, "->", reply)
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
