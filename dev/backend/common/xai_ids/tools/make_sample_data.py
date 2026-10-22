"""
Generate a small synthetic CSV with Edge-IIoT-style columns, for trying the
dashboard without the real dataset:

    python tools/make_sample_data.py sample.csv 20000
    set XAI_IDS_DATASET=sample.csv   (Windows)  /  export XAI_IDS_DATASET=sample.csv
    python app.py
"""
import sys

import numpy as np
import pandas as pd

TYPES = {  # type: (weight, signature)
    "Normal": (0.55, dict(tcp_len=(200, 80), udp_port=0, icmp=0, http=0.2, mqtt=60)),
    "DDoS_UDP": (0.08, dict(tcp_len=(0, 1), udp_port=1, icmp=0, http=0, mqtt=0)),
    "DDoS_ICMP": (0.07, dict(tcp_len=(0, 1), udp_port=0, icmp=1, http=0, mqtt=0)),
    "DDoS_TCP": (0.06, dict(tcp_len=(0, 2), udp_port=0, icmp=0, http=0, mqtt=0)),
    "DDoS_HTTP": (0.03, dict(tcp_len=(400, 60), udp_port=0, icmp=0, http=1, mqtt=0)),
    "SQL_injection": (0.03, dict(tcp_len=(600, 150), udp_port=0, icmp=0, http=1, mqtt=0)),
    "Password": (0.03, dict(tcp_len=(150, 30), udp_port=0, icmp=0, http=0.9, mqtt=0)),
    "Vulnerability_scanner": (0.03, dict(tcp_len=(30, 20), udp_port=0, icmp=0, http=0.5, mqtt=0)),
    "Uploading": (0.02, dict(tcp_len=(1300, 200), udp_port=0, icmp=0, http=1, mqtt=0)),
    "Backdoor": (0.02, dict(tcp_len=(80, 30), udp_port=0, icmp=0, http=0, mqtt=0)),
    "Port_Scanning": (0.02, dict(tcp_len=(0, 1), udp_port=0, icmp=0, http=0, mqtt=0)),
    "XSS": (0.02, dict(tcp_len=(700, 150), udp_port=0, icmp=0, http=1, mqtt=0)),
    "Ransomware": (0.02, dict(tcp_len=(900, 300), udp_port=0, icmp=0, http=0, mqtt=0)),
    "MITM": (0.01, dict(tcp_len=(50, 30), udp_port=0, icmp=0, http=0, mqtt=0)),
    "Fingerprinting": (0.01, dict(tcp_len=(10, 5), udp_port=0, icmp=0.5, http=0, mqtt=0)),
}


def main(out, n):
    rng = np.random.default_rng(7)
    names = list(TYPES)
    w = np.array([TYPES[t][0] for t in names]); w /= w.sum()
    labels = rng.choice(names, size=n, p=w)
    rows = []
    for i, t in enumerate(labels):
        s = TYPES[t][1]
        tl = max(0, rng.normal(*s["tcp_len"]))
        rows.append({
            "frame.time": f" 2021 {8 + i // 3600 % 12:02d}:{i // 60 % 60:02d}:{i % 60:02d}.000000000 ",
            "ip.src_host": f"192.168.0.{rng.integers(2, 254)}",
            "ip.dst_host": f"192.168.0.{rng.integers(2, 254)}",
            "arp.opcode": 1 if t == "MITM" and rng.random() < .7 else 0,
            "icmp.checksum": rng.integers(1, 65535) if rng.random() < s["icmp"] else 0,
            "icmp.seq_le": rng.integers(1, 65535) if rng.random() < s["icmp"] else 0,
            "http.content_length": rng.integers(50, 3000) if rng.random() < s["http"] else 0,
            "http.request.method": "GET" if rng.random() < s["http"] else "0",
            "http.response": 1 if rng.random() < s["http"] * .5 else 0,
            "tcp.ack": int(rng.integers(0, 2_000_000)) if tl > 0 else int(rng.integers(0, 3)),
            "tcp.connection.syn": 1 if t in ("DDoS_TCP", "Port_Scanning") or rng.random() < .05 else 0,
            "tcp.connection.rst": 1 if t == "Port_Scanning" and rng.random() < .6 else 0,
            "tcp.dstport": int(rng.choice([80, 443, 1883, 502])) if t == "Normal" else int(rng.integers(1, 65535)) if t == "Port_Scanning" else 80,
            "tcp.flags": int(rng.choice([16, 24, 2, 4, 18])),
            "tcp.len": round(tl, 1),
            "tcp.seq": int(rng.integers(0, 1_000_000)),
            "udp.port": int(rng.integers(1, 65535)) if s["udp_port"] else 0,
            "udp.stream": int(rng.integers(0, 10_000)) if s["udp_port"] else 0,
            "udp.time_delta": round(float(rng.exponential(.001)), 6) if s["udp_port"] else 0,
            "dns.qry.name.len": int(rng.integers(5, 40)) if t == "Normal" and rng.random() < .2 else 0,
            "mqtt.len": round(max(0, rng.normal(s["mqtt"], 10)), 1) if s["mqtt"] and rng.random() < .6 else 0,
            "mqtt.msgtype": 3 if s["mqtt"] and rng.random() < .6 else 0,
            "Attack_label": 0 if t == "Normal" else 1,
            "Attack_type": t,
            "incident_id": f"INC-{i + 1:06d}",
        })
    pd.DataFrame(rows).to_csv(out, index=False)
    print(f"wrote {n:,} rows to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample_edgeiiot.csv",
         int(sys.argv[2]) if len(sys.argv) > 2 else 20000)
