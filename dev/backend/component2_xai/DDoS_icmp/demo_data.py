"""
Demo data generator in the Edge-IIoTset CSV schema.

The normal captures shipped with the project (Distance, Flame_Sensor, ...) contain
no ICMP flood traffic. For a working demo without the real
`DDoS_ICMP_Flood_attack.csv`, this module injects SYNTHETIC ICMP flood bursts
(plus legitimate low-rate pings) into normal traffic. Synthetic rows are marked
with `synthetic = 1` so they are never mistaken for real captures.
Use the real Edge-IIoTset attack CSV for any reported results.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

EDGE_IIOT_COLUMNS = [
    "frame.time", "ip.src_host", "ip.dst_host", "arp.dst.proto_ipv4", "arp.opcode", "arp.hw.size",
    "arp.src.proto_ipv4", "icmp.checksum", "icmp.seq_le", "icmp.transmit_timestamp", "icmp.unused",
    "http.file_data", "http.content_length", "http.request.uri.query", "http.request.method", "http.referer",
    "http.request.full_uri", "http.request.version", "http.response", "http.tls_port", "tcp.ack", "tcp.ack_raw",
    "tcp.checksum", "tcp.connection.fin", "tcp.connection.rst", "tcp.connection.syn", "tcp.connection.synack",
    "tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.len", "tcp.options", "tcp.payload", "tcp.seq",
    "tcp.srcport", "udp.port", "udp.stream", "udp.time_delta", "dns.qry.name", "dns.qry.name.len",
    "dns.qry.qu", "dns.qry.type", "dns.retransmission", "dns.retransmit_request", "dns.retransmit_request_in",
    "mqtt.conack.flags", "mqtt.conflag.cleansess", "mqtt.conflags", "mqtt.hdrflags", "mqtt.len",
    "mqtt.msg_decoded_as", "mqtt.msg", "mqtt.msgtype", "mqtt.proto_len", "mqtt.protoname", "mqtt.topic",
    "mqtt.topic_len", "mqtt.ver", "mbtcp.len", "mbtcp.trans_id", "mbtcp.unit_id", "Attack_label", "Attack_type",
]


def _fmt(sec: float) -> str:
    sec = sec % 86_400
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f" 2021 {int(h):02d}:{int(m):02d}:{s:09.6f}000 "


def _icmp_rows(times, srcs, dsts, seqs, label: int, atype: str, rng) -> pd.DataFrame:
    n = len(times)
    d = pd.DataFrame(0, index=range(n), columns=EDGE_IIOT_COLUMNS, dtype=object)
    d["frame.time"] = [_fmt(t) for t in times]
    d["ip.src_host"] = srcs
    d["ip.dst_host"] = dsts
    d["icmp.checksum"] = rng.integers(1, 65535, n).astype(float)
    d["icmp.seq_le"] = np.asarray(seqs, dtype=float)
    d["Attack_label"] = label
    d["Attack_type"] = atype
    d["_t"] = times
    d["synthetic"] = 1
    return d


def make_demo_dataset(normal: pd.DataFrame | None = None, seed: int = 7, n_normal: int = 8000,
                      target: str = "192.168.0.128") -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    # ---------------- normal background traffic
    if normal is not None and len(normal):
        base = normal.sample(n=min(n_normal, len(normal)), random_state=seed).copy()
        base.columns = [c.strip() for c in base.columns]
        base = base[[c for c in EDGE_IIOT_COLUMNS if c in base.columns]]
        t = base["frame.time"].astype(str).str.extract(r"(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)").astype(float)
        base["_t"] = (t[0] * 3600 + t[1] * 60 + t[2]).values
        base = base.dropna(subset=["_t"])
        # compress normal traffic onto a 120 s timeline so it overlaps the bursts
        base["_t"] = 1000.0 + (base["_t"].rank(method="first") / len(base)) * 120.0
        base["frame.time"] = base["_t"].map(_fmt)
        base["synthetic"] = 0
    else:
        n = n_normal
        base = pd.DataFrame(0, index=range(n), columns=EDGE_IIOT_COLUMNS, dtype=object)
        base["_t"] = np.sort(rng.uniform(1000, 1120, n))
        base["frame.time"] = base["_t"].map(_fmt)
        hosts = [f"192.168.0.{i}" for i in (101, 128, 152, 170)]
        base["ip.src_host"] = rng.choice(hosts, n)
        base["ip.dst_host"] = rng.choice(hosts, n)
        base["tcp.srcport"] = rng.integers(1024, 65535, n).astype(float)
        base["tcp.dstport"] = 1883.0
        base["tcp.flags"] = "0x00000018"
        base["tcp.len"] = rng.integers(0, 120, n).astype(float)
        base["Attack_label"] = 0
        base["Attack_type"] = "Normal"
        base["synthetic"] = 1

    parts = [base]
    # ---------------- legitimate low-rate pings (request + reply) -> negatives the model must not flag
    for host in ("192.168.0.101", "192.168.0.152", "192.168.0.170"):
        times = np.arange(1000.0, 1120.0, 1.0) + rng.uniform(0, 0.2)
        seq = np.arange(len(times))
        req = _icmp_rows(times, [host] * len(times), [target] * len(times), seq, 0, "Normal", rng)
        rep = _icmp_rows(times + 0.0004, [target] * len(times), [host] * len(times), seq, 0, "Normal", rng)
        parts += [req, rep]

    # ---------------- synthetic DDoS ICMP floods
    bursts = [  # start, duration, pkt/s, n sources
        (1015.0, 8.0, 1800, 120),
        (1045.0, 6.0, 900, 40),
        (1070.0, 5.0, 600, 2),     # concentrated (DoS-like) flood
        (1095.0, 10.0, 2500, 250),
    ]
    for start, dur, pps, nsrc in bursts:
        n = int(dur * pps)
        times = np.sort(start + rng.uniform(0, dur, n))
        pool = [f"10.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(nsrc)]
        weights = rng.dirichlet(np.ones(nsrc) * (0.3 if nsrc <= 3 else 2.0))
        srcs = rng.choice(pool, n, p=weights)
        parts.append(_icmp_rows(times, srcs, [target] * n, np.arange(n) % 65535, 1, "DDoS_ICMP", rng))

    out = pd.concat(parts, ignore_index=True).sort_values("_t", kind="mergesort").drop(columns="_t")
    return out.reset_index(drop=True)
