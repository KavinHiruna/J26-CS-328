"""
Edge-IIoTset device / sensor inventory for the Component-2 XAI dashboards (BACKEND).

FILE LOCATION : dev/backend/component2_xai/edge_devices.py
USED BY       : frontend/pages/com2_attack/ddos_tcp.py, ddos_icmp.py, ddos_http.py

Every packet in the dataset is between IP addresses; analysts need to know *which device* that is.
The inventory is learned from the per-sensor normal-traffic captures in dev/data/processed/<Sensor>/:
each IoT sensor node publishes MQTT (TCP 1883) to a broker, and the Modbus capture shows the
Modbus/TCP devices. Testbed roles that are not visible from traffic alone (edge server, attacker
host, gateway) are documented in TESTBED_ROLES below (Edge-IIoTset, Ferrag et al., 2022).
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

import pandas as pd

PROCESSED_DIR = Path(__file__).resolve().parents[2] / "data" / "processed"
MQTT_PORTS = {"1883", "1883.0", "8883", "8883.0"}

# Roles of testbed hosts that traffic alone does not reveal.
TESTBED_ROLES = {
    "192.168.0.128": ("Edge server (Raspberry Pi, Raspbian)",
                      "Edge computing layer: MQTT broker, Modbus/TCP, Apache + DVWA web server"),
    "192.168.0.170": ("Attacker host", "Edge-IIoTset attack machine (scans, injections, HTTP flood)"),
    "192.168.0.1": ("Gateway / router", "Network layer: default gateway of the testbed LAN"),
}


def _sensor_name(folder: str) -> str:
    return folder.replace("_and_", " & ").replace("_", " ").replace("phValue", "pH value")


@lru_cache(maxsize=2)
def inventory(processed_dir: str = str(PROCESSED_DIR)) -> pd.DataFrame:
    """One row per known IP: role, device, sensors it serves / is, protocols. Empty if no captures."""
    rows: dict[str, dict] = {}

    def add(ip: str, role: str, device: str, sensor: str | None, proto: str):
        if not ip or ip in ("0", "0.0", "nan"):
            return
        r = rows.setdefault(ip, {"ip": ip, "roles": set(), "devices": set(), "sensors": set(), "protocols": set()})
        r["roles"].add(role)
        r["devices"].add(device)
        if sensor:
            r["sensors"].add(sensor)
        r["protocols"].add(proto)

    for f in sorted(Path(processed_dir).glob("*/*.csv")):
        sensor = _sensor_name(f.parent.name)
        try:
            d = pd.read_csv(f, dtype=str, usecols=lambda c: c in {"ip.src_host", "ip.dst_host", "tcp.dstport", "mbtcp.len"},
                            nrows=20_000)
        except (ValueError, OSError):
            continue
        if {"ip.src_host", "ip.dst_host"} - set(d.columns):
            continue
        port = d.get("tcp.dstport", pd.Series("", index=d.index)).astype(str).str.strip()
        mqtt = d[port.isin(MQTT_PORTS)]
        if len(mqtt):
            node, broker = mqtt["ip.src_host"].mode()[0], mqtt["ip.dst_host"].mode()[0]
            add(node, "IoT sensor node", f"{sensor} sensor node", sensor, "MQTT publish (TCP 1883)")
            add(broker, "MQTT broker", f"MQTT broker for {sensor}", sensor, "MQTT broker (TCP 1883)")
        modbus = d[~d.get("mbtcp.len", pd.Series("0", index=d.index)).astype(str).str.strip().isin(["0", "0.0", "", "nan"])]
        if len(modbus):
            for ip in pd.concat([modbus["ip.src_host"], modbus["ip.dst_host"]]).value_counts().head(3).index:
                add(ip, "Modbus/TCP device", "Modbus/TCP device (PLC / meter)", "Modbus", "Modbus/TCP")

    for ip, (device, note) in TESTBED_ROLES.items():
        add(ip, device, device, None, note)

    out = pd.DataFrame([{
        "ip": r["ip"], "role": " · ".join(sorted(r["roles"])), "device": " · ".join(sorted(r["devices"])),
        "sensors": ", ".join(sorted(r["sensors"])), "protocols": " · ".join(sorted(r["protocols"])),
    } for r in rows.values()])
    return out.sort_values("ip").reset_index(drop=True) if len(out) else out


def describe(ip: str) -> dict:
    """Device card for one IP (falls back to private / external classification)."""
    ip = str(ip).strip()
    inv = inventory()
    hit = inv[inv["ip"] == ip] if len(inv) else inv
    if len(hit):
        r = hit.iloc[0].to_dict()
        return {**r, "known": True, "dependent_sensors": dependent_sensors(ip)}
    try:
        addr = ipaddress.ip_address(ip)
        lan = any(addr in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        kind = ("Multicast address" if addr.is_multicast
                else "LAN address outside the sensor inventory" if lan
                else "External / likely spoofed address (not a testbed device)")
    except ValueError:
        kind = "No IP address in this record"
    return {"ip": ip, "role": kind, "device": kind, "sensors": "", "protocols": "", "known": False,
            "dependent_sensors": []}


def dependent_sensors(ip: str) -> list[str]:
    """Sensors whose telemetry goes through this host (it is their MQTT broker or the edge server)."""
    inv = inventory()
    if not len(inv):
        return []
    r = inv[inv["ip"] == str(ip).strip()]
    if not len(r) or "MQTT broker" not in r.iloc[0]["role"]:
        return []
    return [s for s in r.iloc[0]["sensors"].split(", ") if s]


def label(ip: str) -> str:
    """Short 'IP (device)' label for charts and tables."""
    d = describe(ip)
    return f"{d['ip']} ({d['device'].split(' · ')[0]})" if d["known"] else d["ip"]
