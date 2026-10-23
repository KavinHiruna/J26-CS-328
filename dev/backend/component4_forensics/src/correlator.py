"""
Stage 3: Event Correlation (IT-OT Evidence Correlation)
Correlates evidence across IT sources (firewall, IDS) and OT sources
(SCADA engineering workstation, substation PLC logs) using shared
IP/asset identifiers within a configurable time window.
"""

import re
from dataclasses import dataclass
import ipaddress
from datetime import timedelta
from typing import List
from log_loader import EvidenceRecord

IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


@dataclass
class CorrelatedCluster:
    """A group of evidence records believed to relate to the same attack activity."""
    cluster_id: int
    key_ip: str
    records: List[EvidenceRecord]

    @property
    def start(self):
        return min(r.timestamp for r in self.records)

    @property
    def end(self):
        return max(r.timestamp for r in self.records)

    @property
    def sources(self):
        return sorted(set(r.source for r in self.records))


def correlate_evidence(evidence: List[EvidenceRecord],
                        time_window_minutes: int = 5) -> List[CorrelatedCluster]:
    """
    Groups IT (firewall/IDS) and OT (device/PLC) evidence records that share
    an IP address or asset identifier (including IPs embedded in OT asset
    names, e.g. "Substation-Breaker-PLC-10.10.0.50") and fall within
    `time_window_minutes` of one another.

        Firewall Log -> IDS Alert -> OT Device Log -> Correlated Attack Evidence
    """
    window = timedelta(minutes=time_window_minutes)

    def keys_for(r: EvidenceRecord):
        ks = set()
        if r.src_ip:
            ks.add(r.src_ip)
        if r.dst_ip:
            ks.add(r.dst_ip)
        if r.asset:
            ks.add(r.asset)
        for field_val in (r.asset, r.description):
            if field_val:
                ks.update(IP_RE.findall(field_val))
        return ks

    clusters: List[CorrelatedCluster] = []
    ordered = sorted(evidence, key=lambda r: r.timestamp)

    for record in ordered:
        placed = False
        rec_keys = keys_for(record)
        for cluster in clusters:
            cluster_keys = set()
            for r in cluster.records:
                cluster_keys |= keys_for(r)
            shares_key = bool(rec_keys & cluster_keys)
            within_time = (record.timestamp - cluster.end) <= window
            if shares_key and within_time:
                cluster.records.append(record)
                placed = True
                break
        if not placed:
            new_id = len(clusters) + 1
            key_ip = record.src_ip or record.dst_ip or record.asset or "unknown"
            clusters.append(CorrelatedCluster(cluster_id=new_id, key_ip=key_ip,
                                               records=[record]))

    # Merge clusters that grow to share keys (second pass)
    merged = True
    while merged:
        merged = False
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                ki = set()
                for r in clusters[i].records:
                    ki |= keys_for(r)
                kj = set()
                for r in clusters[j].records:
                    kj |= keys_for(r)
                if ki & kj:
                    clusters[i].records.extend(clusters[j].records)
                    del clusters[j]
                    merged = True
                    break
            if merged:
                break

    # Keep only clusters corroborated by 2+ independent sources (IT + OT)
    significant = [c for c in clusters if len(c.sources) >= 2]
    for idx, c in enumerate(significant, start=1):
        c.cluster_id = idx
        c.records.sort(key=lambda r: r.timestamp)
    return significant


# ===========================================================================
# v2: Seeded (incident-driven) IT-OT correlation
# ---------------------------------------------------------------------------
# The v1 engine above links ANY records that share an IP within a time window.
# On real plant traffic that merges routine activity (HMI polling the PLC, etc.)
# into the attack cluster, because the attacker and the plant share assets.
#
# v2 instead starts from the confirmed incident handed over by Component 3
# (seed attacker IPs) and follows the ATTACKER'S ACTIONS forward in time:
#   * a firewall/IDS record is relevant only if its SOURCE is an attacker-
#     controlled host ("actor");
#   * a device (OT) event is relevant only if it happened on a host the actors
#     touched AND it is a high-signal event (or explicitly references an actor);
#   * a host becomes an actor once attacker activity is confirmed on it, so
#     pivots (VPN gateway -> historian -> EMS -> relay) are followed.
# ===========================================================================
HIGH_SIGNAL_EVENTS = {
    "auth_fail", "auth_success", "cred_dump", "file_write", "process_start",
    "config_access", "logic_change", "state_change", "setpoint_change",
}
_PLANT_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_plant_ip(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in _PLANT_NETS)
    except ValueError:
        return False


LOGIN_LIKE_EVENTS = {"login", "vpn_login", "rdp_session", "remote_login"}

# Rules that ablation.py can switch off one at a time (all rules are ON when this set is empty).
#   reverse_seed, flow_history, policy_filter, auth_fail_rule, login_needs_actor,
#   ignore_routine_device, keep_all_groups, corroboration
ABLATE = set()


def correlate_seeded(evidence: List[EvidenceRecord],
                     seed_ips: List[str],
                     time_window_minutes: int = 5,
                     min_sources: int = 2) -> List[CorrelatedCluster]:
    window = timedelta(minutes=time_window_minutes)
    actors = set(seed_ips)       # attacker-controlled hosts (grows as the attack pivots)
    touched = set()              # hosts the actors have connected to
    groups: List[List[EvidenceRecord]] = []
    last_time = None
    seed_set = set(seed_ips)
    flows_seen = {}              # host -> set of (dst_ip, port) flows it made so far
    baseline = {}                # pivoted host -> flows it made BEFORE it was compromised

    for r in sorted(evidence, key=lambda x: x.timestamp):
        include = False

        # Reverse direction: a plant host that connects OUT to a seed address (C2 beaconing,
        # data exfiltration) is compromised, even though the seed never appears as a source.
        if ("reverse_seed" not in ABLATE and r.source in ("firewall", "ids") and r.dst_ip in seed_set
                and r.src_ip not in actors and _is_plant_ip(r.src_ip)):
            include = True
            baseline[r.src_ip] = set(flows_seen.get(r.src_ip, ()))
            actors.add(r.src_ip)
            if r.src_ip:
                touched.add(r.src_ip)

        elif r.source == "firewall":
            flow = (r.dst_ip, str(r.raw.get("dst_port", "")))
            if r.src_ip in actors:
                # a pivoted host's routine flows (seen before the compromise) are not attack evidence
                routine = ("flow_history" not in ABLATE and r.src_ip not in seed_set
                           and flow in baseline.get(r.src_ip, ()))
                include = not routine
                if include and r.dst_ip and "/" not in r.dst_ip:
                    touched.add(r.dst_ip)
            else:
                flows_seen.setdefault(r.src_ip, set()).add(flow)

        elif r.source == "ids":
            if r.src_ip in actors:
                # low-severity policy alerts from a pivoted host are routine polling, not attack steps
                routine = ("policy_filter" not in ABLATE and r.src_ip not in seed_set and r.severity == "Low"
                           and r.raw.get("category") == "Policy")
                include = not routine
                if include and r.dst_ip and "/" not in r.dst_ip:      # ignore subnet-wide scan targets
                    touched.add(r.dst_ip)

        elif r.source == "device":
            found = IP_RE.findall(r.asset or "")
            host_ip = found[0] if found else None
            # IPs mentioned in the event text, excluding the host's own address
            others = [ip for ip in IP_RE.findall(r.description or "") if ip != host_ip]
            refs_actor = any(ip in actors for ip in others)

            if host_ip and (host_ip in touched or refs_actor):
                if r.event_type in LOGIN_LIKE_EVENTS:
                    include = refs_actor or "login_needs_actor" in ABLATE   # a login only counts if tied to an actor
                elif r.event_type == "auth_fail":
                    # one mistyped password is routine; repeated failures or an actor reference are not
                    m = re.search(r"\((\d+) attempts?\)", r.description or "")
                    include = (refs_actor or (m is not None and int(m.group(1)) >= 2)
                               or "auth_fail_rule" in ABLATE)
                elif r.event_type in HIGH_SIGNAL_EVENTS:
                    include = True
                else:
                    include = refs_actor or "ignore_routine_device" in ABLATE   # routine events are ignored
            if include and host_ip:
                if host_ip not in actors:
                    baseline[host_ip] = set(flows_seen.get(host_ip, ()))   # its pre-compromise behaviour
                actors.add(host_ip)                 # attacker now controls this host

        if not include:
            continue

        # split into a new cluster when the chain of linked events has a long gap
        if groups and last_time is not None and (r.timestamp - last_time) > window:
            groups.append([r])
        elif groups:
            groups[-1].append(r)
        else:
            groups.append([r])
        last_time = r.timestamp

    clusters: List[CorrelatedCluster] = []
    built = [CorrelatedCluster(cluster_id=0, key_ip=seed_ips[0] if seed_ips else "unknown", records=g)
             for g in groups]
    # IT + OT corroboration is required, but a long pause inside one attacker chain must not drop
    # the part of the chain on the far side of the pause: if any group is corroborated, keep all.
    need = 1 if "corroboration" in ABLATE else min_sources
    if "keep_all_groups" in ABLATE:
        clusters = [c for c in built if len(c.sources) >= need]
    elif any(len(c.sources) >= need for c in built):
        clusters = built
    for i, c in enumerate(clusters, start=1):
        c.cluster_id = i
    return clusters
