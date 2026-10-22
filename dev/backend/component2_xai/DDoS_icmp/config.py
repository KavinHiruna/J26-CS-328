"""
Configuration for the DDoS ICMP Flood Explainable-AI component (Component 2).

Every model feature below comes from the project parameter sheet
"DDoS_ICMP_Flood_parameters.xlsx". Source/Destination IP are kept as incident
context only (they are not model inputs, so the model cannot overfit to the
lab's IP addresses).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
MODELS_DIR = PACKAGE_DIR / "models"
DEFAULT_MODEL_PATH = MODELS_DIR / "ddos_icmp_model.joblib"

ATTACK_NAME = "DDoS ICMP Flood"
# Label names used by Edge-IIoTset for this attack (Attack_type column)
ATTACK_TYPE_ALIASES = ("DDoS_ICMP", "DDoS_ICMP_Flood", "DDOS_ICMP", "ICMP_Flood")
NORMAL_TYPE_ALIASES = ("Normal", "normal", "BENIGN", "Benign")

# Width of the traffic window (seconds) used for rate / distribution features
WINDOW_SECONDS = 1.0


@dataclass(frozen=True)
class FeatureSpec:
    name: str            # engineered column name used by the model
    group: str           # group from the parameter sheet
    parameter: str       # parameter name exactly as in the sheet
    why: str             # "Why important for ICMP Flood" (from the sheet)
    unit: str = ""
    model_input: bool = True


FEATURE_SPECS: tuple[FeatureSpec, ...] = (
    FeatureSpec("ip_proto", "Protocol", "ip.proto", "Identifies ICMP traffic"),
    FeatureSpec("icmp_type", "ICMP", "icmp.type", "Identifies Echo Request/Reply etc."),
    FeatureSpec("icmp_code", "ICMP", "icmp.code", "Gives ICMP message subtype"),
    FeatureSpec("frame_len", "Packet", "frame.len", "Packet size", "bytes"),
    FeatureSpec("frame_time_delta", "Packet", "frame.time_delta", "Time between packets", "s"),
    FeatureSpec("pkts_per_sec", "Rate", "Packets/sec", "One of the strongest flood indicators", "pkt/s"),
    FeatureSpec("bytes_per_sec", "Rate", "Bytes/sec", "Measures traffic volume", "B/s"),
    FeatureSpec("flow_duration", "Flow", "Flow duration", "Helps distinguish short bursts", "s"),
    FeatureSpec("flow_pkt_count", "Flow", "Packet count", "Number of packets in the flow/window", "pkts"),
    FeatureSpec("flow_byte_count", "Flow", "Byte count", "Total transferred bytes", "bytes"),
    FeatureSpec("src_ip", "Source", "Source IP", "Identifies traffic source", model_input=False),
    FeatureSpec("dst_ip", "Destination", "Destination IP", "Identifies target", model_input=False),
    FeatureSpec("ttl", "Network", "TTL", "Can provide supporting traffic information"),
    FeatureSpec("unique_src_count", "Distribution", "Unique source IP count", "Very useful for DDoS vs DoS", "IPs"),
    FeatureSpec("src_concentration", "Distribution", "Source packet concentration",
                "Helps identify distributed behaviour", "share"),
)

SPEC_BY_NAME = {s.name: s for s in FEATURE_SPECS}
MODEL_FEATURES: tuple[str, ...] = tuple(s.name for s in FEATURE_SPECS if s.model_input)
CONTEXT_COLUMNS: tuple[str, ...] = ("row_id", "src_ip", "dst_ip", "timestamp", "window_id")


def pretty(feature: str) -> str:
    """Human label for a feature, e.g. 'pkts_per_sec' -> 'Packets/sec'."""
    spec = SPEC_BY_NAME.get(feature)
    return spec.parameter if spec else feature


# ---------------------------------------------------------------------------
# Domain knowledge used by the novelty layer (knowledge-grounded explanation).
# feature, operator, threshold, description. Tune thresholds to your testbed.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DomainRule:
    rule_id: str
    feature: str
    op: str          # one of ">=", "<=", "==", "in"
    value: object
    text: str
    weight: float = 1.0


DOMAIN_RULES: tuple[DomainRule, ...] = (
    DomainRule("R1", "ip_proto", "==", 1, "Packet is ICMP (ip.proto = 1)", 1.0),
    DomainRule("R2", "icmp_type", "in", (8, 0), "ICMP Echo Request/Reply (ping) traffic", 0.8),
    DomainRule("R3", "pkts_per_sec", ">=", 100.0, "Packet rate toward target >= 100 pkt/s", 1.5),
    DomainRule("R4", "frame_time_delta", "<=", 0.01, "Inter-arrival time <= 10 ms (burst)", 1.0),
    DomainRule("R5", "bytes_per_sec", ">=", 10_000.0, "Traffic volume >= 10 kB/s", 1.0),
    DomainRule("R6", "unique_src_count", ">=", 3, "3+ distinct sources hit the target (distributed)", 1.2),
    DomainRule("R7", "src_concentration", "<=", 0.6, "No single source dominates (<= 60% of packets)", 0.8),
)

# DDoS vs DoS attribution thresholds
DISTRIBUTED_MIN_SOURCES = 3
DISTRIBUTED_MAX_CONCENTRATION = 0.6

# Severity bands: (min probability, min pkts/sec, label)
SEVERITY_BANDS = (
    (0.90, 1000.0, "Critical"),
    (0.80, 200.0, "High"),
    (0.60, 0.0, "Medium"),
    (0.00, 0.0, "Low"),
)


# ---------------------------------------------------------------------------
# Component 2 novelty statement shown on the dashboard. Edit the wording here
# so the page always matches the thesis / proposal.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class NoveltyItem:
    key: str
    title: str
    summary: str


COMPONENT2_NOVELTY_TITLE = "Component 2 novelty - trustworthy, incident-level XAI for IIoT DDoS ICMP floods"
COMPONENT2_NOVELTY: tuple[NoveltyItem, ...] = (
    NoveltyItem(
        "consensus",
        "SHAP-LIME Explanation Consensus Score",
        "Two independent explainers are run on the same incident and compared (top-k overlap, "
        "direction agreement, rank correlation). The analyst sees how far the explanation can be trusted, "
        "not just what it says.",
    ),
    NoveltyItem(
        "grounding",
        "Knowledge-grounded alignment with ICMP flood indicators",
        "The model's reasons are checked against protocol-level ICMP flood rules taken from the parameter "
        "study (ICMP protocol, echo traffic, packet rate, inter-arrival, volume, source spread). "
        "An alignment score shows whether the model flagged the incident for the right reasons.",
    ),
    NoveltyItem(
        "counterfactual",
        "Counterfactual 'what would make it benign'",
        "A minimal set of feature changes that would flip the decision to benign, giving the analyst an "
        "actionable view of which traffic properties actually drive the alert.",
    ),
    NoveltyItem(
        "attribution",
        "Distributed-vs-single-source attribution",
        "Unique source count and source packet concentration are used to tell a distributed (DDoS) flood from "
        "a single-host (DoS) flood and to choose the right mitigation.",
    ),
    NoveltyItem(
        "report",
        "Analyst-ready incident narrative and mitigation",
        "Every decision is turned into a plain-language incident report with severity, evidence, and "
        "recommended response, exportable as JSON / Markdown for the SOC workflow.",
    ),
)


@dataclass
class ExplainSettings:
    background_rows: int = 300
    compute_shap: bool = True
    compute_lime: bool = True
    threshold: float = 0.5
    top_k: int = 10
    random_state: int = 42
    lime_samples: int = 2000
    extra: dict = field(default_factory=dict)
