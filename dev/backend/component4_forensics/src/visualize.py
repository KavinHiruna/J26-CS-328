"""
Stage 6: Evidence Visualization

Produces, per incident, from the reconstructed timeline and root cause analysis:
    timeline_chart.png      events over time, one lane per asset
    attack_flow.png         ordered attack stages (top to bottom)
    correlation_graph.png   who-connected-to-whom graph with the attacker and
                            compromised assets highlighted
    dashboard.html          one self-contained page that shows all of the above

Charts are coloured by attack stage (theme.py). Every stage also has a text label and a
marker shape, so the charts still read in black and white. Requires: pip install matplotlib networkx
"""

import html
import os
import re
import textwrap
from datetime import datetime

import matplotlib
matplotlib.use("Agg")                      # no GUI needed (works on any machine)
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.lines import Line2D
from matplotlib.patches import FancyBboxPatch
import networkx as nx

from timeline_rca import canonical_stage
from theme import (STAGE_COLOR, stage_color, text_on, INK, MUTED, GRID, ATTACKER, COMPROMISED, TOUCHED,
                   FLAGGED_EDGE, PLAIN_EDGE, SOURCE_COLOR)

IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

STAGE_MARKERS = {
    "Reconnaissance": "p", "Initial Access": "s", "Credential Access": "^",
    "Malware Delivery": "v", "Execution": "D", "Lateral Movement": "P",
    "Discovery": "h", "Command and Control": "H", "Impact": "*", "Network Connection": "o", "Uncategorized": "8",
}
STAGE_SIZE = {"Impact": 260, "Network Connection": 35}
SOURCE_FACE = {"firewall": "white", "ids": "0.6", "device": "black"}
SUBROW = {"firewall": -0.26, "ids": 0.0, "device": 0.26}   # keeps simultaneous events apart
SOURCE_NAME = {"firewall": "Firewall (IT)", "ids": "IDS alert (IT)", "device": "Device log (OT)"}


# ---------------------------------------------------------------- helpers
def _names_by_ip(evidence):
    names = {}
    for r in evidence:
        if r.source == "device":
            m = IP_RE.search(r.asset or "")
            if m:
                names.setdefault(m.group(0), r.asset)
    return names


def _label(asset, names):
    if not asset:
        return "n/a"
    if "/" in asset:
        return f"{asset} (subnet)"
    m = IP_RE.fullmatch(asset)
    return names.get(asset, asset) if m else asset


def _stage_runs(timeline, names):
    """Consecutive events with the same stage are merged into one run (firewall lines skipped)."""
    runs = []
    for e in timeline:
        if e.source == "firewall":
            continue
        st = canonical_stage(e.stage)
        lbl = _label(e.asset, names)
        if runs and runs[-1]["stage"] == st:
            runs[-1]["end"] = e.timestamp
            if lbl not in runs[-1]["assets"]:
                runs[-1]["assets"].append(lbl)
        else:
            runs.append({"stage": st, "start": e.timestamp, "end": e.timestamp, "assets": [lbl]})
    return runs


# ---------------------------------------------------------------- charts
def plot_timeline(timeline, names, out_path, title):
    t_of = lambda e: datetime.strptime(e.timestamp, "%H:%M:%S")
    lanes = []
    for e in timeline:
        lane = _label(e.asset, names)
        if lane not in lanes:
            lanes.append(lane)
    ypos = {lane: i for i, lane in enumerate(reversed(lanes))}      # first lane on top

    fig, ax = plt.subplots(figsize=(11.5, max(4.0, 0.95 * len(lanes) + 2.6)))
    seen_stages, prev_stage, n_labels = [], None, 0
    for e in timeline:
        st = canonical_stage(e.stage)
        y = ypos[_label(e.asset, names)] + SUBROW[e.source]
        face = stage_color(st)
        ax.scatter(t_of(e), y, marker=STAGE_MARKERS.get(st, "8"), s=STAGE_SIZE.get(st, 75),
                   facecolors=face, edgecolors=SOURCE_COLOR[e.source], linewidths=1.3 if e.source != "firewall" else 0.8,
                   zorder=3)
        if st not in seen_stages:
            seen_stages.append(st)
        if e.source != "firewall":
            if st != prev_stage:
                lift = 11 + 15 * (n_labels % 2)                  # alternate heights so labels do not collide
                ax.annotate(st, (t_of(e), y), xytext=(2, lift), textcoords="offset points",
                            fontsize=7.5, rotation=25, ha="left", va="bottom", color=INK, fontweight="bold")
                n_labels += 1
            prev_stage = st

    ax.set_yticks(list(ypos.values()))
    ax.set_yticklabels(list(ypos.keys()), fontsize=8)
    ax.xaxis.set_major_locator(mdates.AutoDateLocator(maxticks=9))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.tick_params(axis="x", labelsize=8)
    ax.grid(axis="y", linestyle=":", color=GRID, zorder=0)
    ax.margins(x=0.06, y=0.18)
    ax.set_title(title, fontsize=11, fontweight="bold")
    ax.set_xlabel("Inside each lane:  top = device log (OT)   |   middle = IDS alert   |   bottom = firewall", fontsize=8, color=MUTED)

    handles = [Line2D([0], [0], marker=STAGE_MARKERS.get(s, "8"), color="w", markerfacecolor=stage_color(s),
                      markeredgecolor=INK, markersize=9 if s != "Network Connection" else 5, label=s)
               for s in seen_stages]
    handles += [Line2D([0], [0], marker="o", color="w", markerfacecolor="white",
                       markeredgecolor=SOURCE_COLOR[k], markeredgewidth=2, markersize=9, label=SOURCE_NAME[k] + " outline")
                for k in SOURCE_COLOR]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.16),
              ncol=5, fontsize=7.5, frameon=False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=170, bbox_inches="tight")
    plt.close(fig)


def plot_attack_flow(timeline, names, out_path, title):
    runs = _stage_runs(timeline, names)
    n = max(len(runs), 1)
    step, box_h = 1.25, 0.85
    fig, ax = plt.subplots(figsize=(8, 1.15 * n + 1.0))
    ax.set_xlim(0, 10)
    ax.set_ylim(-0.4, step * n + 0.3)
    ax.axis("off")
    ax.set_title(title, fontsize=11, fontweight="bold")

    for i, run in enumerate(runs):
        y = (n - 1 - i) * step
        last = i == len(runs) - 1
        col = stage_color(run["stage"])
        ax.add_patch(FancyBboxPatch((0.8, y), 8.4, box_h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                    fc="white", ec=col, lw=1.6))
        ax.add_patch(FancyBboxPatch((0.8, y), 0.35, box_h, boxstyle="round,pad=0.0,rounding_size=0.12",
                                    fc=col, ec=col, lw=1.0))             # coloured stage tab
        if last:                                                    # double border = final stage
            ax.add_patch(FancyBboxPatch((0.68, y - 0.08), 8.64, box_h + 0.16,
                                        boxstyle="round,pad=0.02,rounding_size=0.14",
                                        fc="none", ec=col, lw=1.6))
        span = run["start"] if run["start"] == run["end"] else f"{run['start']} - {run['end']}"
        ax.text(1.4, y + box_h * 0.64, f"{i + 1}. {run['stage']}", fontsize=10.5, fontweight="bold", va="center", color=INK)
        ax.text(8.9, y + box_h * 0.64, span, fontsize=8.5, va="center", ha="right", color=MUTED)
        assets = ", ".join(run["assets"])
        ax.text(1.4, y + box_h * 0.24, textwrap.shorten(assets, 92, placeholder=" ..."), fontsize=8, va="center", color=MUTED)
        if not last:
            ax.annotate("", xy=(5, y - step + box_h + (0.12 if i + 1 == len(runs) - 1 else 0.02)), xytext=(5, y - 0.02),
                        arrowprops=dict(arrowstyle="-|>", lw=1.5, color=MUTED))
    fig.savefig(out_path, dpi=170, bbox_inches="tight")
    plt.close(fig)


def _edge_label(d):
    span = d["first"] if d["first"] == d["last"] else f"{d['first']}-{d['last']}"
    head = "\n".join(d["stages"]) if d["stages"] else "connection"
    return f"{head}\n{span}"


def plot_correlation_graph(timeline, rca, names, seed_ips, out_path, title):
    G = nx.DiGraph()
    info = {}
    for e in timeline:
        if e.source in ("firewall", "ids") and e.src_ip and e.dst_ip:
            d = info.setdefault((e.src_ip, e.dst_ip), {"first": e.timestamp, "last": e.timestamp, "stages": []})
            d["last"] = e.timestamp
            st = canonical_stage(e.stage)
            if st != "Network Connection" and st not in d["stages"]:
                d["stages"].append(st)
    for (s, d), v in info.items():
        G.add_edge(s, d, **v)
    comp = set(IP_RE.findall(" ".join(rca.compromised_energy_assets)))
    for ip in list(comp) + list(seed_ips):
        G.add_node(ip)

    # layer = longest time-ordered path from the attacker, so a host that is reached directly AND
    # through a pivot (e.g. attacker -> PLC and workstation -> PLC) is drawn after the pivot
    depth = {ip: 0 for ip in seed_ips if ip in G}
    ordered_edges = sorted(G.edges(data=True), key=lambda x: x[2]["first"])
    for _ in range(len(G)):
        changed = False
        for u, v, d in ordered_edges:
            if u in depth and v not in seed_ips and depth[u] + 1 > depth.get(v, -1) and depth[u] + 1 < len(G):
                depth[v] = depth[u] + 1
                changed = True
        if not changed:
            break
    maxd = max(depth.values(), default=0)
    for node in G.nodes:
        depth.setdefault(node, maxd + 1)
    layers = {}
    for node, dp in depth.items():
        layers.setdefault(dp, []).append(node)
    pos = {}
    for dp, nodes in layers.items():
        nodes = sorted(nodes, key=lambda n: (n in comp, n))          # compromised hosts at the bottom
        for i, node in enumerate(nodes):
            pos[node] = (dp * 4.8, -(i - (len(nodes) - 1) / 2) * 2.4)

    attackers = [n for n in G.nodes if n in seed_ips]
    compromised = [n for n in G.nodes if n in comp and n not in seed_ips]
    others = [n for n in G.nodes if n not in attackers and n not in compromised]
    wrap = lambda n: textwrap.fill(re.sub(r"-(?=\d)", "- ", _label(n, names)), 12, break_long_words=False).replace("- ", "-")

    biggest_layer = max(len(v) for v in layers.values())
    fig, ax = plt.subplots(figsize=(max(11.5, 3.6 * (max(layers) + 1) + 2.0), max(4.4, 1.35 * biggest_layer + 2.4)))
    solid = [(u, v) for u, v, d in G.edges(data=True) if d["stages"]]
    dashed = [(u, v) for u, v, d in G.edges(data=True) if not d["stages"]]
    node_size = 3900
    for edges, style in ((solid, "solid"), (dashed, "dashed")):
        if edges:
            nx.draw_networkx_edges(G, pos, edgelist=edges, ax=ax, style=style, width=1.6, arrows=True,
                                   arrowstyle="-|>", arrowsize=20, node_size=node_size,
                                   connectionstyle="arc3,rad=0.07",
                                   edge_color=FLAGGED_EDGE if style == "solid" else PLAIN_EDGE)
    nx.draw_networkx_nodes(G, pos, nodelist=others, node_shape="o", node_size=node_size, node_color=TOUCHED,
                           edgecolors=INK, linewidths=1.2, ax=ax)
    nx.draw_networkx_nodes(G, pos, nodelist=compromised, node_shape="s", node_size=node_size, node_color=COMPROMISED,
                           edgecolors=INK, linewidths=1.8, ax=ax)
    nx.draw_networkx_nodes(G, pos, nodelist=attackers, node_shape="D", node_size=node_size, node_color=ATTACKER,
                           edgecolors=INK, linewidths=1.2, ax=ax)
    for group, color in ((others, INK), (compromised, "#111111"), (attackers, "white")):
        nx.draw_networkx_labels(G, pos, labels={n: wrap(n) for n in group}, font_size=6.5,
                                font_color=color, ax=ax)
    edge_labels = {(u, v): _edge_label(d) for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7, ax=ax, rotate=False,
                                 bbox=dict(boxstyle="round,pad=0.15", fc="white", ec=GRID, lw=0.8), font_color=INK)
    ax.set_title(title, fontsize=11, fontweight="bold")
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    ax.set_xlim(min(xs) - 2.4, max(xs) + 2.4)
    ax.set_ylim(min(ys) - 2.0, max(ys) + 2.0)
    ax.axis("off")
    legend = [
        Line2D([0], [0], marker="D", color="w", markerfacecolor=ATTACKER, markeredgecolor=INK, markersize=10, label="Attacker / origin"),
        Line2D([0], [0], marker="s", color="w", markerfacecolor=COMPROMISED, markeredgecolor=INK, markersize=10,
               label="Compromised asset"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor=TOUCHED, markeredgecolor=INK, markersize=10,
               label="Touched / scanned host"),
        Line2D([0], [0], color=FLAGGED_EDGE, lw=1.8, label="IDS-flagged activity"),
        Line2D([0], [0], color=PLAIN_EDGE, lw=1.8, linestyle="--", label="Connection only"),
    ]
    ax.legend(handles=legend, loc="lower center", bbox_to_anchor=(0.5, -0.02), ncol=5, fontsize=8, frameon=False)
    fig.savefig(out_path, dpi=170, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------- dashboard
def write_dashboard(out_dir, incident, rca, timeline, figures, names):
    esc = html.escape
    rows = "".join(
        f"<tr><td>{e.timestamp}</td><td>{esc(canonical_stage(e.stage))}</td>"
        f"<td>{esc(_label(e.asset, names))}</td><td>{e.source}</td><td>{esc(e.description)}</td></tr>"
        for e in timeline)
    cards = [
        ("Incident", incident.get("incident_id", "n/a")),
        ("Origin", f"{rca.origin_type} ({rca.entry_point_ip})"),
        ("Initial vector", rca.initial_vector),
        ("Compromised", ", ".join(rca.compromised_energy_assets) or "none"),
    ]
    card_html = "".join(f"<div class='card'><span>{esc(k)}</span><b>{esc(v)}</b></div>" for k, v in cards)
    figs = "".join(f"<h2>{esc(t)}</h2><img src='{esc(f)}' alt='{esc(t)}'>" for t, f in figures.items())
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Investigation Dashboard - {esc(incident.get('incident_id', ''))}</title>
<style>
body{{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;margin:0;padding:24px;color:#1c2430;background:#f3f5f8}}
h1{{margin-bottom:4px;color:#14213d}} h2{{margin-top:28px;border-bottom:2px solid #14213d;padding-bottom:4px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}}
.card{{background:#fff;border:1px solid #dde2e9;border-left:4px solid #d03b3b;border-radius:8px;padding:10px 14px;min-width:180px}} .card span{{display:block;font-size:12px;color:#5b6573}}
img{{max-width:100%;background:#fff;border:1px solid #dde2e9;border-radius:8px;padding:6px;margin-top:8px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border:1px solid #888;padding:5px 8px;text-align:left}}
th{{background:#14213d;color:#fff}}
</style></head><body>
<h1>Investigation Dashboard</h1>
<div>Energy plant IIoT / SCADA incident - confirmed by {esc(incident.get('source_component', 'SOC component'))}</div>
<div class="cards">{card_html}</div>
{figs}
<h2>Event timeline</h2>
<table><tr><th>Time</th><th>Stage</th><th>Asset</th><th>Source</th><th>Description</th></tr>{rows}</table>
</body></html>"""
    with open(os.path.join(out_dir, "dashboard.html"), "w", encoding="utf-8") as f:
        f.write(page)


def generate_all(out_dir, incident, timeline, rca, evidence):
    """Create every Stage-6 artefact; returns {figure title: file name} for the report."""
    os.makedirs(out_dir, exist_ok=True)
    names = _names_by_ip(evidence)
    inc = incident.get("incident_id", "")
    seeds = incident.get("seed_ips", [])
    figures = {
        "Attack timeline": "timeline_chart.png",
        "Attack flow": "attack_flow.png",
        "Correlation graph (attack path)": "correlation_graph.png",
    }
    plot_timeline(timeline, names, os.path.join(out_dir, "timeline_chart.png"), f"Attack timeline - {inc}")
    plot_attack_flow(timeline, names, os.path.join(out_dir, "attack_flow.png"), f"Attack flow - {inc}")
    plot_correlation_graph(timeline, rca, names, seeds, os.path.join(out_dir, "correlation_graph.png"),
                           f"Correlation graph - {inc}")
    write_dashboard(out_dir, incident, rca, timeline, figures, names)
    return figures
