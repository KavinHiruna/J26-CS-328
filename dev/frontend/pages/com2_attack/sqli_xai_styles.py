"""
Component 2 - SQLi XAI dashboard styles (colours, fonts, CSS and small HTML blocks).

Location : dev/backend/component2_xai/sqli_xai_styles.py
Used by  : dev/frontend/pages/com2_attack/sqli_xai_novelty_page.py

Change colours or fonts here only - the page itself contains no styling.
Palette follows the XAI-IDS design (navy sidebar, light background, white cards, blue actions).
"""
from __future__ import annotations

import html

# ---------------------------------------------------------------- colours
COLORS = {
    "navy": "#0b2545",          # headings, main text
    "navy_light": "#123a6b",    # sidebar top
    "navy_dark": "#0c2446",     # sidebar bottom
    "blue": "#1f6fe5",          # buttons, charts, accents
    "blue_hover": "#1859c0",
    "page_bg": "#eef3f9",       # page background
    "card_bg": "#ffffff",       # cards
    "card_border": "#dbe4ef",
    "muted": "#5b6b82",         # captions, secondary text
    "text": "#22344f",          # body text in cards
    "code_bg": "#f3f6fb",
    "sidebar_text": "#e8f0fb",
}

# status pills: kind -> (background, text)
PILLS = {
    "red": ("#fde2e4", "#c8233c"),
    "amber": ("#fff1c2", "#8a5a00"),
    "green": ("#d8f3e0", "#1b7a3a"),
    "blue": ("#dce8ff", "#1f5fd1"),
    "grey": ("#e7ecf3", "#4a5b73"),
}

# chart colours (used with st.bar_chart(color=...))
CHART = {"primary": COLORS["blue"], "secondary": COLORS["navy"]}

# heat-map legend (must match render_attribution_html in sqli_xai_engine.py)
HEAT = {"towards_attack": "#e04848", "away_from_attack": "#3b82f6"}

# ---------------------------------------------------------------- fonts
FONTS = {
    "body": "'Inter', 'Segoe UI', Roboto, Arial, sans-serif",
    "mono": "Consolas, 'Courier New', monospace",
    "google_import": "https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap",
    "size_body": "0.95rem",
    "size_small": "0.8rem",
    "size_heading": "1.6rem",
}


# ---------------------------------------------------------------- CSS
def page_css() -> str:
    c, f = COLORS, FONTS
    return f"""
<style>
@import url('{f["google_import"]}');
html, body, .stApp, [class*="css"] {{font-family:{f["body"]}}}
.stApp {{background:{c["page_bg"]};color:{c["navy"]}}}
[data-testid="stHeader"] {{background:transparent}}
.block-container {{max-width:1450px;padding-top:1.2rem}}
h1, h2, h3, h4 {{color:{c["navy"]};font-weight:800}}

/* sidebar */
[data-testid="stSidebar"] {{background:linear-gradient(180deg,{c["navy_light"]} 0%,{c["navy_dark"]} 100%)}}
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3,
[data-testid="stSidebar"] label, [data-testid="stSidebar"] p, [data-testid="stSidebar"] span,
[data-testid="stSidebar"] small {{color:{c["sidebar_text"]} !important}}
[data-testid="stSidebar"] [data-baseweb="select"] *, [data-testid="stSidebar"] input {{color:{c["navy"]} !important}}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {{background:rgba(255,255,255,.08);
  border:1px dashed rgba(255,255,255,.35)}}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button span {{color:{c["navy"]} !important}}

/* incident lookup widgets */
.st-key-incident_id_search label, .st-key-incident_id_search input,
.st-key-incident_selector label, .st-key-incident_selector [data-baseweb="select"] * {{
  color:#000 !important
}}
/* incident lookup widgets */
.st-key-incident_id_search label, .st-key-incident_id_search input,
.st-key-incident_selector label, .st-key-incident_selector [data-baseweb="select"] * {{
  color:#000 !important
}}

/* buttons */
.stButton>button, .stDownloadButton>button {{background:{c["blue"]};color:#fff;border:0;border-radius:8px;font-weight:600}}
.stButton>button:hover, .stDownloadButton>button:hover {{background:{c["blue_hover"]};color:#fff}}

/* metric cards */
[data-testid="stMetric"] {{background:{c["card_bg"]};border:1px solid {c["card_border"]};border-radius:12px;
  padding:12px 16px;box-shadow:0 2px 10px rgba(15,43,82,.05)}}
[data-testid="stMetricLabel"] p {{color:{c["muted"]};font-weight:600}}
[data-testid="stMetricValue"] {{color:{c["navy"]}}}
[data-testid="stMetricDelta"], [data-testid="stMetricDelta"] * {{color:#000 !important}}

/* page parts */
.page-title {{font-size:{f["size_heading"]};font-weight:800;color:{c["navy"]};margin:0 0 2px}}
.page-sub {{color:{c["muted"]};font-size:{f["size_small"]};margin-bottom:12px}}
.section-title {{font-size:1rem;font-weight:800;letter-spacing:.03em;text-transform:uppercase;
  color:{c["navy"]};margin:18px 0 8px;padding-left:10px;border-left:4px solid {c["blue"]}}}
.heat {{background:#f7f9fc;border:1px solid {c["card_border"]};border-radius:10px;padding:14px;color:{c["text"]};
  font-family:{f["mono"]};font-size:.92rem;line-height:1.95;overflow-wrap:anywhere}}
.narrative {{background:{c["card_bg"]};border:1px solid {c["card_border"]};border-left:5px solid {c["blue"]};
  border-radius:10px;padding:14px 16px;line-height:1.65;color:{c["text"]}}}
.tech {{background:{c["card_bg"]};border:1px solid {c["card_border"]};border-radius:10px;padding:10px 12px;
  margin-bottom:8px;color:{c["text"]}}}
.tech .meta {{color:{c["muted"]};font-size:{f["size_small"]}}}
.legend span {{display:inline-block;padding:2px 10px;border-radius:6px;margin:0 8px 8px 0;
  font-size:{f["size_small"]};color:#fff;font-weight:600}}
.pill {{display:inline-block;padding:2px 10px;border-radius:6px;font-size:.78rem;font-weight:700;margin:1px 3px 1px 0}}
code {{color:#c8233c;background:{c["code_bg"]}}}
</style>
"""


def apply_theme(st) -> None:
    """Inject the dashboard CSS. Call once, right after st.set_page_config()."""
    st.markdown(page_css(), unsafe_allow_html=True)


# ---------------------------------------------------------------- HTML building blocks
def pill(text: str, kind: str = "grey") -> str:
    bg, fg = PILLS.get(kind, PILLS["grey"])
    return f'<span class="pill" style="background:{bg};color:{fg}">{html.escape(str(text))}</span>'


def level_kind(level: str) -> str:
    """Map Critical/High/Medium/Low to a pill colour."""
    return {"critical": "red", "high": "red", "medium": "amber", "low": "green"}.get(str(level).lower(), "grey")


def page_header(title: str, subtitle: str = "") -> str:
    return (f'<div class="page-title">🛡️ {html.escape(title)}</div>'
            f'<div class="page-sub">{html.escape(subtitle)}</div>')


def section_title(text: str) -> str:
    return f'<div class="section-title">{html.escape(text)}</div>'


def narrative_box(text: str) -> str:
    return f'<div class="narrative"><b>Analyst summary.</b> {html.escape(text)}</div>'


def heat_legend() -> str:
    return (f'<div class="legend"><span style="background:{HEAT["towards_attack"]}">pushes towards attack</span>'
            f'<span style="background:{HEAT["away_from_attack"]}">pushes away from attack</span></div>')


def heat_box(inner_html: str) -> str:
    """inner_html must already be escaped (render_attribution_html does this)."""
    return f'<div class="heat">{inner_html}</div>'


def technique_card(t: dict) -> str:
    sev = t["severity"]
    level = "High" if sev >= 0.75 else "Medium" if sev >= 0.55 else "Low"
    border = PILLS[level_kind(level)][1]
    return (f'<div class="tech" style="border-left:4px solid {border}">'
            f'<b>{html.escape(t["technique"])}</b> {pill(level, level_kind(level))}'
            f'{pill(t["cwe"], "blue")}{pill(t["capec"], "blue")}{pill("ATT&CK " + t["attack"], "blue")}<br>'
            f'<span class="meta">Evidence: <code>{html.escape(t["evidence"])}</code></span><br>'
            f'{html.escape(t["recommendation"])}</div>')
