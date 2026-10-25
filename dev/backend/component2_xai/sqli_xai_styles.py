"""
Component 2 - SQLi XAI dashboard styles (colours, fonts, CSS and small HTML blocks).

Location : dev/backend/component2_xai/sqli_xai_styles.py
Used by  : dev/frontend/pages/com2_attack/web_injection.py

Change colours or fonts here only - the page itself contains no styling.
Dark theme matching the DDoS XAI dashboard design.
"""
from __future__ import annotations

import html

# ---------------------------------------------------------------- colours
# Dark theme (matches DDoS pages)
COLORS = {
    "navy": "#e6ecff",          # headings, main text (light on dark)
    "navy_light": "#1e6fe8",    # sidebar top (bright blue)
    "navy_dark": "#0d47a1",     # sidebar bottom (deep blue)
    "blue": "#4cc9f0",          # buttons, charts, accents
    "blue_hover": "#3ab8df",
    "page_bg": "#0b1020",       # page background (dark navy)
    "panel": "#121a2f",         # cards, panels
    "card_bg": "#121a2f",       # cards (dark panel)
    "card_border": "#1f2b4a",   # dark borders
    "panel_border": "#1f2b4a",
    "soft_bg": "#121a2f",       # heat-map box (same as panel)
    "muted": "#8a96b8",         # captions, secondary text
    "text": "#e6ecff",          # body text in cards
    "code_bg": "#1a2340",
    "sidebar_text": "#ffffff",
    "attack": "#ff4d6d",
    "normal": "#2ec4b6",
    "warn": "#ffb703",
    "accent": "#4cc9f0",
}

# status pills: kind -> (background, text)
PILLS = {
    "red": ("rgba(255,77,109,.18)", "#ff4d6d"),
    "amber": ("rgba(255,183,3,.18)", "#ffb703"),
    "green": ("rgba(46,196,182,.18)", "#2ec4b6"),
    "blue": ("rgba(76,201,240,.18)", "#4cc9f0"),
    "grey": ("rgba(138,150,184,.18)", "#8a96b8"),
}

# chart colours (used with st.bar_chart(color=...))
CHART = {"primary": COLORS["accent"], "secondary": "#64a3f5"}

# heat-map legend (must match render_attribution_html in sqli_xai_engine.py)
HEAT = {"towards_attack": "#ff4d6d", "away_from_attack": "#4cc9f0"}

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
.stApp {{background:radial-gradient(1200px 600px at 10% -10%, #16224a 0%, {c["page_bg"]} 55%);color:{c["text"]}}}
[data-testid="stHeader"] {{background:transparent}}
.block-container {{max-width:1450px;padding-top:1.2rem}}
h1, h2, h3, h4 {{color:{c["text"]};font-weight:800}}

/* sidebar */
[data-testid="stSidebar"] {{background:linear-gradient(180deg,{c["navy_light"]} 0%,{c["navy_dark"]} 100%)}}
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3,
[data-testid="stSidebar"] label, [data-testid="stSidebar"] p, [data-testid="stSidebar"] span,
[data-testid="stSidebar"] small {{color:{c["sidebar_text"]} !important}}
[data-testid="stSidebar"] [data-baseweb="select"] *, [data-testid="stSidebar"] input {{color:{c["navy_dark"]} !important}}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {{background:rgba(255,255,255,.08);
  border:1px dashed rgba(255,255,255,.35)}}
[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button span {{color:{c["navy_dark"]} !important}}

/* buttons */
.stButton>button, .stDownloadButton>button {{background:{c["blue"]};color:{c["page_bg"]};border:0;border-radius:8px;font-weight:600}}
.stButton>button:hover, .stDownloadButton>button:hover {{background:{c["blue_hover"]};color:{c["page_bg"]}}}

/* metric cards */
[data-testid="stMetric"] {{background:{c["panel"]};border:1px solid {c["panel_border"]};border-radius:12px;
  padding:12px 16px}}
[data-testid="stMetricLabel"] p {{color:{c["muted"]};font-weight:600;text-transform:uppercase;letter-spacing:.06em;font-size:.78rem}}
[data-testid="stMetricValue"] {{color:{c["text"]};font-weight:800;font-family:{f["mono"]}}}

/* tabs */
.stTabs [data-baseweb="tab-list"] {{gap:6px}}
.stTabs [data-baseweb="tab"] {{background:{c["panel"]};border-radius:10px 10px 0 0;padding:8px 16px}}
.stTabs [aria-selected="true"] {{border-bottom:2px solid {c["accent"]} !important}}

/* dataframes */
div[data-testid="stDataFrame"] {{border:1px solid {c["panel_border"]};border-radius:10px}}

/* page parts */
.page-title {{font-size:{f["size_heading"]};font-weight:800;color:{c["text"]};margin:0 0 2px}}
.page-sub {{color:{c["muted"]};font-size:{f["size_small"]};margin-bottom:12px}}
.section-title {{font-size:1rem;font-weight:800;letter-spacing:.03em;text-transform:uppercase;
  color:{c["text"]};margin:18px 0 8px;padding-left:10px;border-left:4px solid {c["accent"]}}}
.heat {{background:{c["panel"]};border:1px solid {c["panel_border"]};border-radius:10px;padding:14px;color:{c["text"]};
  font-family:{f["mono"]};font-size:.92rem;line-height:1.95;overflow-wrap:anywhere}}
.narrative {{background:{c["panel"]};border:1px solid {c["panel_border"]};border-left:5px solid {c["accent"]};
  border-radius:10px;padding:14px 16px;line-height:1.65;color:{c["text"]}}}
.tech {{background:{c["panel"]};border:1px solid {c["panel_border"]};border-radius:10px;padding:10px 12px;
  margin-bottom:8px;color:{c["text"]}}}
.tech .meta {{color:{c["muted"]};font-size:{f["size_small"]}}}
.legend span {{display:inline-block;padding:2px 10px;border-radius:6px;margin:0 8px 8px 0;
  font-size:{f["size_small"]};color:#fff;font-weight:600}}
.pill {{display:inline-block;padding:2px 10px;border-radius:6px;font-size:.78rem;font-weight:700;margin:1px 3px 1px 0}}
code {{color:{c["attack"]};background:{c["code_bg"]}}}
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
