"""
Component 3 - SOC dashboard styles (colours, fonts, CSS and small HTML blocks).

Location : dev/frontend/pages/soc_ dash/soc_styles.py
Used by  : dev/frontend/pages/soc_ dash/app.py

Change colours or fonts here only - the page itself contains no styling.
Palette and fonts are the same as Component 2 (frontend/pages/com2_attack/sqli_xai_styles.py):
navy sidebar, light background, white cards, blue actions.
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

# priority level -> pill colour (Critical / High / Medium / Low)
LEVEL_KIND = {"critical": "red", "high": "amber", "medium": "blue", "low": "green"}

# chart colours (used with st.bar_chart(color=...))
CHART = {"primary": COLORS["blue"], "secondary": COLORS["navy"]}

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
[data-testid="stSidebar"] small, [data-testid="stSidebar"] li {{color:{c["sidebar_text"]} !important}}
[data-testid="stSidebar"] [data-baseweb="select"] *, [data-testid="stSidebar"] input {{color:{c["navy"]} !important}}
[data-testid="stSidebar"] [data-baseweb="tag"] span {{color:#fff !important}}
[data-testid="stSidebar"] code {{color:#ffd7dc;background:rgba(255,255,255,.08)}}

/* main-area widget labels */
[data-testid="stMain"] [data-testid="stWidgetLabel"] * {{color:{c["navy"]} !important;font-weight:600}}

/* tabs (Streamlit 1.66: react-aria tabs, not BaseWeb; the grey line under the row is Streamlit's own) */
[data-testid="stTab"], [data-testid="stTab"] p {{color:#111111 !important;font-weight:400 !important}}
[data-testid="stTab"]:hover, [data-testid="stTab"]:hover p {{color:#1a56db !important}}
[data-testid="stTab"][aria-selected="true"], [data-testid="stTab"][aria-selected="true"] p {{color:#1a56db !important;
  font-weight:700 !important}}
[data-testid="stTab"][aria-selected="true"] .react-aria-SelectionIndicator {{background-color:#1a56db !important}}

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
.narrative {{background:{c["card_bg"]};border:1px solid {c["card_border"]};border-left:5px solid {c["blue"]};
  border-radius:10px;padding:14px 16px;line-height:1.65;color:{c["text"]}}}
.card {{background:{c["card_bg"]};border:1px solid {c["card_border"]};border-radius:10px;padding:10px 12px;
  margin-bottom:8px;color:{c["text"]}}}
.card .meta {{color:{c["muted"]};font-size:{f["size_small"]}}}
.step {{background:{c["card_bg"]};border:1px solid {c["card_border"]};border-radius:8px;padding:8px 12px;
  margin-bottom:6px;color:{c["text"]}}}
.step b {{color:{c["blue"]};margin-right:6px}}
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
    return LEVEL_KIND.get(str(level).lower(), "grey")


def level_pill(level: str) -> str:
    return pill(level, level_kind(level))


def page_header(title: str, subtitle: str = "") -> str:
    return (f'<div class="page-title">🛡️ {html.escape(title)}</div>'
            f'<div class="page-sub">{html.escape(subtitle)}</div>')


def section_title(text: str) -> str:
    return f'<div class="section-title">{html.escape(text)}</div>'


def narrative_box(text: str, label: str = "Analyst note.") -> str:
    return f'<div class="narrative"><b>{html.escape(label)}</b> {html.escape(text)}</div>'


def alert_card(attack: str, asset: str, score, level: str, meta: str = "") -> str:
    """Summary card for one alert: attack type -> asset, score and level pill, border in the level colour."""
    border = PILLS[level_kind(level)][1]
    return (f'<div class="card" style="border-left:4px solid {border}">'
            f'<b>{html.escape(str(attack))}</b> against <b>{html.escape(str(asset))}</b> '
            f'{pill(f"score {score}", "blue")}{level_pill(level)}<br>'
            f'<span class="meta">{html.escape(meta)}</span></div>')


def steps_list(steps) -> str:
    """Numbered recommendation steps."""
    return "".join(f'<div class="step"><b>{i}.</b>{html.escape(str(s))}</div>' for i, s in enumerate(steps, 1))
