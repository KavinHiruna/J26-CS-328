"""
Colours for the charts and the HTML report.

Stage colours are slots 1-7 of a validated categorical palette (blue, orange, aqua, yellow,
magenta, green, violet), assigned in attack order; Impact uses the fixed 'critical' red.
Colour is never the only cue: every stage also has a text label and a marker shape.
"""

STAGE_COLOR = {
    "Reconnaissance": "#2a78d6",
    "Initial Access": "#eb6834",
    "Credential Access": "#1baf7a",
    "Malware Delivery": "#eda100",
    "Execution": "#e87ba4",
    "Command and Control": "#008300",
    "Lateral Movement": "#6250d6",
    "Discovery": "#7a8896",
    "Impact": "#d03b3b",
    "Network Connection": "#c9ccd1",
    "Uncategorized": "#c9ccd1",
}
INK = "#1c2430"
MUTED = "#5b6573"
GRID = "#d9dde3"
ATTACKER = "#d03b3b"        # attacker / origin
COMPROMISED = "#eb6834"     # compromised asset
TOUCHED = "#cde2fb"         # touched / scanned host
FLAGGED_EDGE = "#a8302f"
PLAIN_EDGE = "#8a94a3"
SEVERITY_COLOR = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#eda100", "Low": "#2a78d6", "Info": "#7a8896"}
SOURCE_COLOR = {"firewall": "#5b6573", "ids": "#6250d6", "device": "#0b7a5a"}


def stage_color(stage):
    for name, col in STAGE_COLOR.items():
        if stage.startswith(name):
            return col
    return STAGE_COLOR["Uncategorized"]


def text_on(hex_color):
    """Black or white text, whichever reads better on the colour."""
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    lum = 0.2126 * (r / 255) ** 2.2 + 0.7152 * (g / 255) ** 2.2 + 0.0722 * (b / 255) ** 2.2
    return "#111111" if lum > 0.28 else "#ffffff"
