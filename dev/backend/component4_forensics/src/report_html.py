"""
Self-contained HTML version of the forensic report.

Turns forensic_report.md into forensic_report.html: one file with every chart embedded as a base64
image. The page has a header with the incident facts, key figures, an attack-stage strip, a section
menu, stage / severity / source badges in the tables, a collapsible evidence list, light and dark
themes and a print layout (Ctrl+P -> Save as PDF).

Standard library only. It understands the markdown subset the report generator produces:
#/##/### headings, tables, "- " bullets, **bold**, *italic*, `code`, and ![alt](file) images.
"""

import base64
import html
import mimetypes
import os
import re

from theme import STAGE_COLOR, SEVERITY_COLOR, SOURCE_COLOR, stage_color, text_on

CSS = """
:root{--bg:#f3f5f8;--card:#ffffff;--ink:#1c2430;--muted:#5b6573;--line:#dde2e9;--head:#14213d;--head-ink:#ffffff;
--accent:#2a78d6;--zebra:#f7f9fb;--code:#eef1f5;--shadow:0 1px 2px rgba(20,33,61,.08),0 4px 14px rgba(20,33,61,.06)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f141b;--card:#18202a;--ink:#e8ecf1;--muted:#a3adba;
--line:#2a3441;--head:#0b1017;--zebra:#1c2530;--code:#222c38;--accent:#3987e5;--shadow:none}}
:root[data-theme="dark"]{--bg:#0f141b;--card:#18202a;--ink:#e8ecf1;--muted:#a3adba;--line:#2a3441;--head:#0b1017;
--zebra:#1c2530;--code:#222c38;--accent:#3987e5;--shadow:none}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.hero{background:var(--head);color:var(--head-ink);padding:28px 20px 22px}
.wrap{max-width:1080px;margin:0 auto;padding:0 18px}
.hero .wrap{padding:0}
.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.7}
.hero h1{margin:4px 0 10px;font-size:26px;line-height:1.25}
.badges{display:flex;gap:8px;flex-wrap:wrap}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid transparent}
.hero .badge{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.25);color:#fff}
nav{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line)}
nav .wrap{display:flex;gap:4px;overflow-x:auto;padding-top:6px;padding-bottom:6px}
nav a{white-space:nowrap;text-decoration:none;color:var(--muted);font-size:13px;padding:5px 10px;border-radius:6px}
nav a:hover{background:var(--zebra);color:var(--ink)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 6px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;box-shadow:var(--shadow)}
.kpi b{display:block;font-size:22px;line-height:1.2}
.kpi span{font-size:12px;color:var(--muted)}
.kpi.alert{border-left:4px solid #d03b3b}
.chain{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:12px 0;box-shadow:var(--shadow)}
.chain h3{margin:0 0 10px;font-size:13px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.steps{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.step{display:inline-flex;gap:6px;align-items:center;padding:4px 10px;border-radius:8px;font-size:13px;font-weight:600}
.arrow{color:var(--muted)}
section.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 20px 16px;margin:16px 0;box-shadow:var(--shadow)}
section.card h2{font-size:18px;margin:14px 0 8px;padding-bottom:8px;border-bottom:1px solid var(--line);scroll-margin-top:56px}
h3{font-size:15px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
th,td{padding:7px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{background:var(--zebra);font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);position:sticky;top:0}
tbody tr:nth-child(even) td{background:var(--zebra)}
code{background:var(--code);padding:1px 5px;border-radius:4px;font-family:Consolas,Menlo,monospace;font-size:12px;word-break:break-all}
figure{margin:14px 0;text-align:center}
figure img{max-width:100%;background:#fff;border:1px solid var(--line);border-radius:8px;padding:6px}
figcaption{font-size:12px;color:var(--muted);margin-top:4px}
ul{margin:6px 0 6px 20px;padding:0}li{margin:3px 0}
details{margin:8px 0}summary{cursor:pointer;font-weight:600;padding:6px 0;color:var(--accent)}
.chip{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;border:1px solid rgba(0,0,0,.25)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:700}
.hint{font-size:12px;color:var(--muted);margin:16px 0 24px}
footer{color:var(--muted);font-size:12px;padding:6px 0 30px}
.toggle{float:right;background:rgba(255,255,255,.12);color:#fff;border:1px solid rgba(255,255,255,.3);border-radius:6px;padding:3px 9px;cursor:pointer;font-size:12px}
@media print{nav,.toggle,.hint{display:none}body{background:#fff;color:#000}.hero{background:#14213d !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
section.card,.kpi,.chain{box-shadow:none;break-inside:avoid}tr,figure{break-inside:avoid}details>*{display:block}
.dot,.pill,.step{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""

SCRIPT = """
(function(){var b=document.getElementById('theme');if(!b)return;
b.addEventListener('click',function(){var r=document.documentElement,
d=(r.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'))==='dark';
r.setAttribute('data-theme',d?'light':'dark');});})();
"""


def _embed_image(alt, src, base_dir):
    path = os.path.join(base_dir, src)
    if not os.path.exists(path):
        return f"<em>[image not found: {html.escape(src)}]</em>"
    mime = mimetypes.guess_type(path)[0] or "image/png"
    with open(path, "rb") as f:
        data = base64.b64encode(f.read()).decode("ascii")
    return f'<img alt="{html.escape(alt)}" src="data:{mime};base64,{data}">'


def _inline(text, base_dir):
    text = html.escape(text, quote=False)
    text = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", lambda m: _embed_image(m.group(1), m.group(2), base_dir), text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*(?!\*|\s)(.+?)(?<!\*|\s)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    return text


def _pill(label, color):
    return f'<span class="pill" style="background:{color};color:{text_on(color)}">{html.escape(label)}</span>'


def _stage_chip(label):
    return (f'<span class="chip"><span class="dot" style="background:{stage_color(label)}"></span>'
            f'{html.escape(label)}</span>')


def _cell(value, header, base_dir):
    h = header.strip().lower()
    v = value.strip()
    if h == "severity" and v in SEVERITY_COLOR:
        return _pill(v, SEVERITY_COLOR[v])
    if h == "source" and v in SOURCE_COLOR:
        return _pill(v, SOURCE_COLOR[v])
    if h == "stage" and any(v.startswith(k) for k in STAGE_COLOR):
        return _stage_chip(v)
    return _inline(v, base_dir)


def _table(rows, base_dir):
    cells = lambda line: [c.strip() for c in line.strip().strip("|").split("|")]
    header = cells(rows[0])
    body = [cells(r) for r in rows[2:]]            # rows[1] is the |---|---| separator
    out = ["<table><thead><tr>" + "".join(f"<th>{_inline(c, base_dir)}</th>" for c in header) + "</tr></thead><tbody>"]
    for r in body:
        out.append("<tr>" + "".join(f"<td>{_cell(c, header[i] if i < len(header) else '', base_dir)}</td>"
                                    for i, c in enumerate(r)) + "</tr>")
    out.append("</tbody></table>")
    return "\n".join(out), len(body)


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _body_blocks(lines, base_dir):
    """Markdown lines of one section -> list of HTML blocks."""
    out, para, i = [], [], 0

    def flush():
        if para:
            out.append("<p>" + "<br>".join(_inline(p, base_dir) for p in para) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            flush()
        elif line.startswith("### "):
            flush(); out.append(f"<h3>{_inline(line[4:], base_dir)}</h3>")
        elif line.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i]); i += 1
            tbl, n = _table(rows, base_dir)
            out.append(f"<details><summary>Show {n} records</summary>{tbl}</details>" if n > 14 else tbl)
            continue
        elif line.startswith("- "):
            flush()
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(lines[i][2:]); i += 1
            out.append("<ul>" + "".join(f"<li>{_inline(x, base_dir)}</li>" for x in items) + "</ul>")
            continue
        elif re.fullmatch(r"!\[[^\]]*\]\([^)]+\)", stripped):
            flush()
            alt = re.match(r"!\[([^\]]*)\]", stripped).group(1)
            if out and out[-1] == f"<p><b>{html.escape(alt)}</b></p>":
                out.pop()                              # the figcaption already carries this label
            out.append(f"<figure>{_inline(stripped, base_dir)}<figcaption>{html.escape(alt)}</figcaption></figure>")
        else:
            para.append(stripped)
        i += 1
    flush()
    return out


def _hero(title, meta):
    badges = ""
    if meta.get("priority"):
        col = SEVERITY_COLOR.get(meta["priority"], "#7a8896")
        badges += f'<span class="badge" style="background:{col};border-color:{col};color:{text_on(col)}">{html.escape(str(meta["priority"]))} priority</span>'
    if meta.get("origin"):
        badges += f'<span class="badge">{html.escape(str(meta["origin"]))} origin</span>'
    if meta.get("window"):
        badges += f'<span class="badge">{html.escape(str(meta["window"]))}</span>'
    return (f'<header class="hero"><div class="wrap"><button class="toggle" id="theme" type="button">Light / dark</button>'
            f'<div class="eyebrow">Energy plant IIoT / SCADA &middot; Digital forensic report</div>'
            f'<h1>{html.escape(title)}</h1><div class="badges">{badges}</div></div></header>')


def _kpis(meta):
    items = [
        ("Records collected", meta.get("collected")),
        ("Attack evidence", meta.get("relevant")),
        ("Excluded as routine", meta.get("excluded")),
        ("Attack stages", meta.get("n_stages")),
        ("Duration", meta.get("duration")),
    ]
    tiles = "".join(f'<div class="kpi"><b>{html.escape(str(v))}</b><span>{html.escape(k)}</span></div>'
                    for k, v in items if v is not None)
    ext = []
    if meta.get("entry_ip"):
        ext.append(("Entry point", meta["entry_ip"]))
    if meta.get("vector"):
        ext.append(("Initial vector", meta["vector"]))
    if meta.get("compromised") is not None:
        ext.append(("Compromised assets", meta["compromised"]))
    tiles += "".join(f'<div class="kpi alert"><b style="font-size:15px">{html.escape(str(v))}</b><span>{html.escape(k)}</span></div>'
                     for k, v in ext)
    return f'<div class="kpis">{tiles}</div>'


def _chain(meta):
    stages = meta.get("stage_order") or []
    if not stages:
        return ""
    steps = '<span class="arrow">&rarr;</span>'.join(
        f'<span class="step" style="background:{stage_color(s)};color:{text_on(stage_color(s))}">{html.escape(s)}</span>'
        for s in stages)
    return f'<div class="chain"><h3>Attack progression</h3><div class="steps">{steps}</div></div>'


def markdown_to_html(md_text, base_dir, title="Forensic Report", meta=None):
    meta = meta or {}
    lines = md_text.splitlines()
    heading = title
    sections, current = [], None
    for line in lines:
        if line.startswith("# "):
            heading = line[2:].strip()
        elif line.startswith("## "):
            current = {"title": line[3:].strip(), "lines": []}
            sections.append(current)
        elif current is not None:
            current["lines"].append(line)
        # lines before the first "## " (generated time, trigger) are shown in the footer
    intro = [l.strip("* ").strip() for l in lines[1:] if l.strip() and not l.startswith("#")][:0]
    pre = []
    for line in lines[1:]:
        if line.startswith("## "):
            break
        if line.strip():
            pre.append(line.strip().rstrip(" ").strip("*").strip())

    nav = "".join(f'<a href="#{_slug(s["title"])}">{html.escape(re.sub(r"^[0-9]+[a-z]?[.] ", "", s["title"]))}</a>'
                  for s in sections)
    cards = []
    for s in sections:
        blocks = _body_blocks(s["lines"], base_dir)
        cards.append(f'<section class="card" id="{_slug(s["title"])}"><h2>{html.escape(s["title"])}</h2>'
                     + "\n".join(blocks) + "</section>")
    sub = "<br>".join(html.escape(p) for p in pre)
    page = (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(heading)}</title><style>{CSS}</style></head><body>'
            + _hero(heading, meta)
            + f'<nav><div class="wrap">{nav}</div></nav><main class="wrap">'
            + _kpis(meta) + _chain(meta)
            + "\n".join(cards)
            + f'<div class="hint">To save a PDF: press Ctrl + P and choose Save as PDF.</div>'
            + f'<footer>{sub}</footer></main><script>{SCRIPT}</script></body></html>')
    return page


def write_html_report(md_path, meta=None):
    """Create forensic_report.html next to the markdown file; returns its path."""
    with open(md_path, encoding="utf-8") as f:
        md = f.read()
    title = md.splitlines()[0].lstrip("# ").strip() if md else "Forensic Report"
    page = markdown_to_html(md, os.path.dirname(md_path), title, meta)
    out_path = os.path.splitext(md_path)[0] + ".html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    return out_path
