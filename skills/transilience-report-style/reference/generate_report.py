#!/usr/bin/env python3
"""
Transilience-style report generator (data-driven, reusable).

Usage:
    python3 generate_report.py <report_data.json> [-o output.pdf] [--assets <dir>] [--theme light|dark]

Reads ONE JSON describing the engagement + findings (see report-data-schema.json)
and emits a Transilience-branded A4 PDF. All sections except `engagement` and
`findings` are optional — omit a key and the section is skipped.

Theme: LIGHT by default (modern, minimal, professional). `--theme dark` (or
engagement.theme:"dark") renders the legacy dark palette on the new layout.
Precedence: --theme > engagement.theme > light; an unknown value falls back to light.

Design system: formats/transilience-report-style/SKILL.md
Fonts + logo:  formats/transilience-report-style/{fonts,transilience-logo.png}
"""
import os, sys, json, html, argparse, re
from collections import Counter
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
                                Table, TableStyle, Image, PageBreak, NextPageTemplate, KeepTogether)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


def _load_shape():
    """Import the stdlib crash-invariant guard + KPI helper from repo tools/.
    Resolved from this file's canonical location (symlink-safe via realpath), with
    a cwd/tools fallback so the workflows' `python3 skills/.../generate_report.py`
    invocation always finds it."""
    here = os.path.dirname(os.path.realpath(__file__))
    for d in (os.path.abspath(os.path.join(here, "..", "..", "..", "tools")),
              os.path.abspath(os.path.join(os.getcwd(), "tools"))):
        if os.path.isfile(os.path.join(d, "report_data_shape.py")) and d not in sys.path:
            sys.path.insert(0, d)
            break
    from report_data_shape import require_report_data_shape, default_metrics
    return require_report_data_shape, default_metrics


require_report_data_shape, default_metrics = _load_shape()
from reportlab.graphics.shapes import Drawing, Rect, String


def find_assets(override=None):
    """Locate formats/transilience-report-style (fonts + logo)."""
    if override and os.path.isdir(os.path.join(override, "fonts")):
        return override
    here = os.path.abspath(__file__)
    d = here
    for _ in range(8):                       # walk up to repo root
        d = os.path.dirname(d)
        cand = os.path.join(d, "formats", "transilience-report-style")
        if os.path.isdir(os.path.join(cand, "fonts")):
            return cand
    return os.path.dirname(os.path.dirname(here))  # fallback: skill dir


# ---------- fonts ----------
def register_fonts(fonts_dir):
    def reg(alias, fn):
        try: pdfmetrics.registerFont(TTFont(alias, os.path.join(fonts_dir, fn)))
        except Exception: pass
    reg("Poppins", "Poppins-Regular.ttf"); reg("Poppins-Bold", "Poppins-Bold.ttf")
    reg("Poppins-Med", "Poppins-Medium.ttf"); reg("Poppins-Light", "Poppins-Light.ttf")
    reg("Carlito", "Carlito-Regular.ttf"); reg("Carlito-Bold", "Carlito-Bold.ttf")

FB, FM, FP, FC, FCB = "Poppins-Bold", "Poppins-Med", "Poppins", "Carlito", "Carlito-Bold"

# ---------- theme palettes (Transilience brand: purple #6941C6 -> magenta #C9317C) ----------
# One dict per theme; every colour the layer uses lives here so the whole look is
# a single swap. LIGHT is the default; DARK reproduces the legacy look on the new layout.
THEME = {
    "light": dict(
        PAGE="#FFFFFF", SURFACE="#FFFFFF", TINT="#F6F4FB", ALT="#FBFAFE",
        INK="#1B1725", INK_SOFT="#5A5568", LBL="#6B7280", BORDER="#E7E3F0",
        BRAND="#6941C6", BRAND2="#C9317C", BRANDL="#8B5CF6",
        CODE_BG="#F5F4F8", CODE_INK="#2A2536", CODE_BORDER="#E4E0EE",
        GREEN="#15803D", BLUE="#2563EB", AMBER="#B45309",
        FOOT="#8A8594", PAGENUM="#6941C6",
        SEV=dict(Critical="#DC2626", High="#EA580C", Medium="#CA8A04", Low="#16A34A", Info="#64748B"),
    ),
    "dark": dict(
        PAGE="#07040B", SURFACE="#13101C", TINT="#1A1625", ALT="#13101C",
        INK="#F0F2F5", INK_SOFT="#C7C3D2", LBL="#E0E3E8", BORDER="#2A2535",
        BRAND="#6941C6", BRAND2="#C9317C", BRANDL="#8B5CF6",
        CODE_BG="#1A1625", CODE_INK="#E6E3F0", CODE_BORDER="#2A2535",
        GREEN="#10B981", BLUE="#3B82F6", AMBER="#F59E0B",
        FOOT="#9CA3AF", PAGENUM="#8B5CF6",
        SEV=dict(Critical="#EF4444", High="#FB923C", Medium="#EAB308", Low="#22C55E", Info="#9CA3AF"),
    ),
}

def _theme(name):
    raw = THEME.get(name, THEME["light"])
    T = {}
    for k, v in raw.items():
        if k == "SEV":
            T["SEV"] = {sk: colors.HexColor(sv) for sk, sv in v.items()}
        elif isinstance(v, str) and v.startswith("#"):
            T[k] = colors.HexColor(v)
        else:
            T[k] = v
    return T

PAGE = A4; MX = 16 * mm; CW = PAGE[0] - 2 * MX

def score_band(score):
    """CVSS score -> severity band key (pure; used for colour-coding scores)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Info"
    if s <= 0: return "Info"       # schema has no "None"; 0/None -> Info
    if s < 4.0: return "Low"
    if s < 7.0: return "Medium"
    if s < 9.0: return "High"
    return "Critical"

def cvss_display(score):
    """CVSS score for display: the numeric value, or 'n/a' when absent.
    Every finding/CVE always shows this score cell paired with its severity label."""
    return str(score) if score not in (None, "") else "n/a"

def cvss_version_label(vector):
    """CVSS version tag ('v4.0'/'v3.1'/'v3.0'/'v2.0') derived from a vector's
    prefix, or '' when unknown. v4.0 is the primary version repo-wide; a
    prefix-less vector is CVSS v2.0."""
    m = re.match(r'(?i)^CVSS:(\d\.\d)/', str(vector or ""))
    if m:
        return "v" + m.group(1)
    return "v2.0" if vector else ""

def hx(c): return "#" + c.hexval()[2:]
def esc(s): return html.escape(str(s if s is not None else ""), quote=False)
def mask(s):  # defensive PII/secret masking
    s = str(s or "")
    s = re.sub(r'\b(\d{6})\d{4,9}(\d{2,4})\b', lambda m: m.group(1) + "****" + m.group(2), s)
    s = re.sub(r'\b([A-Z]{5})\d{4}([A-Z])\b', r'\1####\2', s)
    return s

def styles(T):
    ps = lambda n, **k: ParagraphStyle(n, **k)
    return {
      "ct": ps("ct", fontName=FB, fontSize=29, leading=35, textColor=T["INK"]),
      "cc": ps("cc", fontName=FM, fontSize=14.5, leading=20, textColor=T["BRAND"]),
      "h1": ps("h1", fontName=FB, fontSize=17, leading=22, textColor=T["INK"], spaceAfter=6),
      "h3": ps("h3", fontName=FM, fontSize=11, leading=15, textColor=T["BRAND"], spaceBefore=7, spaceAfter=3),
      "body": ps("body", fontName=FC, fontSize=10, leading=15, textColor=T["INK"], alignment=TA_JUSTIFY, spaceAfter=6),
      "bs": ps("bs", fontName=FC, fontSize=9, leading=12.5, textColor=T["INK_SOFT"]),
      "bsw": ps("bsw", fontName=FC, fontSize=8.4, leading=11.5, textColor=T["INK"], wordWrap='CJK'),
      "mono": ps("mono", fontName="Courier", fontSize=7.8, leading=10.5, textColor=T["CODE_INK"], wordWrap='CJK'),
      "code": ps("code", fontName="Courier", fontSize=7.8, leading=10.6, textColor=T["CODE_INK"], wordWrap='CJK'),
      "sl": ps("sl", fontName=FM, fontSize=8.4, leading=11, textColor=T["INK"]),
      "label": ps("label", fontName=FP, fontSize=9.5, leading=13, textColor=T["LBL"]),
      "bullet": ps("bullet", fontName=FC, fontSize=10, leading=15, textColor=T["INK"], leftIndent=12, spaceAfter=4),
      "notice": ps("notice", fontName=FC, fontSize=8.3, leading=12, textColor=T["LBL"]),
      "metric": ps("metric", fontName=FB, fontSize=20, leading=22, textColor=T["INK"], alignment=TA_CENTER),
      "metricl": ps("metricl", fontName=FM, fontSize=7.5, leading=9.5, textColor=T["LBL"], alignment=TA_CENTER),
      "cardt": ps("cardt", fontName=FB, fontSize=11.5, leading=15, textColor=T["INK"]),
      "cardlbl": ps("cardlbl", fontName=FM, fontSize=8, leading=11, textColor=T["BRAND"]),
      "cardbody": ps("cardbody", fontName=FC, fontSize=9, leading=12.6, textColor=T["INK"]),
      "v": ps("v", fontName=FM, fontSize=10.5, textColor=T["INK"], leading=15),
    }


# The executive summary is a deliverable in its own right, not a section of the
# technical report — it goes to a different audience. build() is already fully
# data-driven (every technical block is `if data.get(...)`, and the findings
# groups are `if not fl: continue`), so the exec edition is a filtered VIEW of
# report_data rather than a second code path through a 400-line function.
#
# ALLOWLIST, deliberately: a denylist would silently leak any technical key added
# later into a document meant for circulation outside the security team.
EXEC_ONLY_KEYS = ("engagement", "executive_summary", "metrics", "roadmap",
                  "conclusion", "disclaimer")


def exec_only_view(data):
    """report_data -> the executive edition: cover, KPI boxes, narrative, roadmap."""
    view = {k: data[k] for k in EXEC_ONLY_KEYS if k in data}
    # KPI boxes normally derive from findings[]. Precompute them from the FULL
    # finding set before dropping it, so the counts still describe the whole
    # engagement rather than the empty list left behind.
    if view.get("metrics") is None:
        view["metrics"] = default_metrics(data.get("findings") or [])
    view["findings"] = []          # keeps the shape valid; renders no cards
    return view


def build(data, dest, assets, theme=None):
    register_fonts(os.path.join(assets, "fonts"))
    LOGO = os.path.join(assets, "transilience-logo.png")
    eng = data.get("engagement", {})
    name = theme or eng.get("theme") or "light"        # precedence: CLI > data > light
    if name not in THEME:
        name = "light"                                  # unknown -> light (never error)
    T = _theme(name)
    S = styles(T)
    findings = data.get("findings", [])
    sm = Counter(f.get("severity", "Info") for f in findings)

    def grad(c, x, y, w, h, steps=80):
        # Brand hairline: purple (#6941C6) -> magenta (#C9317C).
        sw = w / steps
        for i in range(steps):
            t = i / (steps - 1)
            r = 0.412 + (0.788 - 0.412) * t; g = 0.255 + (0.192 - 0.255) * t; b = 0.776 + (0.486 - 0.776) * t
            c.setFillColorRGB(r, g, b); c.rect(x + i * sw, y, sw + 1, h, fill=1, stroke=0)

    foot = f"TRANSILIENCE AI   ·   {esc(eng.get('footer','Security Assessment'))}   ·   CONFIDENTIAL   ·   {esc(eng.get('date',''))}"
    def page_bg(c, d):
        c.saveState(); c.setFillColor(T["PAGE"]); c.rect(0, 0, *PAGE, fill=1, stroke=0)
        grad(c, 0, PAGE[1] - 2.5, PAGE[0], 2.5)
        c.setStrokeColor(T["BORDER"]); c.setLineWidth(0.6); c.line(MX, 23, PAGE[0] - MX, 23)
        c.setFillColor(T["FOOT"]); c.setFont(FP, 7); c.drawString(MX, 13, foot)
        c.setFillColor(T["PAGENUM"]); c.setFont(FB, 9); c.drawRightString(PAGE[0] - MX, 12.5, f"{d.page}")
        c.restoreState()
    def page_cover(c, d):
        c.saveState(); c.setFillColor(T["PAGE"]); c.rect(0, 0, *PAGE, fill=1, stroke=0)
        grad(c, 0, PAGE[1] - 3, PAGE[0], 3)
        c.restoreState()

    doc = BaseDocTemplate(dest, pagesize=PAGE, leftMargin=MX, rightMargin=MX, topMargin=20 * mm,
                          bottomMargin=16 * mm, title=eng.get("title", "Security Report"), author="Transilience AI")
    fr = Frame(MX, 16 * mm, CW, PAGE[1] - 34 * mm, id="m")
    doc.addPageTemplates([PageTemplate(id="cover", frames=[fr], onPage=page_cover),
                          PageTemplate(id="main", frames=[fr], onPage=page_bg)])

    # ---- reusable builders (all read T) ----
    def gline(col=None, h=1.4, frac=1.0):
        t = Table([[""]], colWidths=[CW * frac], rowHeights=[h])
        t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), h, col or T["BRAND"])])); return t
    def labelp(text, col):
        return Paragraph(f'<font name="{FM}" color="{hx(col)}">{esc(text)}</font>', S["cardlbl"])
    def codebox(html_text, width=None):
        # Boxed monospace block for code / samples (input already escaped HTML).
        p = Paragraph(html_text, S["code"])
        w = width if width is not None else CW - 30
        t = Table([[p]], colWidths=[w])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), T["CODE_BG"]), ("BOX", (0, 0), (-1, -1), 0.5, T["CODE_BORDER"]),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)])); return t
    def mbox(label, val, col):
        t = Table([[Paragraph(f'<font color="{hx(col)}">{esc(val)}</font>', S["metric"])], [Paragraph(esc(label), S["metricl"])]], colWidths=[CW / 6.2])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), T["TINT"]), ("BOX", (0, 0), (-1, -1), 0.6, T["BORDER"]),
            ("LINEABOVE", (0, 0), (-1, 0), 3, col), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)])); return t
    def _cols(x):
        return [] if x is None else list(x) if isinstance(x, (list, tuple)) else [x]
    def _score_band(v):
        v = str(v).strip()
        if not v:
            return None
        try:
            float(v)
        except ValueError:
            return None
        return score_band(v)
    def tbl(header, rows, widths, sevcol=None, scorecol=None, statuscol=None, cell="bsw"):
        # Colour-code severity-label cells (sevcol), CVSS-score cells (scorecol), and
        # coverage-status cells (statuscol) by band. The colour is emitted as an inline
        # <font> tag inside the cell: TableStyle TEXTCOLOR/FONTNAME are IGNORED on
        # Paragraph cells, so the colour must live in the cell markup itself.
        # sevcol/scorecol/statuscol accept an int or a list.
        sevc, scoc, statc = _cols(sevcol), _cols(scorecol), _cols(statuscol)
        # "deferred" needs its own colour: it is neither covered nor open work, and
        # rendering it uncoloured beside a red "pending" reads as "fine" when it means
        # "blocked on the client". Mobile DAST deferrals make this routine.
        STATUS_COL = {"covered": T["GREEN"], "covered_negative": T["BLUE"],
                      "deferred": T["AMBER"],
                      "pending": T["SEV"]["Critical"], "untested": T["SEV"]["Critical"]}
        def cellp(val, ci):
            col = None
            if ci in sevc and val in T["SEV"]:
                col = T["SEV"][val]
            elif ci in statc and val in STATUS_COL:
                col = STATUS_COL[val]
            elif ci in scoc:
                band = _score_band(val)
                if band:
                    col = T["SEV"][band]
            txt = esc(val)
            if col is not None:
                txt = f'<font name="{FCB}" color="{hx(col)}">{txt}</font>'
            return Paragraph(txt, S[cell])
        cells = [[Paragraph(esc(h), S["sl"]) for h in header]] + \
                [[cellp(c, ci) for ci, c in enumerate(r)] for r in rows]
        t = Table(cells, colWidths=widths, repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), T["TINT"]), ("GRID", (0, 0), (-1, -1), 0.4, T["BORDER"]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
              ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 6),
              ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [T["SURFACE"], T["ALT"]])]
        t.setStyle(TableStyle(st)); return t
    def sev_chart(counts):
        # Graphical Summary — horizontal severity bars on a light track.
        order = ["Critical", "High", "Medium", "Low", "Info"]
        data2 = [(k, counts.get(k, 0)) for k in order]
        mx = max([v for _, v in data2] + [1])
        rowh, labelw = 20, 66
        barmax = CW - labelw - 46
        h = 10 + rowh * len(data2)
        d = Drawing(CW, h)
        for i, (k, v) in enumerate(data2):
            cy = h - 6 - rowh * i - rowh / 2
            d.add(String(labelw - 8, cy - 3, k, fontName=FM, fontSize=8.3, fillColor=T["INK_SOFT"], textAnchor="end"))
            d.add(Rect(labelw, cy - 5.5, barmax, 11, fillColor=T["TINT"], strokeColor=None))
            bw = (barmax * v / mx) if v > 0 else 1.5
            d.add(Rect(labelw, cy - 5.5, bw, 11, fillColor=T["SEV"][k], strokeColor=None))
            d.add(String(labelw + bw + 7, cy - 3, str(v), fontName=FB, fontSize=8.5, fillColor=T["INK"]))
        return d
    def findings_summary_rows(fs):
        rows = []
        for lvl in ["Critical", "High", "Medium", "Low", "Info"]:
            for f in sorted([x for x in fs if x.get("severity", "Info") == lvl], key=lambda x: -(x.get("cvss_score") or 0)):
                rows.append([esc(f.get("id", "")), esc(f.get("title", ""))[:66], lvl,
                             esc(cvss_display(f.get("cvss_score")))])
        return rows

    E = []
    sec = [0]
    def section(title):
        sec[0] += 1
        E.append(Paragraph(f"{sec[0]:02d} · {esc(title)}", S["h1"])); E.append(gline(T["BRAND"], 1.6)); E.append(Spacer(1, 7))

    # ---- cover ----
    E.append(Spacer(1, 30 * mm))
    if os.path.exists(LOGO):
        try:
            iw, ih = ImageReader(LOGO).getSize()
            lw = 48 * mm; lh = lw * ih / iw            # real aspect ratio (never squished)
            E.append(Image(LOGO, width=lw, height=lh)); E.append(Spacer(1, 15 * mm))
        except Exception: pass
    for line in eng.get("title_lines", [eng.get("title", "Security Assessment Report")]):
        E.append(Paragraph(esc(line), S["ct"]))
    E.append(Spacer(1, 5 * mm))
    if eng.get("subtitle"): E.append(Paragraph(esc(eng["subtitle"]), S["cc"]))
    E.append(Spacer(1, 5 * mm)); E.append(gline(T["BRAND"], 2, 0.32)); E.append(Spacer(1, 9 * mm))
    _alias = {"REPORT DATE": "date", "PREPARED BY": "prepared_by", "REPORT ID": "report_id"}
    meta = eng.get("cover_meta") or [[k, eng.get(_alias.get(k, k.lower().replace(" ", "_")), "")] for k in
        ["REPORT DATE", "DURATION", "CLASSIFICATION", "SECTOR", "TARGET", "METHOD", "PREPARED BY", "REPORT ID"]]
    meta = [[k, v] for k, v in meta if v]
    if meta:
        mt = Table([[Paragraph(esc(k), S["label"]), Paragraph(esc(v), S["v"])] for k, v in meta],
                   colWidths=[CW * 0.30, CW * 0.70])
        mt.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 5.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -2), 0.4, T["BORDER"])]))
        E.append(mt)
    E.append(Spacer(1, 14 * mm))
    if eng.get("confidentiality"): E.append(Paragraph(esc(eng["confidentiality"]), S["notice"]))
    E.append(NextPageTemplate("main")); E.append(PageBreak())

    # ---- executive summary ----
    exsum = data.get("executive_summary", {})
    if exsum or findings:
        section("Executive Summary")
        for p in exsum.get("narrative", []):
            E.append(Paragraph(p, S["body"]))
        metrics = data.get("metrics")
        if metrics is None:
            metrics = default_metrics(data.get("findings") or [])  # includes Critical when present
        strip = [mbox(m["label"], m["value"], T["SEV"].get(m.get("sev"), T["BRAND"]) if not m.get("color") else colors.HexColor(m["color"])) for m in metrics[:6]]
        if strip:
            ms = Table([strip], colWidths=[CW / max(6.05, len(strip) + 0.05)] * len(strip))
            ms.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1)]))
            E.append(Spacer(1, 4)); E.append(ms); E.append(Spacer(1, 10))
        # Graphical Summary (severity chart) + Tabular Summary (findings index)
        if findings:
            E.append(Paragraph("Severity Distribution", S["h3"]))
            E.append(sev_chart(sm)); E.append(Spacer(1, 8))
            E.append(Paragraph("Findings Summary", S["h3"]))
            E.append(tbl(["ID", "Finding", "Severity", "CVSS"], findings_summary_rows(findings),
                        [CW * 0.12, CW * 0.60, CW * 0.16, CW * 0.12], sevcol=2, scorecol=3, cell="bs"))
            E.append(Spacer(1, 9))
        if exsum.get("key_risks"):
            E.append(Paragraph("Key Risks", S["h3"]))
            for t in exsum["key_risks"]: E.append(Paragraph("&bull; " + t, S["bullet"]))
        if exsum.get("positives"):
            E.append(Paragraph("Positive Observations", S["h3"]))
            for t in exsum["positives"]: E.append(Paragraph("&bull; " + t, S["bullet"]))
        E.append(PageBreak())

    # ---- free-form sections (scope / methodology / …) ----
    # A section flagged "internal": true is kept in report_data.json (internal record /
    # QA log, e.g. blind-validation reproduction) but is NEVER rendered into the client PDF.
    for blk in data.get("sections", []):
        if blk.get("internal"):
            continue
        section(blk["title"])
        for p in blk.get("paragraphs", []): E.append(Paragraph(p, S["body"]))
        if blk.get("table"):
            E.append(tbl(blk["table"]["header"], blk["table"]["rows"], [CW * w for w in blk["table"]["widths"]]))
        E.append(PageBreak())

    # ---- findings (grouped by severity) ----
    def image_flowable(src):
        """A framed Image flowable for a PoC step's image_url, or None when the
        image is not available. Accepts a local path or an http(s) URL (best-effort
        download; silently skipped on any failure so 'show the image if available')."""
        if not src or not isinstance(src, str):
            return None
        path = src
        if src.startswith(("http://", "https://")):
            try:
                import urllib.request, tempfile
                with urllib.request.urlopen(src, timeout=8) as resp:
                    data = resp.read()
                fd, path = tempfile.mkstemp(suffix=".img")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)                       # reportlab reads it at build() time; keep the temp file
            except Exception:
                return None
        if not os.path.exists(path):
            return None
        try:
            iw, ih = ImageReader(path).getSize()
            w = CW - 34; h = w * ih / iw
            frame = Table([[Image(path, width=w, height=h)]], colWidths=[w + 2])
            frame.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, T["BORDER"]), ("LEFTPADDING", (0, 0), (-1, -1), 1),
                ("RIGHTPADDING", (0, 0), (-1, -1), 1), ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
            return frame
        except Exception:
            return None

    def cve_block(f):
        rows = [[esc(c.get("id", "")),
                 esc(cvss_display(c.get("score"))),
                 esc(c.get("severity") or score_band(c.get("score")))] for c in f.get("cves", [])]
        out = [labelp("CVE RISK (authoritative NVD)", T["BLUE"]),
               tbl(["CVE", "CVSS", "Severity"], rows, [CW * 0.28, CW * 0.14, CW * 0.20], sevcol=2, scorecol=1, cell="bs")]
        if f.get("cve_caveat"):
            out.append(Paragraph(f'<font color="{hx(T["AMBER"])}">{esc(mask(f["cve_caveat"]))}</font>', S["cardbody"]))
        return out

    def card(f):
        skey = f.get("severity") or "Info"; sc = T["SEV"].get(skey, T["SEV"]["Info"])
        rows = []
        def row(*flows): rows.append([list(flows)])
        # header: id + [SEV label] (colour-coded, always present) + title
        row(Paragraph(f'<font name="{FB}" color="{hx(sc)}">{esc(f.get("id",""))}</font> '
                      f'<font name="{FB}" color="{hx(sc)}">[{esc(skey.upper())}]</font>  '
                      f'<font name="{FB}" color="{hx(T["INK"])}">{esc(f.get("title",""))}</font>', S["cardt"]))
        # meta: Severity label + CVSS score (always shown; n/a when no CVSS) · CWE · OWASP · Status
        cvss_val = f.get("cvss_score")
        has_cvss = cvss_val not in (None, "")
        scc = T["SEV"].get(score_band(cvss_val), T["INK_SOFT"]) if has_cvss else T["INK_SOFT"]
        confirmed = not f.get("needs_live_confirmation")
        status = f.get("status_label") or ("CONFIRMED (offline)" if confirmed else "EVIDENCED — needs live confirmation")
        stc = T["GREEN"] if confirmed else T["AMBER"]
        cvss_ver = cvss_version_label(f.get("cvss_vector"))
        cvss_lbl = ("CVSS " + cvss_ver) if (has_cvss and cvss_ver) else "CVSS"
        parts = [f'<font color="{hx(T["LBL"])}">Severity</font> <font name="{FB}" color="{hx(sc)}">{esc(skey)}</font>',
                 f'<font color="{hx(T["LBL"])}">{cvss_lbl}</font> <font name="{FB}" color="{hx(scc)}">{esc(cvss_display(cvss_val))}</font>']
        if f.get("cwe"): parts.append(f'<font color="{hx(T["LBL"])}">CWE</font> {esc(f["cwe"])}')
        if f.get("owasp"): parts.append(f'<font color="{hx(T["LBL"])}">OWASP</font> {esc(f["owasp"])}')
        # MITRE technique ids sit beside CWE/OWASP. A string is accepted as well
        # as a list so a hand-written report_data.json is not a silent blank.
        _atk = f.get("attack")
        if _atk:
            _atk = [_atk] if isinstance(_atk, str) else _atk
            _ids = ", ".join(esc(str(t)) for t in _atk if str(t).strip())
            if _ids: parts.append(f'<font color="{hx(T["LBL"])}">MITRE</font> {_ids}')
        parts.append(f'<font color="{hx(T["LBL"])}">Status</font> <font color="{hx(stc)}">{status}</font>')
        row(Paragraph("&nbsp;&nbsp;&nbsp;".join(parts), S["cardbody"]))
        if f.get("cvss_vector"):
            row(codebox("Vector: " + esc(mask(f["cvss_vector"]))))
        if f.get("ease_of_exploitation"):
            row(Paragraph(f'<font color="{hx(T["LBL"])}">Ease of Exploitation</font>&nbsp;&nbsp;{esc(mask(f["ease_of_exploitation"]))}', S["cardbody"]))
        aff = "; ".join(f.get("affected", [])[:6]) + (" …" if len(f.get("affected", [])) > 6 else "")
        if aff:
            row(labelp("AFFECTED", T["BRAND"]), codebox(esc(mask(aff))))
        for lbl, key, lim in [("DESCRIPTION", "description", 1500), ("IMPACT", "impact", 1000)]:
            if f.get(key):
                row(labelp(lbl, T["BRAND"]), Paragraph(esc(mask(f[key]))[:lim], S["cardbody"]))
        # PROOF OF CONCEPT — ordered list of steps; per step: prose description,
        # code-styled command (exact command to run), and an embedded image if available.
        poc = f.get("poc")
        if isinstance(poc, list) and poc:
            # One card row per PoC step so an image-heavy PoC splits across pages at
            # step boundaries (a single row cannot split, and stacked screenshots can
            # exceed one page). The card's box/stripe is redrawn per page fragment.
            row(labelp("PROOF OF CONCEPT", T["BLUE"]))
            for i, step in enumerate([s for s in poc if isinstance(s, dict)], start=1):
                stepflows = [Paragraph(f'<font name="{FB}" color="{hx(T["INK"])}">{i}.</font>&nbsp;&nbsp;'
                                       f'{esc(mask(str(step.get("description") or "")))}', S["cardbody"])]
                cmd = step.get("command")
                if cmd not in (None, ""):
                    stepflows.append(codebox(esc(mask(str(cmd)))))
                img = image_flowable(step.get("image_url"))
                if img is not None:
                    stepflows.append(Spacer(1, 3)); stepflows.append(img)
                rows.append([stepflows])
        if f.get("calibration"):
            row(labelp("SEVERITY CALIBRATION", T["AMBER"]), Paragraph(esc(mask(f["calibration"])), S["cardbody"]))
        if f.get("cves"):
            rows.append([cve_block(f)])
        if f.get("recommendation"):
            row(labelp("REMEDIATION", T["GREEN"]), Paragraph(esc(mask(f["recommendation"])), S["cardbody"]))
        refs = f.get("references")
        if refs:
            if isinstance(refs, str): refs = [refs]
            blk = [labelp("REFERENCES", T["BLUE"])]
            for r in refs[:12]:
                blk.append(Paragraph("&bull; " + esc(mask(str(r))), S["cardbody"]))
            rows.append([blk])
        # Multi-ROW table -> splits across pages at row boundaries; box/stripe redrawn per fragment.
        t = Table(rows, colWidths=[CW])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), T["SURFACE"]),
            ("BOX", (0, 0), (-1, -1), 0.75, T["BORDER"]),
            ("LINEBEFORE", (0, 0), (0, -1), 3, sc),
            ("LEFTPADDING", (0, 0), (-1, -1), 13), ("RIGHTPADDING", (0, 0), (-1, -1), 13),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (0, 0), 11), ("BOTTOMPADDING", (0, len(rows) - 1), (-1, len(rows) - 1), 11),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    by_sev = {}
    for f in findings: by_sev.setdefault(f.get("severity", "Info"), []).append(f)
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        fl = by_sev.get(level)
        if not fl: continue
        fl.sort(key=lambda x: -(x.get("cvss_score") or 0))
        section(f"{level}-Severity Findings" if level != "Info" else "Informational")
        for f in fl:
            E.append(KeepTogether(card(f)) if level in ("Low", "Info") else card(f))
            E.append(Spacer(1, 9))
        E.append(PageBreak())

    # ---- optional registers ----
    if data.get("cve_register"):
        section("CVE Risk Register (authoritative NVD)")
        rows = [[c.get("cve"), c.get("component", ""), str(c.get("score")), c.get("severity", ""), (c.get("summary") or "")[:90]] for c in data["cve_register"]]
        E.append(tbl(["CVE", "Component", "CVSS", "Severity", "Summary"], rows, [CW * 0.16, CW * 0.18, CW * 0.08, CW * 0.12, CW * 0.46], sevcol=3, scorecol=2)); E.append(PageBreak())
    if data.get("coverage_table"):
        section("Coverage")
        ct = data["coverage_table"]
        E.append(tbl(ct["header"], ct["rows"], [CW * w for w in ct["widths"]]))
        if ct.get("note"): E.append(Spacer(1, 4)); E.append(Paragraph(esc(ct["note"]), S["bs"]))
        E.append(PageBreak())
    if data.get("attack_pattern_coverage"):
        section("Attack Pattern Coverage")
        apc = data["attack_pattern_coverage"]
        E.append(Paragraph("Every applicable (surface-unit × attack-class) cell is enumerated by code from the discovered surface; the status column is machine-computed by the deterministic coverage gate (covered = validated finding; covered_negative = tested clean with corroborated evidence; pending = untested).", S["body"]))
        E.append(tbl(apc["header"], apc["rows"], [CW * w for w in apc["widths"]], statuscol=len(apc["header"]) - 1))
        if apc.get("note"): E.append(Spacer(1, 4)); E.append(Paragraph(esc(apc["note"]), S["bs"]))
        E.append(PageBreak())
    if data.get("ruled_out"):
        section("Investigated and Ruled Out")
        E.append(Paragraph("The following candidate issues were investigated during the engagement and dismissed with "
                            "corroborating evidence. They are recorded to document assessment coverage and to distinguish "
                            "tested-clean classes from untested ones.", S["body"]))
        rows = [[r.get("title", ""), r.get("why", "")] for r in data["ruled_out"]]
        E.append(tbl(["Candidate issue", "Why it was ruled out"], rows, [CW * 0.34, CW * 0.66]))
        E.append(PageBreak())
    if data.get("tools_used"):
        section("Tools & Techniques Used")
        if data.get("tools_intro"): E.append(Paragraph(esc(data["tools_intro"]), S["body"]))
        trows = [[mask(str(c)) for c in r] for r in data["tools_used"]]
        E.append(tbl(["Tool / Technique", "Purpose", "Invocations"], trows, [CW * 0.26, CW * 0.50, CW * 0.24])); E.append(PageBreak())
    if data.get("source_ips"):
        section("Source IPs / Egress Vantage")
        if data.get("source_ips_intro"): E.append(Paragraph(esc(data["source_ips_intro"]), S["body"]))
        E.append(tbl(["Source IP", "Role", "Provider / Region"], data["source_ips"], [CW * 0.28, CW * 0.28, CW * 0.44])); E.append(PageBreak())
    if data.get("roadmap"):
        section("Remediation Roadmap")
        cmap = {"immediate": T["SEV"]["High"], "short": T["SEV"]["Medium"], "medium": T["SEV"]["Low"], "long": T["BRAND"]}
        for r in data["roadmap"]:
            col = next((v for k, v in cmap.items() if k in r["title"].lower()), T["BRAND"])
            E.append(Paragraph(f'<font color="{hx(col)}">{esc(r["title"])}</font>', S["h3"]))
            for it in r.get("items", []): E.append(Paragraph("&bull; " + esc(it), S["bullet"]))
            E.append(Spacer(1, 4))
        E.append(PageBreak())
    concl = data.get("conclusion")
    if concl:
        section("Conclusion")
        for p in concl.get("narrative", []):
            E.append(Paragraph(p, S["body"]))
        if concl.get("assessment"):
            E.append(Paragraph("Overall Assessment", S["h3"]))
            av = concl["assessment"]
            for p in (av if isinstance(av, list) else [av]):
                E.append(Paragraph(esc(p), S["body"]))
        if concl.get("limitations"):
            E.append(Paragraph("Limitations", S["h3"]))
            lv = concl["limitations"]
            for p in (lv if isinstance(lv, list) else [lv]):
                E.append(Paragraph("&bull; " + esc(p), S["bullet"]))
        E.append(PageBreak())
    if data.get("disclaimer"):
        E.append(Spacer(1, 8)); E.append(gline(T["BORDER"], 0.6)); E.append(Spacer(1, 4))
        E.append(Paragraph(esc(data["disclaimer"]), S["notice"]))

    doc.build(E)
    return dest


def main():
    ap = argparse.ArgumentParser(description="Generate a Transilience-style PDF report from a JSON data file.")
    ap.add_argument("data", help="report_data.json")
    ap.add_argument("-o", "--output", default=None, help="output PDF path")
    ap.add_argument("--assets", default=None, help="path to formats/transilience-report-style (fonts + logo)")
    ap.add_argument("--theme", default=None, help="light (default) | dark; unknown falls back to light")
    ap.add_argument("--exec-only", action="store_true",
                    help="render the executive edition only (cover, KPI boxes, narrative, roadmap) "
                         "— no findings detail, no technical registers")
    a = ap.parse_args()
    data = json.load(open(a.data))
    try:  # fail-closed: block the crash-invariants (string narrative, bad severity, ...) before rendering
        require_report_data_shape(data)
    except ValueError as e:
        print(f"generate_report: invalid report_data — {e}", file=sys.stderr)
        raise SystemExit(2)
    default_out = os.path.splitext(a.data)[0] + ("-exec.pdf" if a.exec_only else ".pdf")
    out = a.output or default_out
    assets = find_assets(a.assets)
    build(exec_only_view(data) if a.exec_only else data, out, assets, theme=a.theme)
    print(f"WROTE {out} ({os.path.getsize(out)} bytes)  [assets: {assets}]"
          + ("  [executive edition]" if a.exec_only else ""))


if __name__ == "__main__":
    main()
