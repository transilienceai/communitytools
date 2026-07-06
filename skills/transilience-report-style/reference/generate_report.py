#!/usr/bin/env python3
"""
Transilience-style report generator (data-driven, reusable).

Usage:
    python3 generate_report.py <report_data.json> [-o output.pdf] [--assets <dir>]

Reads ONE JSON describing the engagement + findings (see report-data-schema.json)
and emits a Transilience-branded A4 PDF. All sections except `engagement` and
`findings` are optional — omit a key and the section is skipped.

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
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
                                Table, TableStyle, Image, PageBreak, NextPageTemplate, KeepTogether)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


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


# ---------- palette / fonts (Transilience design system v4) ----------
def register_fonts(fonts_dir):
    def reg(alias, fn):
        try: pdfmetrics.registerFont(TTFont(alias, os.path.join(fonts_dir, fn)))
        except Exception: pass
    reg("Poppins", "Poppins-Regular.ttf"); reg("Poppins-Bold", "Poppins-Bold.ttf")
    reg("Poppins-Med", "Poppins-Medium.ttf"); reg("Carlito", "Carlito-Regular.ttf")
    reg("Carlito-Bold", "Carlito-Bold.ttf")

FB, FM, FP, FC, FCB = "Poppins-Bold", "Poppins-Med", "Poppins", "Carlito", "Carlito-Bold"
BG = colors.HexColor("#07040B"); BGC = colors.HexColor("#13101C"); BGCA = colors.HexColor("#1A1625")
GL = colors.HexColor("#1E1A2E"); BS = colors.HexColor("#2A2535"); BP = colors.HexColor("#6941C6"); BPL = colors.HexColor("#8B5CF6")
WHITE = colors.HexColor("#FFFFFF"); BODY = colors.HexColor("#F0F2F5"); LBL = colors.HexColor("#E0E3E8")
GREEN = colors.HexColor("#10B981"); BLUE = colors.HexColor("#3B82F6"); AMBER = colors.HexColor("#F59E0B")
SEV = {"Critical": colors.HexColor("#EF4444"), "High": colors.HexColor("#FB923C"),
       "Medium": colors.HexColor("#EAB308"), "Low": colors.HexColor("#22C55E"), "Info": colors.HexColor("#9CA3AF")}
PAGE = A4; MX = 16 * mm; CW = PAGE[0] - 2 * MX

def hx(c): return "#" + c.hexval()[2:]
def esc(s): return html.escape(str(s if s is not None else ""), quote=False)
def mask(s):  # defensive PII/secret masking
    s = str(s or "")
    s = re.sub(r'\b(\d{6})\d{4,9}(\d{2,4})\b', lambda m: m.group(1) + "****" + m.group(2), s)
    s = re.sub(r'\b([A-Z]{5})\d{4}([A-Z])\b', r'\1####\2', s)
    return s

def styles():
    ps = lambda n, **k: ParagraphStyle(n, **k)
    return {
      "ct": ps("ct", fontName=FB, fontSize=30, leading=36, textColor=WHITE),
      "cc": ps("cc", fontName=FM, fontSize=15, leading=21, textColor=BPL),
      "h1": ps("h1", fontName=FB, fontSize=18, leading=24, textColor=WHITE, spaceAfter=8),
      "h3": ps("h3", fontName=FM, fontSize=11, leading=15, textColor=BPL, spaceBefore=5, spaceAfter=2),
      "body": ps("body", fontName=FC, fontSize=10, leading=14.5, textColor=BODY, alignment=TA_JUSTIFY, spaceAfter=5),
      "bs": ps("bs", fontName=FC, fontSize=9, leading=12.5, textColor=BODY),
      "bsw": ps("bsw", fontName=FC, fontSize=8.3, leading=11, textColor=BODY, wordWrap='CJK'),
      "mono": ps("mono", fontName="Courier", fontSize=7.6, leading=10, textColor=BODY, wordWrap='CJK'),
      "sl": ps("sl", fontName=FM, fontSize=8.3, leading=11, textColor=WHITE),
      "label": ps("label", fontName=FP, fontSize=10, leading=14, textColor=LBL),
      "bullet": ps("bullet", fontName=FC, fontSize=10, leading=14.5, textColor=BODY, leftIndent=12, spaceAfter=3),
      "notice": ps("notice", fontName=FC, fontSize=8.3, leading=12, textColor=LBL),
      "metric": ps("metric", fontName=FB, fontSize=20, leading=22, textColor=WHITE, alignment=TA_CENTER),
      "metricl": ps("metricl", fontName=FM, fontSize=7.5, leading=9.5, textColor=LBL, alignment=TA_CENTER),
      "cardt": ps("cardt", fontName=FB, fontSize=11, leading=14.5, textColor=WHITE),
      "cardlbl": ps("cardlbl", fontName=FM, fontSize=8, leading=11, textColor=BPL),
      "cardbody": ps("cardbody", fontName=FC, fontSize=8.8, leading=12, textColor=BODY),
      "v": ps("v", fontName=FM, fontSize=10.5, textColor=WHITE, leading=14),
    }


def build(data, dest, assets):
    register_fonts(os.path.join(assets, "fonts"))
    LOGO = os.path.join(assets, "transilience-logo.png")
    S = styles()
    eng = data.get("engagement", {})
    findings = data.get("findings", [])
    sm = Counter(f.get("severity", "Info") for f in findings)

    def grad(c, x, y, w, h, steps=80):
        sw = w / steps
        for i in range(steps):
            t = i / (steps - 1); r = 0.412 + (0.788 - 0.412) * t; g = 0.255 + (0.192 - 0.255) * t; b = 0.776 + (0.486 - 0.776) * t
            c.setFillColorRGB(r, g, b); c.rect(x + i * sw, y, sw + 1, h, fill=1, stroke=0)

    foot = f"TRANSILIENCE AI   ·   {eng.get('footer','Security Assessment')}   ·   CONFIDENTIAL   ·   {eng.get('date','')}"
    def page_bg(c, d):
        c.saveState(); c.setFillColor(BG); c.rect(0, 0, *PAGE, fill=1, stroke=0)
        grad(c, 0, PAGE[1] - 3.5, PAGE[0], 3.5)
        c.setFillColor(GL); c.rect(0, 0, PAGE[0], 26, fill=1, stroke=0)
        c.setFillColor(colors.HexColor("#9CA3AF")); c.setFont(FP, 7); c.drawString(MX, 9.5, foot)
        c.setFillColor(BPL); c.setFont(FB, 9); c.drawRightString(PAGE[0] - MX, 9.5, f"{d.page}")
        c.setFillColorRGB(0.412, 0.255, 0.776, 0.12); c.rect(0, 26, 2.5, PAGE[1] - 26, fill=1, stroke=0)
        c.restoreState()
    def page_cover(c, d):
        c.saveState(); c.setFillColor(BG); c.rect(0, 0, *PAGE, fill=1, stroke=0)
        grad(c, 0, PAGE[1] - 4, PAGE[0], 4)
        c.setFillColorRGB(0.412, 0.255, 0.776, 0.12); c.rect(0, 0, 2.5, PAGE[1], fill=1, stroke=0)
        c.restoreState()

    doc = BaseDocTemplate(dest, pagesize=PAGE, leftMargin=MX, rightMargin=MX, topMargin=20 * mm,
                          bottomMargin=16 * mm, title=eng.get("title", "Security Report"), author="Transilience AI")
    fr = Frame(MX, 15 * mm, CW, PAGE[1] - 34 * mm, id="m")
    doc.addPageTemplates([PageTemplate(id="cover", frames=[fr], onPage=page_cover),
                          PageTemplate(id="main", frames=[fr], onPage=page_bg)])

    def gline(col=None, h=2, frac=1.0):
        t = Table([[""]], colWidths=[CW * frac], rowHeights=[h]); t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), h, col or BP)])); return t
    def mbox(label, val, col):
        t = Table([[Paragraph(f'<font color="{hx(col)}">{val}</font>', S["metric"])], [Paragraph(esc(label), S["metricl"])]], colWidths=[CW / 6.2])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BGC), ("BOX", (0, 0), (-1, -1), 0.6, BS),
            ("LINEABOVE", (0, 0), (-1, 0), 3, col), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)])); return t
    def tbl(header, rows, widths, sevcol=None, cell="bsw"):
        cells = [[Paragraph(esc(h), S["sl"]) for h in header]] + [[Paragraph(esc(c), S[cell]) for c in r] for r in rows]
        t = Table(cells, colWidths=widths, repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), BGC), ("GRID", (0, 0), (-1, -1), 0.4, GL), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
              ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 5),
              ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG, BGCA])]
        if sevcol is not None:
            for i, r in enumerate(rows, 1):
                if r[sevcol] in SEV: st += [("TEXTCOLOR", (sevcol, i), (sevcol, i), SEV[r[sevcol]]), ("FONTNAME", (sevcol, i), (sevcol, i), FCB)]
        t.setStyle(TableStyle(st)); return t

    E = []
    sec = [0]
    def section(title):
        sec[0] += 1
        E.append(Paragraph(f"{sec[0]:02d} · {esc(title)}", S["h1"])); E.append(gline(BP, 2)); E.append(Spacer(1, 5))

    # ---- cover ----
    E.append(Spacer(1, 34 * mm))
    if os.path.exists(LOGO):
        try: E.append(Image(LOGO, width=50 * mm, height=50 * mm * 0.28)); E.append(Spacer(1, 18 * mm))
        except Exception: pass
    for line in eng.get("title_lines", [eng.get("title", "SECURITY ASSESSMENT REPORT")]):
        E.append(Paragraph(esc(line), S["ct"]))
    E.append(Spacer(1, 6 * mm))
    if eng.get("subtitle"): E.append(Paragraph(esc(eng["subtitle"]), S["cc"]))
    E.append(Spacer(1, 5 * mm)); E.append(gline(BP, 2, 0.35)); E.append(Spacer(1, 9 * mm))
    _alias = {"REPORT DATE": "date", "PREPARED BY": "prepared_by", "REPORT ID": "report_id"}
    meta = eng.get("cover_meta") or [[k, eng.get(_alias.get(k, k.lower().replace(" ", "_")), "")] for k in
        ["REPORT DATE", "CLASSIFICATION", "SECTOR", "TARGET", "METHOD", "PREPARED BY", "REPORT ID"]]
    mt = Table([[Paragraph(esc(k), S["label"]), Paragraph(esc(v), S["v"])] for k, v in meta if v],
               colWidths=[CW * 0.32, CW * 0.68])
    mt.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    E.append(mt); E.append(Spacer(1, 14 * mm))
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
            metrics = [{"label": k.upper(), "value": sm.get(k, 0), "sev": k} for k in ["High", "Medium", "Low", "Info"]]
        strip = [mbox(m["label"], m["value"], SEV.get(m.get("sev"), BPL) if not m.get("color") else colors.HexColor(m["color"])) for m in metrics[:6]]
        if strip:
            ms = Table([strip], colWidths=[CW / max(6.05, len(strip) + 0.05)] * len(strip))
            ms.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1)]))
            E.append(Spacer(1, 4)); E.append(ms); E.append(Spacer(1, 9))
        if exsum.get("key_risks"):
            E.append(Paragraph("Key Risks", S["h3"]))
            for t in exsum["key_risks"]: E.append(Paragraph("&bull; " + t, S["bullet"]))
        if exsum.get("positives"):
            E.append(Paragraph("Positive Observations", S["h3"]))
            for t in exsum["positives"]: E.append(Paragraph("&bull; " + t, S["bullet"]))
        E.append(PageBreak())

    # ---- scope / methodology (free-form blocks) ----
    for blk in data.get("sections", []):
        section(blk["title"])
        for p in blk.get("paragraphs", []): E.append(Paragraph(p, S["body"]))
        if blk.get("table"):
            E.append(tbl(blk["table"]["header"], blk["table"]["rows"], [CW * w for w in blk["table"]["widths"]]))
        E.append(PageBreak())

    # ---- findings (grouped by severity) ----
    def cve_block(f):
        rows = [[c["id"], str(c.get("score")), c.get("severity", "")] for c in f.get("cves", [])]
        out = [Paragraph(f'<font color="{hx(BLUE)}" name="{FM}">CVE RISK (authoritative NVD)</font>', S["cardlbl"]),
               tbl(["CVE", "CVSS", "Severity"], rows, [CW * 0.30, CW * 0.12, CW * 0.20], cell="mono")]
        if f.get("cve_caveat"): out.append(Paragraph(f'<font color="{hx(AMBER)}">{esc(f["cve_caveat"])}</font>', S["cardbody"]))
        return out

    def card(f):
        sc = SEV.get(f.get("severity", "Info"), SEV["Info"]); flow = []
        flow.append(Table([[""]], colWidths=[CW], rowHeights=[4], style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), sc)])))
        flow.append(Spacer(1, 5))
        flow.append(Paragraph(f'<font name="{FB}" color="{hx(sc)}">{esc(f.get("id",""))}  [{esc(f.get("severity","").upper())}]</font>  '
                              f'<font name="{FB}" color="#FFFFFF">{esc(f.get("title",""))}</font>', S["cardt"]))
        status = "CONFIRMED (offline)" if not f.get("needs_live_confirmation") else "EVIDENCED — needs live confirmation"
        flow.append(Paragraph(f'<font color="{hx(BPL)}">CVSS:</font> {esc(f.get("cvss_score",""))}  '
                              f'<font color="{hx(BPL)}">Vector:</font> <font name="Courier">{esc(f.get("cvss_vector",""))}</font>', S["cardbody"]))
        flow.append(Paragraph(f'<font color="{hx(BPL)}">CWE:</font> {esc(f.get("cwe",""))} &nbsp; <font color="{hx(BPL)}">OWASP:</font> {esc(f.get("owasp",""))} '
                              f'&nbsp; <font color="{hx(BPL)}">Status:</font> <font color="{hx(GREEN if not f.get("needs_live_confirmation") else AMBER)}">{status}</font>', S["cardbody"]))
        aff = "; ".join(f.get("affected", [])[:6]) + (" …" if len(f.get("affected", [])) > 6 else "")
        if aff: flow.append(Paragraph(f'<font color="{hx(BPL)}">Affected:</font> <font name="Courier">{esc(mask(aff))}</font>', S["cardbody"]))
        for lbl, key, col, lim in [("DESCRIPTION", "description", BPL, 1500), ("EVIDENCE", "evidence", BPL, 1400),
                                   ("IMPACT", "impact", BPL, 1000)]:
            if f.get(key):
                flow.append(Paragraph(f'<font color="{hx(col)}" name="{FM}">{lbl}</font>', S["cardlbl"]))
                flow.append(Paragraph(esc(mask(f[key]))[:lim], S["cardbody"]))
        if f.get("calibration"):
            flow.append(Paragraph(f'<font color="{hx(AMBER)}" name="{FM}">SEVERITY CALIBRATION</font>', S["cardlbl"]))
            flow.append(Paragraph(esc(f["calibration"]), S["cardbody"]))
        if f.get("poc_request"):
            flow.append(Paragraph(f'<font color="{hx(BLUE)}" name="{FM}">TEST / PROOF-OF-CONCEPT</font>', S["cardlbl"]))
            flow.append(Paragraph(esc(mask(f["poc_request"]))[:1100], S["mono"]))
            if f.get("test_method"): flow.append(Paragraph(f'<font color="{hx(BPL)}">Confirms when:</font> {esc(mask(f["test_method"]))[:400]}', S["cardbody"]))
        if f.get("cves"): flow += cve_block(f)
        if f.get("recommendation"):
            flow.append(Paragraph(f'<font color="{hx(GREEN)}" name="{FM}">REMEDIATION</font>', S["cardlbl"]))
            flow.append(Paragraph(esc(f["recommendation"]), S["cardbody"]))
        flow.append(Spacer(1, 6)); flow.append(gline(BS, 0.6, 0.5)); flow.append(Spacer(1, 8))
        return flow

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    by_sev = {}
    for f in findings: by_sev.setdefault(f.get("severity", "Info"), []).append(f)
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        fl = by_sev.get(level)
        if not fl: continue
        fl.sort(key=lambda x: -(x.get("cvss_score") or 0))
        section(f"{level}-Severity Findings" if level != "Info" else "Informational")
        for f in fl:
            if level in ("Low", "Info"): E.append(KeepTogether(card(f)))
            else:
                for frag in card(f): E.append(frag)
        E.append(PageBreak())

    # ---- optional registers ----
    if data.get("cve_register"):
        section("CVE Risk Register (authoritative NVD)")
        rows = [[c.get("cve"), c.get("component", ""), str(c.get("score")), c.get("severity", ""), (c.get("summary") or "")[:90]] for c in data["cve_register"]]
        E.append(tbl(["CVE", "Component", "CVSS", "Severity", "Summary"], rows, [CW * 0.16, CW * 0.18, CW * 0.08, CW * 0.12, CW * 0.46], sevcol=3)); E.append(PageBreak())
    if data.get("coverage_table"):
        section("Coverage")
        ct = data["coverage_table"]
        E.append(tbl(ct["header"], ct["rows"], [CW * w for w in ct["widths"]]))
        if ct.get("note"): E.append(Spacer(1, 4)); E.append(Paragraph(esc(ct["note"]), S["bs"]))
        E.append(PageBreak())
    if data.get("ruled_out"):
        section("Ruled-Out Candidates (false positives)")
        E.append(Paragraph("Blind adversarial validation ruled these out — recorded for transparency.", S["body"]))
        E.append(tbl(["Candidate", "Why rejected"], [[r.get("title", "")[:70], r.get("why", "")[:120]] for r in data["ruled_out"]], [CW * 0.40, CW * 0.60])); E.append(PageBreak())
    if data.get("tools_used"):
        section("Tools & Techniques Used")
        if data.get("tools_intro"): E.append(Paragraph(esc(data["tools_intro"]), S["body"]))
        E.append(tbl(["Tool / Technique", "Purpose", "Mode / Outcome"], data["tools_used"], [CW * 0.26, CW * 0.50, CW * 0.24])); E.append(PageBreak())
    if data.get("roadmap"):
        section("Remediation Roadmap")
        cmap = {"immediate": SEV["High"], "short": SEV["Medium"], "medium": SEV["Low"], "long": BPL}
        for r in data["roadmap"]:
            col = next((v for k, v in cmap.items() if k in r["title"].lower()), BPL)
            E.append(Paragraph(f'<font color="{hx(col)}">{esc(r["title"])}</font>', S["h3"]))
            for it in r.get("items", []): E.append(Paragraph("&bull; " + esc(it), S["bullet"]))
            E.append(Spacer(1, 4))
    if data.get("disclaimer"):
        E.append(Spacer(1, 8)); E.append(gline(BS, 0.6)); E.append(Spacer(1, 4))
        E.append(Paragraph(esc(data["disclaimer"]), S["notice"]))

    doc.build(E)
    return dest


def main():
    ap = argparse.ArgumentParser(description="Generate a Transilience-style PDF report from a JSON data file.")
    ap.add_argument("data", help="report_data.json")
    ap.add_argument("-o", "--output", default=None, help="output PDF path")
    ap.add_argument("--assets", default=None, help="path to formats/transilience-report-style (fonts + logo)")
    a = ap.parse_args()
    data = json.load(open(a.data))
    out = a.output or os.path.splitext(a.data)[0] + ".pdf"
    assets = find_assets(a.assets)
    build(data, out, assets)
    print(f"WROTE {out} ({os.path.getsize(out)} bytes)  [assets: {assets}]")


if __name__ == "__main__":
    main()
