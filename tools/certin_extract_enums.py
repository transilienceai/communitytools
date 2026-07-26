#!/usr/bin/env python3
"""Extract the CERT-In Audit Metadata Format controlled vocabularies into enums.json.

One-shot generator. Parses the official v2.3 workbook's two hidden sheets
("Hidden Sheet- Options" = sheet7, "Hidden - sub-sector" = sheet8) plus the
Manpower sheet's certification headers (sheet6), and writes the single
source-of-truth `enums.json` that tools/certin_metadata_build.py validates
emitted values against.

Stdlib only (zipfile + xml.etree). Values are extracted verbatim — nothing is
invented. Re-run whenever CERT-In publishes a new template version.

Usage:
    python3 tools/certin_extract_enums.py \
        --template formats/certin-audit-metadata/Audit-Metadata-Format-2026.xlsx \
        -o formats/certin-audit-metadata/enums.json
"""
import argparse
import json
import sys
import zipfile
import xml.etree.ElementTree as ET

M = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
TEMPLATE_VERSION = "2.3 July 2026"

# sheet7 "Hidden Sheet- Options" — column -> enum name. Verified against the v2.3
# template content; counts are asserted below so a template change is caught.
SHEET7_COLUMNS = {
    "C": "category",
    "E": "audit_type",
    "F": "reason",
    "G": "state_ut",
    "H": "attributing_factor",
    "I": "severity",
    "J": "standards",
    "Q": "report_type",   # First Audit / Final Audit (data sheets col N/G)
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def col_of(coord):
    return "".join(c for c in coord if c.isalpha())


def row_of(coord):
    return int("".join(c for c in coord if c.isdigit()))


def read_shared_strings(z):
    out = []
    if "xl/sharedStrings.xml" not in z.namelist():
        return out
    root = ET.fromstring(z.read("xl/sharedStrings.xml"))
    for si in root:
        out.append("".join(t.text or "" for t in si.iter(M + "t")))
    return out


def cell_value(c, shared):
    t = c.get("t")
    v = c.find(M + "v")
    isnode = c.find(M + "is")
    if t == "s" and v is not None:
        return shared[int(v.text)]
    if isnode is not None:
        return "".join(x.text or "" for x in isnode.iter(M + "t"))
    if v is not None:
        return v.text
    return None


def read_cells(z, sheet_file, shared):
    """Return {coord: value} for non-empty cells of a worksheet."""
    root = ET.fromstring(z.read("xl/worksheets/" + sheet_file))
    sd = root.find(M + "sheetData")
    cells = {}
    if sd is None:
        return cells
    for row in sd.findall(M + "row"):
        for c in row.findall(M + "c"):
            val = cell_value(c, shared)
            if val is not None and str(val).strip() != "":
                cells[c.get("r")] = str(val).replace("\xa0", " ").strip()
    return cells


def column_values(cells, letter, min_row=1):
    """Ordered, de-duplicated values down one column (row order)."""
    items = sorted(
        ((row_of(k), v) for k, v in cells.items() if col_of(k) == letter and row_of(k) >= min_row),
        key=lambda kv: kv[0],
    )
    seen, out = set(), []
    for _, v in items:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def extract(template_path):
    z = zipfile.ZipFile(template_path)
    shared = read_shared_strings(z)
    s7 = read_cells(z, "sheet7.xml", shared)
    s8 = read_cells(z, "sheet8.xml", shared)
    s6 = read_cells(z, "sheet6.xml", shared)

    enums = {}
    for letter, name in SHEET7_COLUMNS.items():
        # column may have a header in row 1 for some columns; options list starts row 1 here.
        enums[name] = column_values(s7, letter, min_row=1)

    # severity: force canonical high->low order (extraction order is alphabetical)
    got = set(enums["severity"])
    enums["severity"] = [s for s in SEVERITY_ORDER if s in got] + [s for s in enums["severity"] if s not in SEVERITY_ORDER]

    # count_specials: the non-integer tokens used by the count/patch/gap/open columns (K,L,M,N).
    specials = []
    for letter in ("K", "L", "M", "N"):
        for v in column_values(s7, letter, min_row=1):
            try:
                int(v)
            except (TypeError, ValueError):
                if v not in specials:
                    specials.append(v)
    enums["count_specials"] = specials

    # sector -> [subsectors] from sheet8 A2:B36 (canonical spaced sector display form).
    sector_map = {}
    pairs = []
    for k, v in s8.items():
        if col_of(k) == "A" and row_of(k) >= 2:
            pairs.append((row_of(k), v))
    for r, sector in sorted(pairs):
        sub = s8.get("B%d" % r)
        if sector and sub:
            sector_map.setdefault(sector, [])
            if sub not in sector_map[sector]:
                sector_map[sector].append(sub)
    enums["sector"] = sector_map

    # certifications: Manpower sheet6 row 2, columns E..K
    certs = [s6.get("%s2" % col) for col in ("E", "F", "G", "H", "I", "J", "K")]
    enums["certifications"] = [c for c in certs if c]

    # first_final is the report_type extracted from sheet7 col N
    enums["first_final"] = enums.pop("report_type")

    # attributing-factor CWE mapping is a builder concern, not a template vocabulary — omitted here.

    # --- sanity assertions (fail loudly if the template shape drifts) ---
    checks = {
        "category": (5, 8),
        "audit_type": (15, 25),
        "reason": (8, 14),
        "state_ut": (30, 40),
        "attributing_factor": (6, 6),
        "severity": (5, 5),
        "standards": (14, 20),
        "certifications": (7, 7),
        "first_final": (2, 2),
    }
    for name, (lo, hi) in checks.items():
        n = len(enums[name])
        if not (lo <= n <= hi):
            raise SystemExit("extract: enum '%s' has %d values, expected %d..%d — template drift?" % (name, n, lo, hi))
    if len(enums["sector"]) != 12:
        raise SystemExit("extract: sector map has %d sectors, expected 12" % len(enums["sector"]))

    enums["_meta"] = {"template_version": TEMPLATE_VERSION, "source": "hidden sheets 7/8 + Manpower headers", "tlp": "AMBER"}
    return enums


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", default="formats/certin-audit-metadata/Audit-Metadata-Format-2026.xlsx")
    ap.add_argument("-o", "--out", default="formats/certin-audit-metadata/enums.json")
    args = ap.parse_args()
    try:
        enums = extract(args.template)
    except (OSError, zipfile.BadZipFile, ET.ParseError) as e:
        print("extract: cannot read template %s: %s" % (args.template, e), file=sys.stderr)
        return 2
    with open(args.out, "w") as f:
        json.dump(enums, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print(json.dumps({"out": args.out, "sectors": len(enums["sector"]),
                      "audit_types": len(enums["audit_type"]), "standards": len(enums["standards"]),
                      "states": len(enums["state_ut"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
