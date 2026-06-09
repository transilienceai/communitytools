#!/usr/bin/env python3
"""Build-time helper: dump raw PDF text for a page range.

Assists verbatim transcription / cross-checking of the catalog. The
authoritative read is via the Read tool (`Read pages=`), which renders the
PDF faithfully; this dumper (PyPDF2) gives a quick text view for diffing.

Usage:
  python3 tools/pci-sss/extract_catalog.py --pages 11-20 [--pdf PATH]

Page numbers are 1-based PDF pages.
"""
from __future__ import annotations

import argparse
import sys

from _common import SOURCE_PDF


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", required=True, help="1-based PDF page range, e.g. 11-20 or 15")
    ap.add_argument("--pdf", default=str(SOURCE_PDF))
    args = ap.parse_args()

    try:
        import PyPDF2  # type: ignore
    except ImportError:
        print("PyPDF2 not installed; `pip install PyPDF2` or read via the Read tool", file=sys.stderr)
        return 2

    if "-" in args.pages:
        a, b = args.pages.split("-", 1)
        lo, hi = int(a), int(b)
    else:
        lo = hi = int(args.pages)

    reader = PyPDF2.PdfReader(args.pdf)
    for p in range(lo, hi + 1):
        if 1 <= p <= len(reader.pages):
            print(f"\n===== PDF PAGE {p} =====")
            print(reader.pages[p - 1].extract_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
