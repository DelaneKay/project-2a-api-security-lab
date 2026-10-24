#!/usr/bin/env python3
"""Print report excerpts around the ZAP SQL alert and product-search route."""

# Run from the WSL workstation after the ZAP API Scan HTML report is saved.
from html.parser import HTMLParser
from pathlib import Path
import sys


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, value):
        if value.strip():
            self.parts.append(value.strip())


report = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "project-2a/zap-reports/juice-shop-api-active.html"
parser = Text()
parser.feed(report.read_text(errors="replace"))
body = " ".join(" ".join(parser.parts).split())
for term in ("SQL Injection", "/rest/products/search"):
    pos = body.lower().find(term.lower())
    print(f"--- {term} ---")
    print(body[max(0, pos - 500):pos + 1800] if pos >= 0 else "Not found in report")
