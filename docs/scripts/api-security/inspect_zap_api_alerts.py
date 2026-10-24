#!/usr/bin/env python3
"""Print short text excerpts for selected alerts in the ZAP API HTML report."""

# Run from the WSL workstation after the ZAP API Scan has produced its HTML report.
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
terms = (
    "SQL Injection",
    "/rest/products/search",
    "Cross-Domain Misconfiguration",
    "Private IP Disclosure",
    "Timestamp Disclosure - Unix",
    "Unexpected Content-Type",
)

for term in terms:
    positions = []
    start = 0
    while True:
        pos = body.lower().find(term.lower(), start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + len(term)
    print(f"\n--- {term} ({len(positions)} occurrences) ---")
    if not positions:
        print("Not found in report")
        continue
    for pos in positions[:3]:
        print(body[max(0, pos - 300):pos + 1100])
        print()
