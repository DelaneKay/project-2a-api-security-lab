#!/usr/bin/env python3
"""Show bounded excerpts around server-error alerts in a ZAP API HTML report."""

# Run from the WSL workstation after the ZAP API Scan has produced its HTML report.
from html.parser import HTMLParser
from pathlib import Path
import re
import sys


report = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "project-2a/zap-reports/juice-shop-api-active.html"


class Errors(HTMLParser):
    def __init__(self):
        super().__init__()
        self.capture = False
        self.depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("name") == "100000":
            self.capture = True
            self.depth = 1
        elif self.capture:
            self.depth += 1

    def handle_endtag(self, tag):
        if self.capture:
            self.depth -= 1
            if self.depth <= 0:
                self.capture = False

    def handle_data(self, value):
        if self.capture and value.strip():
            self.parts.append(value.strip())


html = report.read_text(errors="replace")
parser = Errors()
parser.feed(html)
if parser.parts:
    print("\n".join(parser.parts[:250]))
else:
    print("No matching alert block found; searching the report text instead.")
    for match in list(re.finditer(r"Server Error response code", html, re.I))[:2]:
        excerpt = html[max(0, match.start() - 1000):match.start() + 5000]
        print(re.sub(r"<[^>]+>", " ", excerpt))
        print("\n---\n")
