#!/usr/bin/env python3
"""Compare the saved classic and AJAX Spider result lists by exact URL string."""

# Run from WSL after saving spider-results.json and ajax-spider-results.json.
import json
from pathlib import Path
from urllib.parse import urlparse


root = Path.home() / "project-2a/zap-reports"


def load_urls(filename):
    entries = json.loads((root / filename).read_text()).get("results", [])
    return {entry if isinstance(entry, str) else entry.get("url") for entry in entries} - {None}


spider = load_urls("spider-results.json")
ajax = load_urls("ajax-spider-results.json")
for name, urls in (("traditional", spider), ("AJAX", ajax)):
    print(name, "URLs:", len(urls))
    print(name, "/api/ paths:", sum("/api/" in urlparse(url).path for url in urls))
print("shared exact URLs:", len(spider & ajax))
print("AJAX-only exact URLs:", len(ajax - spider))
