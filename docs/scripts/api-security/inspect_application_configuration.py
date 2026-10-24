#!/usr/bin/env python3
"""Print configuration property paths and secret-like key names, never values."""

# Run from WSL while the Juice Shop SSH tunnel is available on localhost:3000.
import json
import re
import urllib.request


URL = "http://localhost:3000/rest/admin/application-configuration"
SENSITIVE_NAME = re.compile(r"secret|password|token|private|credential|api.?key", re.I)

with urllib.request.urlopen(URL, timeout=10) as response:
    data = json.load(response)

print("Top-level properties:")
for key in sorted(data) if isinstance(data, dict) else []:
    print(" ", key)


def walk(value, path="$"):
    if isinstance(value, dict):
        for key, child in sorted(value.items()):
            child_path = f"{path}.{key}"
            print(child_path)
            if SENSITIVE_NAME.search(key):
                print("  REVIEW KEY NAME:", child_path)
            walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(child, f"{path}[{index}]")


print("Configuration property paths (values omitted):")
walk(data.get("config", {}), "$.config")
