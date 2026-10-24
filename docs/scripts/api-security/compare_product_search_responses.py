#!/usr/bin/env python3
"""Compare response metadata for a normal and quote-containing Juice Shop search."""

# Run from WSL while the SSH tunnel to Juice Shop is listening on localhost:3001.
import urllib.error
import urllib.request


base = "http://localhost:3001/rest/products/search?q="
for label, value in (("normal search", "apple"), ("single quote", "%27")):
    request = urllib.request.Request(base + value, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(f"{label}: HTTP {response.status}, {response.headers.get('Content-Type')}, {response.headers.get('Content-Length', 'unknown')} bytes")
    except urllib.error.HTTPError as error:
        print(f"{label}: HTTP {error.code}, {error.headers.get('Content-Type')}, error response")
    except Exception as error:
        print(f"{label}: request failed ({type(error).__name__}: {error})")
