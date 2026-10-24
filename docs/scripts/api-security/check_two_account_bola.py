#!/usr/bin/env python3
"""Use two lab accounts to compare own-basket and cross-account read responses."""

# Run on the target server, where the Juice Shop container bridge is reachable.
import getpass
import json
import sys
import urllib.error
import urllib.request


BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:3000"


def call(path, token=None, body=None):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    try:
        return response.status, json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return response.status, {}


def login(label):
    print(f"\nAccount {label}")
    email = getpass.getpass("Test account email (hidden): ").strip()
    password = getpass.getpass("Test account password (hidden): ")
    status, result = call("/rest/user/login", body={"email": email, "password": password})
    if status != 200 or "authentication" not in result:
        raise RuntimeError(f"Account {label} login did not succeed (HTTP {status})")
    auth = result["authentication"]
    return auth["token"], str(auth["bid"])


token_a, basket_a = login("A")
token_b, basket_b = login("B")
cases = (
    ("Account A reading its own basket", token_a, basket_a),
    ("Account B reading its own basket", token_b, basket_b),
    ("Account A reading Account B's basket", token_a, basket_b),
    ("Account B reading Account A's basket", token_b, basket_a),
)

for label, token, basket_id in cases:
    status, result = call(f"/rest/basket/{basket_id}", token=token)
    returned_id = result.get("data", {}).get("id")
    print(f"{label}: HTTP {status}; returned basket ID={returned_id}")
