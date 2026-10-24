# Manual API Assessment — Individual Checks and Findings

**Assessment date:** 2026-10-24  
**Target:** OWASP Juice Shop v20.3.0 training lab, reached through the local SSH tunnel on port 3001  
**Method:** Deliberate read-only HTTP requests, selected test identities/tokens, and limited source review. No checkout or other state-changing test was performed. Tokens, passwords, user data, and basket contents were not recorded.

This appendix records manual checks separately from ZAP-generated results. Some endpoints were also included in the ZAP API scan; the overlap column identifies this, while keeping the evidence from each method distinct.

## Confirmed manual findings

| Finding ID | Finding | Initial lab risk rating | Manual evidence | Tool overlap | OWASP classification / limits |
|---|---|---|---|---|---|
| MAN-API-01 | Broken object-level authorization (BOLA) on baskets | **Critical** | Account A read its own basket (HTTP 200, ID 6); Account B read its own basket (HTTP 200, ID 7). Account A then requested B's basket and received HTTP 200 with ID 7; Account B requested A's basket and received HTTP 200 with ID 6. Requests were read-only; basket contents were not printed. | The recorded ZAP API scan was unauthenticated and did not exercise two accounts against each other's basket IDs. This finding is manual-only in this assessment. | OWASP Top 10:2025 A01 Broken Access Control; OWASP API Security Top 10:2023 API1 BOLA. Impact beyond access to basket records was not tested. |
| MAN-API-02 | Unsigned JWT accepted by basket endpoint | **Critical** | A generated unsigned JWT using `alg: none`, identifying test Account A, was accepted by `GET /rest/basket/6`; response was HTTP 200 and returned basket ID 6. The token was not printed or saved. | The recorded ZAP API scan was unauthenticated and did not submit a crafted unsigned token. This finding is manual-only in this assessment. | OWASP Top 10:2025 A07 Authentication Failures; OWASP API Security Top 10:2023 API2 Broken Authentication. Broader impersonation and write-action impact were not tested. |
| MAN-API-03 | Product search accepts an ordinary query | Not a finding | `GET /rest/products/search?q=apple` returned HTTP 200. The response body was not retained. | ZAP included product search and separately generated a quote probe. | Positive functional observation only; it does not establish query safety. The SQL construction concern is recorded separately as MAN-API-04 and in ZAP-API-01. |
| MAN-API-04 | Product search quote probe did not complete manually | Not confirmed by manual test | A manual request using a single-quote search value timed out from the tester and returned no HTTP result. No exploitation or data extraction was attempted. | ZAP's generated quote probe returned HTTP 500; source review found user-controlled `q` interpolated into raw SQL. | This manual attempt is inconclusive. See ZAP-API-01 and the source analysis in the assessment report; do not describe the manual timeout as a confirmed SQL injection result. OWASP Top 10:2025 A05 Injection applies to the source-confirmed unsafe SQL construction. |

## Other manual endpoint and behavior checks

| Check ID | Request / behavior | Manual result | Tool overlap | Assessment |
|---|---|---|---|---|
| MAN-API-05 | `GET /rest/admin/application-configuration` without authentication | HTTP 200; JSON; 36,154-byte response. Property-name review showed frontend-style configuration and a Google OAuth client ID; no common secret/password/token/private-key property names were found. Response also contained private IP/port values and two future Unix timestamps, captured in the ZAP API report. | Yes. ZAP reported private IP disclosure, timestamp disclosure, and wildcard CORS for this endpoint. | Public configuration response observed. Client ID is not a client secret. Internal-address/timestamp sensitivity was not established; see API-05 in the main assessment. |
| MAN-API-06 | `GET /rest/admin/application-version` without authentication | HTTP 200 with `{"version":"20.3.0"}`. | Yes. ZAP included this route in its CORS observations. | Public version metadata; low-sensitivity fingerprinting observation, not a confirmed authorization flaw. |
| MAN-API-07 | `GET /api/Challenges/?name=Score%20Board` without authentication | HTTP 200 with challenge catalog metadata; the returned item was marked unsolved. No credential-like values were observed. | Route discovery and CORS behavior overlapped with ZAP. | Appears to be public UI data; no sensitive exposure confirmed. |
| MAN-API-08 | Challenge API request with `Origin: https://other-origin.example` | Response included `Access-Control-Allow-Origin: *`; no `Access-Control-Allow-Credentials` header was present. | Yes, ZAP found wildcard CORS on API routes; this exact selected-origin request was manual. | Confirms wildcard CORS on this public-data response. Does not demonstrate credentialed access to authenticated data. |
| MAN-API-09 | `GET /rest/languages` without authentication | HTTP 200; response body was not retained. | Yes. ZAP included the route in CORS observations. | Reachability observed; data sensitivity undetermined. |
| MAN-API-10 | `GET /api/Quantitys/` without authentication | HTTP 200; JSON, 7,628 bytes, 56 inventory records including exact quantities and per-user limits. No user records, credentials, or secrets were observed in reviewed fields. | Yes. ZAP reported wildcard CORS on this endpoint. | Inventory/business metadata is exposed. Whether this is a security defect depends on intended access policy and business sensitivity. |
| MAN-API-11 | `GET /api/Users` without authentication | HTTP 401; response body discarded to avoid retaining user data. | Yes. ZAP also observed this route and reported CORS, CSP, and content-type alerts on the 401 response. | Positive evidence that this route denies this anonymous request; does not prove authenticated object-level authorization is correct. |
| MAN-API-12 | `GET /rest/user/whoami` / identity endpoint | The session indicates this endpoint was queried, but the exact manual request/response evidence was not retained in the project record. | ZAP reported wildcard CORS for `/rest/user/whoami` (HTTP 200). | Retained as an unverified check record, not a finding. Avoid inferring what identity data was returned without the original response evidence. |

## What manual testing added beyond ZAP

- The two-account basket test established cross-user object access; the unauthenticated ZAP API scan could not establish that scenario.
- The unsigned-token request established that the tested protected endpoint accepted a forged token; the ZAP API scan did not test this token case.
- Manual inspection added context to selected anonymous responses, such as distinguishing an OAuth client ID from a secret and checking which fields were present without saving response values unnecessarily.
- Manual testing was narrow and hypothesis-driven. It does not replace broad route discovery or generated scan coverage. Conversely, ZAP alert counts and HTTP errors do not replace controlled authorization tests or source review.

## Evidence limits

The results above reflect only the requests and response details preserved in the chat/project evidence. Several GET response bodies were not saved, the manual quote probe timed out, the `whoami` response was not retained, and no write operations were tested. The lab is intentionally vulnerable; findings describe the training application and are not claims about a production service.
