# Project 2A — Consolidated Security Assessment Inventory

**Assessment date:** 2026-10-24  
**Target:** OWASP Juice Shop v20.3.0, intentionally vulnerable training application  
**Purpose:** Record assessment evidence and classify findings. This is not a claim of production security or compliance.

The technical first-pass triage and prioritization is in [triage-review.md](triage-review.md); it distinguishes confirmed lab behavior, source findings, likely test/build-only records, and items requiring service-owner context.

## Scope and evidence sources

This inventory consolidates the evidence currently preserved in `zap-baseline-report.md`. The work covered SCA (Snyk Open Source), SAST (Snyk Code), passive and API scanning (OWASP ZAP), plus read-only manual API checks. Findings in the training application's deliberate challenge code are reported as assessment results, not treated as defects in a production service.

The user pasted detailed Snyk results into the chat. The individual Snyk Code and Snyk Open Source records have now been transcribed into [the SAST appendix](sast-individual-findings.md) and [the SCA appendix](sca-individual-findings.md). Those appendices preserve the reported finding IDs, source paths/severities, advisory links, affected packages, and dependency path/fix notes where present. ZAP alert-instance totals remain grouped where the pasted report supplied aggregate counts rather than a clean per-instance export.

## SCA — Snyk Open Source

**Recorded result:** 87 issue entries: 2 Critical, 36 High, 47 Medium, and 2 Low. These are **Snyk-reported severities**, not the final lab risk ratings. The count represents advisory/path entries and may include multiple paths to the same underlying package advisory. Scan used `snyk test --dev` after local dependency installation because the checkout had no lockfile. This is not an exact SBOM of the running container.

**Individual records:** See [sca-individual-findings.md](sca-individual-findings.md) for all 87 pasted advisory/path entries. Repeated advisories along different dependency paths are retained as distinct CLI entries; consolidate them only when prioritizing remediation.

| Finding record | Snyk-reported severity | Evidence preserved | Classification / caveat |
|---|---|---|---|
| SCA aggregate — 87 advisory/path entries | Critical 2; High 36; Medium 47; Low 2 | Counts from the pasted Snyk CLI output | The individual issue records are listed in [sca-individual-findings.md](sca-individual-findings.md); this is not a count of 87 distinct packages. |

**OWASP classification:** SCA findings must be classified individually based on the affected dependency and demonstrated application impact. A package advisory does not automatically map to one OWASP Top 10 category. Capture the relevant vulnerability type (for example, vulnerable/outdated component) only where supported by the advisory and use the edition named in the report.

## SAST — Snyk Code

**Recorded result:** 306 open issues: 26 High, 11 Medium, and 269 Low; none ignored. These are **Snyk-reported severities**, not the final lab risk ratings. Scan target was the Juice Shop v20.3.0 source checkout. The source is intentionally vulnerable and includes test/challenge code, so each result needs source and data-flow triage before calling it exploitable.

**Individual records:** See [sast-individual-findings.md](sast-individual-findings.md) for all 306 pasted findings, with IDs, severities, titles, and source locations.

| Finding record | Snyk-reported severity | Evidence preserved | Classification / caveat |
|---|---|---|---|
| SAST aggregate — 306 open issues | High 26; Medium 11; Low 269 | Counts from the pasted Snyk Code output | All individual titles, finding IDs, reported severities, and source locations are listed in [sast-individual-findings.md](sast-individual-findings.md). |

**OWASP classification:** Map individual SAST issues only after reviewing the actual rule and code context. Depending on evidence, classes may map to injection, access control, insecure design, security misconfiguration, or other OWASP categories. Do not assign one category to all 306 findings.

## DAST — OWASP ZAP

The per-finding DAST inventory, with separate generic baseline, AJAX baseline, route-discovery, and active API scan results, is in [dast-individual-findings.md](dast-individual-findings.md). That appendix preserves every alert record and affected URL shown in the pasted reports, and identifies aggregate counts where the pasted report did not include all instance URLs.

### Generic ZAP baseline — passive scan

**Coverage/result:** 116 URLs crawled; 0 FAIL, 3 warning types, 58 PASS. This was a passive baseline and did not send active attack payloads.

| Finding / observation | ZAP risk | Evidence in generic baseline | Interpretation |
|---|---|---|---|
| Content Security Policy (CSP) Header Not Set (10038) | Medium | Missing CSP observed on the root and discovered paths including `/`, `/ftp`, and `/sitemap.xml`. | Header absence is confirmed; no XSS exploit was demonstrated. Candidate OWASP Top 10:2025 A02 Security Misconfiguration. |
| Cross-Domain Misconfiguration (10098) | Medium | `Access-Control-Allow-Origin: *` on GET responses for `/`, `/assets/public/favicon_js.ico`, `/robots.txt`, `/rolldown-runtime-BoHGiXSq.js`, and `/styles.css`. | Permissive CORS on observed resources; no authenticated sensitive data exposure was demonstrated. Candidate A02 Security Misconfiguration. |
| Modern Web Application (10109) | Informational | JavaScript observed but no links discovered during traditional crawling; instances included the root, file-server route references, and `/sitemap.xml`. | Informational crawler classification, not a vulnerability. It indicates traditional crawling had limited visibility into the JavaScript application. |

### AJAX-enabled ZAP baseline — passive scan with client-side crawling

**Coverage/result:** 35 URLs; 0 FAIL, 3 warning types, 58 PASS. This was a separate passive baseline run using the AJAX Spider option. The URL count differs from the generic run and should not be treated as a direct measure of security or scan improvement.

| Finding / observation | ZAP risk | Evidence in AJAX baseline | Interpretation |
|---|---|---|---|
| Content Security Policy (CSP) Header Not Set (10038) | Medium | Reported at the root, `/sitemap.xml`, and three `/ftp/*.bak` or configuration-looking paths that returned 403 Forbidden. | Missing header reported; 403 responses do not establish that the files were disclosed. No XSS exploit was demonstrated. Candidate A02 Security Misconfiguration. |
| Cross-Domain Misconfiguration (10098) | Medium | Same warning family persisted. The saved summary records wildcard CORS on root/static resources; the supplied summary does not provide a clean complete per-instance URL list for this run. | Keep as a repeated scanner observation; do not add as a new independent vulnerability without distinct affected behavior. |
| Modern Web Application (10109) | Informational | AJAX-enabled report still classified the client-side JavaScript application as a modern web application. | Informational; the separate direct AJAX Spider API crawl below is the route-discovery evidence. |

### Direct traditional and AJAX Spider API crawls — route discovery, not vulnerability scan

The traditional Spider returned 94 URLs and found no `/api/` paths. The separate AJAX Spider API result returned 91 unique in-scope Juice Shop URLs and included API routes such as `/api/Challenges/`, `/api/Quantitys/`, `/rest/admin/application-configuration`, `/rest/admin/application-version`, `/rest/continue-code`, `/rest/languages`, and `/rest/products/search`. Ten exact URL strings were shared and 81 appeared only in the AJAX result. Socket.IO query parameters inflate raw URL differences, so 81 is not a count of distinct application routes. These crawls discover targets; their URL counts do not confirm vulnerabilities.

### ZAP API Scan — active generated requests against imported API URLs

The API scan imported 16 URLs, reported 53 total URLs, 37 endpoints (all GET), 108 PASS, 0 FAIL, and seven warning types. Unlike the two passive baselines, this run used ZAP active rules and generated requests. It was unauthenticated and did not cover authenticated authorization behavior comprehensively. Its alert counts and evidence are kept separate from the generic and AJAX baseline results above.

| Finding / observation | Count / ZAP risk | Evidence | OWASP classification / interpretation |
|---|---|---|---|
| SQL Injection (40018) | 1 / High by ZAP | Quote probe `q'` to `/rest/products/search?q=q%27` returned HTTP 500. Source review found `req.query.q` interpolated into a raw Sequelize SQL template. No data extraction was attempted. | A05 Injection (Top 10:2025). Source-confirmed unsafe SQL construction; scanner's 500 alone is not proof of successful exploit. Juice Shop labels this an intentional challenge. |
| Server Error response code (100000) | 17 | Visible examples: `/api`, `/api/`, generated numeric path, `/api/Challenges/?name=%00`, `/rest`; supplied excerpt has status only | A10 Mishandling of Exceptional Conditions (Top 10:2025), pending response-body/log review. Aggregate alert count is not 17 confirmed vulnerabilities. |
| Unexpected Content-Type (100001) | 30 | Includes API paths returning HTML or error responses; application root is the SPA shell | A02 Security Misconfiguration, only where an API response is unexpectedly wrong for its contract. Not independently confirmed as a security impact from available excerpts. |
| CSP Header Not Set (10038) | 1 API instance | `/api/Users` returned 401 without CSP | A02 Security Misconfiguration; lower-priority header observation, no exploit demonstrated. |
| Unix timestamp disclosure (10096) | 2 | Configuration response included `1969196030` and `1970691216` | A02 Security Misconfiguration / information disclosure observation. Operational sensitivity not established. |
| Cross-Domain Misconfiguration (10098) | 8 | Includes `/rest/user/whoami`, `/api/Quantitys/`, `/api/Users`, `/rest/languages`, and application-version; wildcard origin shown | A02 Security Misconfiguration. No credentialed cross-origin access to sensitive data demonstrated. |
| Private IP Disclosure (2) | 1 | Configuration response included `192.168.99.100:3000` and `192.168.99.100:4200` | A02 Security Misconfiguration / low-sensitivity information disclosure; reachability and operational sensitivity not established. |

ZAP's 0 FAIL count is the scanner's check status, not a statement that there were no vulnerabilities. The DAST alert excerpts available here aggregate counts and selected evidence; per-instance URL/evidence exports are needed for a fully enumerated alert-instance appendix.

## Combined API assessment — tool-driven and manual results

The separate request-by-request manual test record is in [manual-api-findings.md](manual-api-findings.md). It contains the two confirmed manual findings, selected endpoint observations, ZAP overlap, and limitations of each check.

We used **both methods because they answer different questions**. The ZAP API scan efficiently explored imported endpoints with generated requests and reported patterns such as error responses, headers, and injection signals. It was unauthenticated and did not establish access control between users. Manual checks sent a small number of deliberate requests with controlled accounts/tokens or a chosen `Origin` header, allowing us to verify specific behaviors. Manual checks also overlap with some ZAP endpoints; where they do, both evidence sources are recorded separately below. A result from one method is not assumed to prove the other method's scenario.

| ID | Finding / result | ZAP API scan evidence | Manual check evidence | Assessment and OWASP classification |
|---|---|---|---|---|
| API-01 | Broken object-level authorization on baskets (BOLA/IDOR) | The imported API scan was unauthenticated and did not exercise two authenticated users against each other's basket IDs. No ZAP confirmation for BOLA is recorded. | Two test accounts each read the other's basket by changing the ID; both cross-account requests returned HTTP 200 and the other basket ID. Read-only; no basket contents or mutations were tested. | **Confirmed in lab; Critical initial matrix rating, High confidence.** OWASP Top 10:2025 A01 Broken Access Control; OWASP API Top 10:2023 API1 BOLA. |
| API-02 | Unsigned JWT accepted | The API scan was unauthenticated and did not submit a crafted unsigned JWT. No ZAP confirmation for token validation is recorded. | An unsigned `alg: none` token was accepted by `GET /rest/basket/6`, returning HTTP 200 and basket ID 6. Broader actions were not assessed. | **Confirmed in lab; Critical initial matrix rating, High confidence.** OWASP Top 10:2025 A07 Authentication Failures; OWASP API Top 10:2023 API2 Broken Authentication. |
| API-03 | Unsafe SQL construction in product search | ZAP reported one High SQL Injection alert for `/rest/products/search?q=q%27`; quote probe `q'` returned HTTP 500. | Manual normal search `q=apple` returned HTTP 200. A manually selected quote input was attempted but timed out from the tester, so that manual request did not provide a result. Source review independently found `req.query.q` interpolated into a raw Sequelize SQL template. No data extraction was attempted. | **Unsafe construction confirmed in source; High initial matrix rating; exploit effect not demonstrated.** ZAP's 500 is a signal, not proof of extraction. OWASP Top 10:2025 A05 Injection. API Top 10:2023 has no dedicated injection category; API Top 10:2019 included API8 Injection. |
| API-04 | Permissive wildcard CORS on API responses | ZAP reported 8 Cross-Domain Misconfiguration instances, including `/api/Quantitys/`, `/api/Users`, `/rest/languages`, `/rest/user/whoami`, and application-version, with wildcard origin evidence. | A request with `Origin: https://other-origin.example` to the public challenge API returned `Access-Control-Allow-Origin: *`; no `Access-Control-Allow-Credentials` header was present. Other manual requests observed wildcard CORS on selected API responses. | **Policy confirmed; sensitive credentialed cross-origin access not demonstrated.** OWASP Top 10:2025 A02 Security Misconfiguration; OWASP API Top 10:2023 API8 Security Misconfiguration. |
| API-05 | Public configuration includes internal addresses and timestamps | ZAP reported 1 Private IP Disclosure instance and 2 Unix timestamp disclosures on `/rest/admin/application-configuration`. | Anonymous GET returned HTTP 200 and JSON (36,154 bytes). Review found `192.168.99.100:3000`, `192.168.99.100:4200`, and two future Unix timestamps. No common secret/password/token/private-key properties were found; OAuth client ID is not a client secret. | **Low-sensitivity disclosure observed; impact pending service-owner context.** OWASP Top 10:2025 A02 Security Misconfiguration; OWASP API Top 10:2023 API8 is a tentative classification. |
| API-06 | Server errors on malformed/unknown requests | ZAP reported 17 Server Error response-code instances. Visible examples: `/api`, `/api/`, a generated numeric path, `/api/Challenges/?name=%00`, and `/rest`; the supplied excerpt showed status codes only. | No separate manually controlled malformed/unknown-request test result is preserved. | **Scanner signal; no stack trace or sensitive body confirmed.** OWASP Top 10:2025 A10 Mishandling of Exceptional Conditions; API Top 10:2023 API8 is tentative. |
| API-07 | Unexpected API response content type | ZAP reported 30 Unexpected Content-Type instances, including API/generated paths returning HTML or error responses. | No dedicated manual content-type validation was recorded. | **Needs endpoint-contract review; no independent security impact confirmed.** Candidate OWASP Top 10:2025 A02 only if an actual misconfiguration is confirmed. |
| API-08 | Missing CSP on API response | ZAP reported 1 CSP Header Not Set instance on `/api/Users` (401). | No dedicated manual CSP header check is recorded for this endpoint. | **Header observation; no exploit shown.** OWASP Top 10:2025 A02 Security Misconfiguration. |

### Manual API endpoint checks and overlap

| Manually checked request | Manual result | ZAP overlap in recorded API scan | Interpretation |
|---|---|---|---|
| `GET /rest/admin/application-configuration` | Anonymous HTTP 200; body/property review as above | Yes — private IP and timestamp alerts; CORS alert | Used to determine what the response contained and whether values looked secret or operationally sensitive. |
| `GET /rest/admin/application-version` | Anonymous HTTP 200 with `{"version":"20.3.0"}` | Yes — CORS alert | Public version metadata; low-sensitivity fingerprinting observation, not a confirmed authorization flaw. |
| `GET /api/Challenges/?name=Score%20Board` | Anonymous HTTP 200 with challenge catalog metadata | Yes — route appeared in crawl/inventory; recorded CORS detail was also assessed for this endpoint | Public UI data; no credential-like values observed. |
| Challenge API with `Origin: https://other-origin.example` | Wildcard allow-origin; no allow-credentials header | ZAP assessed wildcard CORS on API routes, but the exact cross-origin request was our manual check | Confirms policy behavior for this request; it did not expose authenticated data. |
| `GET /rest/languages` | Anonymous HTTP 200; body not retained | Yes — route listed in ZAP CORS detail | Reachable; sensitivity undetermined because body was not retained. |
| `GET /rest/products/search?q=apple` | Anonymous HTTP 200 | Yes — product search included in API scan, which also generated a quote probe | Normal query behavior checked manually; SQL behavior separately signaled by ZAP and source review. |
| `GET /api/Quantitys/` | Anonymous HTTP 200; 56 inventory records, exact stock quantities and per-user limits | Yes — CORS alert on this route | Business/inventory metadata exposed. No user data, credentials, or secrets observed. Whether this is a defect depends on intended policy. |
| `GET /api/Users` | Anonymous HTTP 401; body discarded | Yes — CORS, CSP, and content-type alert instances | Positive evidence of anonymous access denial for this route; does not establish authenticated object-level authorization. |
| `GET /api/Users` / `GET /rest/user/whoami` with valid test-session context | Earlier results show selected identity endpoints were explored, but exact request/response evidence is not preserved here | ZAP included these routes in CORS observations | Retain as scan/route observations only until the exact manual output is available; do not infer a finding from route presence. |
| Two-user basket read attempts (A reads B and B reads A) | Both returned HTTP 200 with the other basket ID | Not tested by the recorded unauthenticated ZAP API scan | Manual authenticated authorization test; confirms API-01. |
| Basket request with unsigned `alg: none` JWT | HTTP 200 with basket ID 6 | Not tested by the recorded unauthenticated ZAP API scan | Manual token-validation test; confirms API-02. |

The manual route checks above overlap with some ZAP endpoints, but the evidence fields are kept distinct. The authenticated two-account and unsigned-token tests are manual-only in this assessment. The ZAP scan's SQL, error, content-type, header, CORS, timestamp, and private-IP observations are tool-driven; manual review added context to selected responses and source code.

### Lab risk matrix and rating rationale

This is a **qualitative lab triage matrix**, not a production risk acceptance or compliance decision. Likelihood means how readily the observed behavior could be reached or abused in the assessed lab; impact means the plausible effect if abused. Confidence records how directly the test evidence supports the finding. In a real service, the service/data owner would confirm business impact, exposure, and deadlines.

| Likelihood \ Impact | Low | Moderate | High |
|---|---|---|---|
| **High** | Medium | High | Critical |
| **Medium** | Low | Medium | High |
| **Low** | Low | Low | Medium |

| Lab rating | Interpretation |
|---|---|
| Critical | Urgent treatment; credible path to severe impact. Escalate to service owner. |
| High | Prioritize for prompt remediation planning and an accountable owner. |
| Medium | Plan remediation based on exposure and business context; confirm assumptions. |
| Low | Track or accept with owner rationale; reassess if exposure or impact changes. |

| Finding | Likelihood | Impact | Matrix rating | Confidence / reason |
|---|---|---|---|---|
| API-01 Basket BOLA | High | High | **Critical** | High confidence: both directions of cross-account basket reads returned the other basket ID. Lab impact is confirmed; production impact depends on actual basket data and deployment exposure. |
| API-02 Unsigned JWT accepted | High | High | **Critical** | High confidence: unsigned token was accepted for an authenticated basket request. Broader impersonation impact was not tested, so service owner should validate impact outside the lab. |
| API-03 SQL injection construction | Medium | High | **High** | High confidence in unsafe source construction; runtime data access or alteration was not demonstrated. ZAP's HTTP 500 alone does not prove exploit success. |
| API-04 Wildcard CORS | Medium | Low | **Medium** | High confidence that wildcard headers were returned; sensitive credentialed cross-origin access was not demonstrated. |
| API-05 Configuration metadata | Medium | Low | **Low** | High confidence that IPs/timestamps appeared; sensitivity, freshness, and reachability are unconfirmed. |
| API-06 Malformed/unknown request errors | Medium | Low | **Low** | Medium confidence in aggregate 500 responses; no sensitive body or stack trace evidence was supplied. |
| API-07 Unexpected content types | Medium | Low | **Low** | Medium confidence in scanner alert count; endpoint-specific contract violations and security impact need review. |
| API-08 Missing CSP on API error response | Medium | Low | **Low** | High confidence header was absent on the observed 401; exploit impact was not demonstrated and this is lower priority for a JSON API response. |

These ratings are initial prioritization aids for the lab. The full severity should be revisited if the target is internet-facing, contains real personal or financial data, or is deployed with different authentication, network, or browser policies.

## Summary and completeness status

This report combines tool-driven and manual API assessment results and labels which method supplied each item of evidence. It includes all **87 SCA** and **306 SAST** individual records in linked appendices. In this report, **scanner severity** is the rating supplied by Snyk or ZAP; **initial lab risk rating** is our likelihood/impact assessment using the matrix above. These ratings can differ. ZAP findings are recorded at the level preserved in the pasted report: alert types, counts, and visible endpoint/evidence examples. A structured per-instance ZAP export would allow the 17 server errors, 30 content-type observations, and systemic CORS instances to be enumerated and deduplicated by URL. Confirmed vulnerabilities remain distinct from scanner signals and public-data observations.
