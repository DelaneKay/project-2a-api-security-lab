# OWASP ZAP — Individual DAST Findings and Observations

**Target:** OWASP Juice Shop v20.3.0 training lab  
**Assessment date:** 2026-10-24  
**Interpretation:** “Scanner severity” below is ZAP's assigned risk level. It is not the final lab risk rating. Alert instances may repeat the same underlying condition across URLs or scan runs. Passive alerts are observations; active scan alerts used generated requests and require validation.

## Generic ZAP baseline — passive scan

**Run result:** 116 URLs crawled; 0 FAIL; 3 warning types; 58 PASS. The pasted generic baseline report identifies 93 total endpoints and 100% GET. This run did not use active attack rules.

| DAST ID | Alert | Scanner severity | Affected URL(s) shown in report | Evidence / interpretation | OWASP classification |
|---|---|---|---|---|---|
| ZAP-GEN-01 | Content Security Policy (CSP) Header Not Set (plugin 10038) | Medium | `http://host.docker.internal:3000`; `/`; `/ftp`; `/ftp/coupons_2013.md.bak`; `/sitemap.xml` | CSP header absent on five listed responses. No XSS exploit was shown. | Top 10:2025 A02 Security Misconfiguration (candidate mapping). |
| ZAP-GEN-02 | Cross-Domain Misconfiguration (plugin 10098) | Medium | `/`; `/assets/public/favicon_js.ico`; `/robots.txt`; `/rolldown-runtime-BoHGiXSq.js`; `/styles.css` | `Access-Control-Allow-Origin: *` observed on five listed GET responses. These are root/static resources; no authenticated sensitive response was demonstrated. | Top 10:2025 A02 Security Misconfiguration (candidate mapping). |
| ZAP-GEN-03 | Modern Web Application (plugin 10109) | Informational | `http://host.docker.internal:3000`; `/`; `/juice-shop/build/routes/fileServer.js:52:13`; `/juice-shop/build/routes/fileServer.js:68:18`; `/sitemap.xml` | JavaScript was present while the traditional spider found no links. This is a crawler classification, not a vulnerability. | Informational; no OWASP vulnerability classification. |

## AJAX-enabled ZAP baseline — passive scan with AJAX Spider

**Run result:** 35 URLs; 0 FAIL; 3 warning types; 58 PASS. This was a separate baseline run. Its URL count is not directly comparable to the 116-URL generic baseline as a security score.

| DAST ID | Alert | Scanner severity | Affected URL(s) preserved | Evidence / interpretation | OWASP classification |
|---|---|---|---|---|---|
| ZAP-AJAX-01 | Content Security Policy (CSP) Header Not Set (plugin 10038) | Medium | Root; `/sitemap.xml`; three `/ftp/*.bak` or configuration-looking paths | The three `/ftp` responses returned 403 Forbidden. The supplied AJAX summary does not preserve every exact path; the 403s do not show file disclosure. | Top 10:2025 A02 Security Misconfiguration (candidate mapping). |
| ZAP-AJAX-02 | Cross-Domain Misconfiguration (plugin 10098) | Medium | Systemic alert; per-URL list not preserved in the AJAX summary | Wildcard CORS alert repeated in this run. Do not count it as a new underlying weakness where it is the same policy observed in the generic or API run. | Top 10:2025 A02 Security Misconfiguration (candidate mapping). |
| ZAP-AJAX-03 | Modern Web Application (plugin 10109) | Informational | Application root / client-side application | Informational classifier; not a vulnerability. The direct AJAX Spider crawl below is the route discovery output. | Informational; no OWASP vulnerability classification. |

## Direct traditional and AJAX Spider crawls — route discovery only

| DAST ID | Run | Result | Security finding? |
|---|---|---|---|
| ZAP-SPIDER-01 | Traditional Spider | 94 URLs; no `/api/` paths found | No vulnerability alert from URL discovery alone. |
| ZAP-SPIDER-02 | AJAX Spider API crawl | 91 unique in-scope Juice Shop URLs, including `/api/Challenges/`, `/api/Quantitys/`, `/rest/admin/application-configuration`, `/rest/admin/application-version`, `/rest/continue-code`, `/rest/languages`, and `/rest/products/search` | Route discovery only. Ten exact URL strings were shared with the traditional result; 81 raw URL strings appeared only in AJAX results. Socket.IO query values inflate the difference, so this is not 81 distinct routes or vulnerabilities. |

## ZAP API Scan — active generated requests against imported API URLs

**Run result:** 16 imported URLs; 53 total URLs; 37 endpoints, all GET; 108 PASS; 0 FAIL; 7 warning alert types plus one informational alert type. ZAP also reported 17% slow responses. The scan was unauthenticated. It did not perform the two-account basket comparison or submit an unsigned JWT.

| DAST ID | Alert | Scanner severity | Count | Affected URL(s) or evidence preserved | Assessment / OWASP classification |
|---|---|---|---:|---|---|
| ZAP-API-01 | SQL Injection (40018) | High | 1 | `GET /rest/products/search?q=q%27`; attack `q'`; evidence `HTTP/1.1 500 Internal Server Error` | Source review separately confirmed raw SQL interpolation of user input. No data extraction was attempted. Treat the 500 as a signal, not proof of successful exploitation. OWASP Top 10:2025 A05 Injection. |
| ZAP-API-02 | Server Error response code (100000) | Low | 17 | Report examples: `/api/2641664227801395321`; `/rest/1606907803236864983`; `/rest/admin/6722006272142903514`; `/rest/products/332336067431530505`; `/rest/user/6979041481908229358`; HTTP 500 | Scanner-generated or malformed requests produced errors. Only five of 17 URLs are preserved in the pasted console output; no stack trace or sensitive body was shown. Candidate OWASP Top 10:2025 A10 Mishandling of Exceptional Conditions. |
| ZAP-API-03 | Unexpected Content-Type (100001) | Low | 30 | Report examples: `/api/Users` (401); `/1473492561648132443` (200); `/518468616016771490` (200); `/api/2641664227801395321` (500); `/api/Challenges/7989625861820774099` (401); evidence included `text/html` | Only five of 30 instances are preserved in the console output. HTML may be expected for the SPA shell or generic errors; verify API response contracts before treating as a weakness. Candidate A02 only if misconfiguration is confirmed. |
| ZAP-API-04 | Content Security Policy Header Not Set (10038) | Medium | 1 | `/api/Users` (401 Unauthorized) | CSP was absent on this API error response. No exploit was demonstrated. Candidate OWASP Top 10:2025 A02. |
| ZAP-API-05 | Timestamp Disclosure - Unix (10096) | Low | 2 | `/rest/admin/application-configuration` (200), two occurrences | Two Unix timestamps in the anonymous configuration response. Their operational sensitivity was not established. Candidate OWASP Top 10:2025 A02. |
| ZAP-API-06 | Cross-Domain Misconfiguration (10098) | Medium | 8 (systemic in summary) | Report examples: `/rest/user/whoami` (200); `/api/Quantitys/` (200); `/api/Users` (401); `/rest/languages` (200); `/rest/admin/application-version` (200). Evidence: `Access-Control-Allow-Origin: *` | Five listed examples of eight observations. Manual cross-origin test also confirmed wildcard CORS on public challenge metadata, without `Access-Control-Allow-Credentials`. Sensitive credentialed data access was not demonstrated. Candidate OWASP Top 10:2025 A02. |
| ZAP-API-07 | Private IP Disclosure (plugin 2) | Low | 1 | `/rest/admin/application-configuration` (200); evidence included `192.168.99.100:3000` and `192.168.99.100:4200` | Private network addresses were returned in public configuration. Reachability and sensitivity are unknown. Candidate OWASP Top 10:2025 A02. |
| ZAP-API-08 | Client Error response code returned by server | Informational | 5 | Five informational client-error responses were counted; per-instance URLs were not preserved in the supplied summary. | Informational status-code observation, not by itself a vulnerability. Review only if an unexpected client error affects an API contract or exposes information. |

## Cross-run interpretation

- The generic and AJAX passive baselines share alert families. Their repeated CSP, CORS, and modern-application alerts should not be counted as independent defects without a distinct affected behavior.
- The API scan used active generated requests and found additional API-focused signals. Its SQL, server-error, and content-type results are not the same evidence as passive header observations.
- Manual checks added evidence the unauthenticated ZAP API scan did not establish: cross-account basket access and acceptance of an unsigned JWT. These remain separate manual findings in the main assessment report.
- Where only an aggregate count and a subset of URLs were pasted, the table labels the examples and count explicitly. The missing instances must not be fabricated.
