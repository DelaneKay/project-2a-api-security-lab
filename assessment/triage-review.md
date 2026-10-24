# Project 2A — Initial Finding Triage

**Date:** 2026-10-24  
**Purpose:** First-pass technical triage of the recorded SCA, SAST, DAST, and manual API findings. This is a lab assessment, not a production service-owner risk decision.

## Triage approach

Scanner severity is a prioritization signal. This review considers whether a result is confirmed, whether the source path is test-only or an application dependency, whether the behavior is an intentional Juice Shop challenge, and whether the affected dependency is likely shipped at runtime or used only in build/test tooling. The scan used the deliberately vulnerable Juice Shop project; route and frontend findings can be intentional challenge implementations. “Candidate” means review before disposition, not confirmed production exposure.

No real service owner, business data classification, production deployment context, or remediation deadline is identified in the lab evidence. Therefore the proposed technical owner groups are retained, while named ownership, due dates, and risk acceptance remain for a service owner to decide. The detailed 393-row SCA/SAST triage is recorded in [risk-register-sca-sast.csv](risk-register-sca-sast.csv).

## Highest-priority API findings

| Finding | Triage decision | Why / remaining action | Ticket |
|---|---|---|---|
| Basket BOLA | **Confirmed lab issue; Critical initial lab rating.** Retain as a priority API finding. | Two test accounts read each other's baskets. This is direct authorization evidence, though the test did not inspect basket contents or perform mutations. The application's developers own the code fix; service owner sets deadline and accepts residual risk. | [Issue #1](https://github.com/DelaneKay/project-2a-api-security-lab/issues/1) |
| Unsigned JWT accepted | **Confirmed lab issue; Critical initial lab rating.** Retain as a priority API finding. | An unsigned `alg: none` token was accepted on a protected basket request. Broader impersonation impact was not tested. The identity/API team owns the code fix; service owner sets deadline and accepts residual risk. | [Issue #2](https://github.com/DelaneKay/project-2a-api-security-lab/issues/2) |
| Product-search SQL construction | **High-priority source-confirmed weakness; exploit effect unconfirmed.** | Source review found raw SQL interpolation and ZAP's quote probe received HTTP 500. No extraction was attempted; the manual quote request timed out. Developers should validate and fix in a separate remediation exercise. | [Issue #3](https://github.com/DelaneKay/project-2a-api-security-lab/issues/3) |
| Wildcard CORS | **Policy confirmed; impact limited in evidence.** | Public responses allow wildcard origins, but no authenticated sensitive cross-origin read was demonstrated. Keep as P2/Medium candidate pending intended-origin and data-owner review. | [Issue #4](https://github.com/DelaneKay/project-2a-api-security-lab/issues/4) |
| Public configuration metadata | **Low/informational pending owner context.** | Internal IPs and timestamps were present; no secret was found and reachability/sensitivity are unknown. Confirm frontend need and whether values are current. | [Issue #5](https://github.com/DelaneKay/project-2a-api-security-lab/issues/5) |
| Malformed-request server errors | **Low/observe; scanner signal, not confirmed disclosure.** | ZAP counted 17 HTTP 500 responses, but the preserved evidence contains statuses and examples only, not sensitive bodies or stack traces. Review representative server logs/responses before raising priority. | [Issue #6](https://github.com/DelaneKay/project-2a-api-security-lab/issues/6) |

ZAP's unauthenticated API scan did not reproduce the BOLA or unsigned-token cases. These remain manual-only findings. The SQL alert was tool-generated, while source review confirmed unsafe query construction. CORS and configuration alerts overlap with manual checks; the report keeps each method's evidence separate.

## SAST triage

- Snyk Code reported **26 High** issues. All 26 are in application-source paths; **23** are in route, frontend, or library paths and remain high-priority source-review candidates. **Three** are under `data/static/codefixes/` and appear to be challenge/code-fix examples; confirm whether they are executable or shipped before treating them as runtime exposure.
- There are **no High SAST records in `test/` paths** in the pasted results.
- **240 Low** SAST records are in `test/` paths. Exclude these from the application's runtime vulnerability backlog unless a test fixture contains a real credential, reaches a production service, or is included in a shipped artifact. Retain a test-code hygiene action if appropriate.
- The remaining **33 Medium/Low application-source records** and **seven additional Medium/Low records outside test/application-source paths** should be reviewed after the High source findings, with duplicate alert correlation and challenge-context review.
- The product-search SQL issue is already tied to API-03 and GitHub issue #3. Avoid opening a duplicate ticket for the same route/source flaw.

## SCA triage

Snyk Open Source reported **2 Critical and 36 High advisory/path entries**. The command used `--dev`, so development and build dependencies were included. An advisory's package severity does not by itself establish that a vulnerable package is reachable in the shipped service.

| SCA entries | Triage decision | Evidence and next decision |
|---|---|---|
| Critical `marsdb@0.6.11` — arbitrary code injection | **Urgent validation candidate** | The pasted output lists the package as a direct introduced dependency. Confirm whether production application code imports/uses it and whether the affected feature is reachable; verify the applicable fixed version from the advisory. |
| Critical `decompress@4.2.1` — directory traversal | **Urgent validation candidate** | The recorded chain is `download@8.0.0 > decompress@4.2.1`. Confirm the parent dependency, whether it is runtime or tooling, and whether untrusted archives reach it. |
| High legacy `express-jwt` / `jsonwebtoken` / `jws` authentication and signature advisories | **High; correlate with API-02** | The dependency paths include the legacy `express-jwt` and `jsonwebtoken` chain. The live unsigned-token check independently confirmed a JWT validation weakness in the lab. Deduplicate repeated advisory/path rows and align dependency remediation with the API fix. |
| High `lodash` advisories introduced by `sanitize-html` | **High runtime candidate; validate use** | Multiple advisory entries share the same old lodash dependency path. Confirm whether the sanitizer and transitive lodash are used in deployed code, then group duplicate advisories by package and upgrade path. |
| Other High entries (including build, native-install, and transitive packages) | **High scanner severity; dependency-path review before production priority** | The triage CSV flags likely tooling/build chains separately where the dependency path suggests them. Confirm the manifest section, package inclusion in the shipped image, and reachable use. Keep CI/build supply-chain exposure in scope even if a package is absent at runtime. |

The SCA run was based on a locally resolved dependency tree after installation because the checkout initially lacked a lockfile. It is not an exact SBOM of the container image. Compare against the actual built image and reviewed lockfile before making release decisions.

## DAST triage

Use [dast-individual-findings.md](dast-individual-findings.md) for scanner severity, run scope, alert counts, and the exact URLs preserved in the pasted reports. Keep the alert interpretations conservative:

- The SQL alert is elevated because source review corroborated unsafe SQL construction, but exploitation was not demonstrated.
- The 17 server errors and 30 content-type alerts remain scanner signals until individual responses and API contracts are reviewed.
- CSP, wildcard CORS, IP, and timestamp observations are recorded with the run and endpoint context; repeated alerts across generic, AJAX, and API runs should be deduplicated by underlying policy/response behavior.
- Traditional/AJAX Spider URL counts are discovery coverage, not vulnerability counts.

## Ownership and status

The six GitHub issues are actionable drafts for the development/identity teams, not evidence that fixes have been performed. In this assessment they remain open. A real service owner must name a responsible team/person, set a due date, determine business impact, and record any accepted residual risk. Developers own source remediation; DevSecOps supports prioritization, safe test criteria, pipeline controls, and independent verification when a remediation build exists.
