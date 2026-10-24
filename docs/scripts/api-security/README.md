# API security helper scripts

These scripts preserve the small Python checks and report parsers used during the Project 2A API assessment. The ZAP HTML parsers read an existing report; the request scripts send only the requests described in their names. Run them only against the isolated OWASP Juice Shop lab.

| Script | Where it runs | Purpose |
| --- | --- | --- |
| `juice-shop-api-readonly.yaml` | WSL / ZAP container | The eight GET routes used for the documented API scan; `/rest/continue-code` was left out because it could expose challenge state. |
| `inspect_zap_api_alerts.py` | WSL | Print excerpts for SQL injection, CORS, private-IP, timestamp, and content-type alert text from the ZAP API HTML report. |
| `extract_zap_server_errors.py` | WSL | Inspect bounded snippets around server-error response entries in that report. |
| `compare_spider_url_lists.py` | WSL | Compare the saved traditional and AJAX Spider URL lists, including exact URL overlap and API path counts. |
| `inspect_application_configuration.py` | WSL | List configuration property paths and flag secret-like key names while omitting values. |
| `compare_product_search_responses.py` | WSL, with the port-3001 tunnel open | Compare status and response metadata for normal and single-quote product searches; it does not print response bodies. |
| `check_two_account_bola.py` | Target server, with the container reachable | Log in to two lab accounts and compare own-basket and cross-account basket IDs. |
| `check_unsigned_jwt.py` | Target server, with the container reachable | Log in to a lab account and send a read-only basket request with an unsigned JWT. |

The scripts prompt for account credentials without echoing them. They do not print tokens or basket contents. Their terminal output should still be reviewed alongside the assessment evidence and stated test limits.
