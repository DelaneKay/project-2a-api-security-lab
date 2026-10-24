# My Project 2A SCA, SAST and DAST Scanning: Application and API Security Assessment Journey

- **Core technologies:** Ubuntu in WSL, a hardened Ubuntu admin node, a hardened Ubuntu target node, Docker, OWASP Juice Shop, Snyk Open Source, Snyk Code, and OWASP ZAP.
- **Problem addressed:** I needed to assess an intentionally vulnerable web application across its dependencies, source code, web behavior, and API authorization, then record findings for the teams responsible for remediation.
- **Outcome:** I completed SCA and SAST scans, used ZAP baseline and AJAX Spider scans for DAST, and assessed API security with ZAP API Scan plus targeted manual checks. I documented individual findings, triage, and remediation ownership in this repository. I did not modify Juice Shop or remediate the findings; the next action belongs to the development/service owners.

I started this project with the same WSL workstation and hardened servers I had used for Project 1A Linux Server Hardening. I wanted to see what security issues I could find in the Juice Shop source and running application, then prepare clear evidence for the teams who would fix them. I installed Juice Shop on the target, ran ZAP baseline and AJAX scans, then cloned the source for SAST and SCA. After the original SSH tunnel became unreliable, I restored access and completed the API assessment with ZAP and two test accounts. I record the problems I hit along the way because getting the test setup right was part of the work.

## The lab scenario

I continued the lab from Project 1A Linux Server Hardening, reusing its three-node layout: my Windows workstation running Ubuntu in WSL, the admin node, and the target node. I checked the current host and network state as I added application security testing; I did not assume that every earlier setting was still active.

I used the previously hardened Ubuntu target node to host **OWASP Juice Shop**, a deliberately vulnerable web application built for security training. I ran the application in a Docker container, which kept its process and packages in a separate container environment while the Project 1A Linux Server Hardening controls remained on the host. I published the web port on the target's private lab interface and reached it through the lab network and SSH forwarding path. That kept the training application inside the lab network while giving me a running target for web and API assessment. Juice Shop's vulnerabilities are intentional; I used them to practise finding, validating, classifying, and handing off issues.

I documented the assessment in four parts. The sections below follow the order I carried out the tests:

1. **DAST — Dynamic Application Security Testing:** assess the running application over HTTP with ZAP baseline and AJAX Spider scans.
2. **SAST — Static Application Security Testing:** a **white-box** assessment because I had access to Juice Shop's source code. Snyk Code inspected source paths and code patterns without executing those paths in the running service. In this lab, that let me connect alerts to files and lines and review whether a pattern belonged to application code, tests, or an intentional training challenge.
3. **SCA — Software Composition Analysis:** identify known vulnerabilities in direct and transitive dependencies.
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
| [1. Docker and target application](#1-install-docker-and-start-juice-shop) | Install Docker offline → verify the target → load and start Juice Shop. |
| [2. DAST](#2-dast--dynamic-application-security-testing) | Run ZAP baseline and AJAX scans against the running target; record crawl issues and coverage. |
| [3. SAST](#3-sast--static-application-security-testing) | Clone the matching source → prepare and authenticate Snyk → run Snyk Code → preserve source findings. |
| [4. SCA](#4-sca--software-composition-analysis) | Resolve dependencies in WSL → run Snyk Open Source → preserve advisories and dependency paths. |
| [5. API Security](#5-api-security) | Run ZAP API Scan → combine tool evidence with bounded two-account, token, and response checks. |
| [6. Assessment handoff](#6-assessment-handoff) | Consolidate findings → triage → create developer issues → leave remediation to owners. |

**Starting point:** The servers had been hardened in Project 1A Linux Server Hardening. The first task was to install Docker on the isolated target and start Juice Shop. I cloned the matching source release into WSL later, when I prepared the SAST and SCA scans. I used the lab accounts and SSH access already established for this environment; I did not include private keys or account passwords in this repository.

## 1. Install Docker and start Juice Shop

### 1.1 I prepared the cached image in WSL and installed Docker on the isolated target

I first checked Docker on my WSL workstation before installing it on the target. The Docker CLI was present, but my `devsecops` account could not access `/var/run/docker.sock`. I checked the active context and socket permissions, then added my WSL account to the `docker` group. Membership gives me root-level control over WSL, so I made this access change deliberately. I closed and reopened the shell so the new group membership would take effect:

```bash
# WSL workstation
docker context ls
ls -l /var/run/docker.sock
sudo usermod -aG docker devsecops
# I closed and reopened the WSL shell before running these checks.
id
docker info
```

The `default` context pointed to `/var/run/docker.sock`. After reopening the shell, I confirmed that `id` listed the `docker` group and `docker info` could reach the Docker Desktop engine. I checked the running containers before using Docker, then looked for a Juice Shop image already cached in WSL:

```bash
# WSL workstation
docker ps
docker image ls
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' bkimminich/juice-shop:latest
```

I found two running containers for `learn-to-cloud-app`. Their ports were bound to loopback, so they did not conflict with this lab and I left them running. I also found `bkimminich/juice-shop:latest` in the WSL image store and recorded its image ID and repository digest. WSL's Docker Desktop engine and the target's Docker engine were separate, so I still needed to install Docker on the target and transfer the cached image there.

Docker was not installed on the target, and the target had no internet route for downloading packages. I prepared the Ubuntu packages in WSL, sent them through the admin node, and checked their checksums at each stage.

Before I installed Docker, I checked the target's free disk space and Ubuntu release, then reviewed the available Docker package and APT's proposed install plan. I ran these commands on the **target server**, connecting from WSL through the admin node:

```bash
# Target server
df -h /
cat /etc/os-release
apt-cache policy docker.io
apt-get -s install docker.io
```

I confirmed that the target ran Ubuntu 26.04.1. Its package index offered `docker.io` version `29.1.3-0ubuntu4.1`, and the simulated install would add eight packages without removing any. I refreshed WSL's package list and checked the candidate version there too:

```bash
# WSL workstation
sudo apt-get update
apt-cache policy docker.io
apt-get -s install docker.io
```

The WSL simulation listed more packages because WSL and the target already had different dependencies installed. I used the target's package plan to identify what I needed to transfer.

APT downloaded `docker.io`, `containerd`, and `runc`, but skipped five dependencies that were already present in WSL. I downloaded those five packages separately, then gathered all eight packages needed by the target:

```bash
# WSL workstation
sudo apt-get --download-only --no-install-recommends install docker.io
ls -lh /var/cache/apt/archives/*.deb
sudo apt-get --download-only --reinstall --no-install-recommends install bridge-utils dns-root-data dnsmasq-base pigz ubuntu-fan
ls -lh /var/cache/apt/archives/*.deb

mkdir -p ~/project-2a/staging/docker-packages
cp /var/cache/apt/archives/{bridge-utils_1.7.1-4ubuntu3_amd64.deb,containerd_2.2.2-0ubuntu1.2_amd64.deb,dns-root-data_2025080400build1_all.deb,dnsmasq-base_2.92-1ubuntu0.5_amd64.deb,docker.io_29.1.3-0ubuntu4.1_amd64.deb,pigz_2.8-1build1_amd64.deb,runc_1.4.0-0ubuntu1_amd64.deb,ubuntu-fan_0.12.17_all.deb} ~/project-2a/staging/docker-packages/
ls -lh ~/project-2a/staging/docker-packages
cd ~/project-2a/staging/docker-packages
sha256sum *.deb > SHA256SUMS
sha256sum -c SHA256SUMS
```

The eight package files totalled about **71 MB**. I created a SHA-256 manifest in WSL and verified the files before transferring them. Then I created a staging folder on the **admin node**:

```bash
# Admin node
mkdir -p ~/project-2a/staging/docker-packages
```

I copied the manifest and package files from **WSL** into that folder:

```bash
# WSL workstation
scp -i ~/.ssh/mds_admin_ed25519 SHA256SUMS *.deb mdsadmin@192.168.56.101:~/project-2a/staging/docker-packages/
```

On the **admin node**, I verified the transferred files against the manifest:

```bash
# Admin node
cd ~/project-2a/staging/docker-packages
sha256sum -c SHA256SUMS
```

I confirmed all eight package files reported `OK` on the admin node.

After the admin node check passed, I created the staging folder on the **target server**:

```bash
# Target server
mkdir -p ~/project-2a/staging/docker-packages
```

I then used the **admin node's** SSH key for the target to copy the package files across:

```bash
# Admin node
scp -i ~/.ssh/mds_target_ed25519 ~/project-2a/staging/docker-packages/* mdsadmin@192.168.77.10:~/project-2a/staging/docker-packages/
```

On the **target server**, I ran the checksum check once more:

```bash
# Target server
cd ~/project-2a/staging/docker-packages
sha256sum -c SHA256SUMS
```

I confirmed all eight packages reported `OK` on the target, so the transfer had not changed them.

My first offline APT attempt failed. On the **target server**, the `--no-download` simulation returned `Unable to fetch some archives` and made no changes. A second simulation using local package paths showed the eight-package plan, but the actual APT install still tried to fetch the packages and failed. I included all three commands to show what I tried and where APT stopped:

```bash
# Target server
cd ~/project-2a/staging/docker-packages
apt-get --no-download -s install ./*.deb

# Target server: simulation using local package paths.
apt-get -s install ./*.deb

# Target server: actual APT attempt, which also failed to fetch archives.
sudo apt-get --no-download install ./*.deb
```

Because the package files were already on the **target server**, I switched to `dpkg` to install them locally:

```bash
# Target server
cd ~/project-2a/staging/docker-packages
sudo dpkg -i ./*.deb
```

The installation completed successfully. I saw the Docker packages unpacked and configured, and systemd create links for the Docker service and socket.

After the install, I checked Docker and the network from the **target server**:

```bash
# Target server
systemctl is-active docker
ip route
```

I confirmed that Docker was `active`. The route table showed the new `172.17.0.0/16` bridge and the lab route `192.168.77.0/24`, with no default route. The target therefore remained isolated from the internet.

### 1.2 I transferred, verified, and started the first Juice Shop container

Since the target had no internet route, I used the `bkimminich/juice-shop:latest` image already stored in WSL. Before transferring it, I recorded its WSL image ID, `sha256:2d370ec1…`, and repository digest. I then saved the image as an archive:

I saved the image and created a checksum file in **WSL**:

```bash
# WSL workstation
docker save --output ~/project-2a/staging/juice-shop.tar bkimminich/juice-shop:latest
cd ~/project-2a/staging
sha256sum juice-shop.tar > juice-shop.tar.sha256
ls -lh juice-shop.tar juice-shop.tar.sha256
```

The archive was about **347 MB**. I copied it and its checksum file from **WSL to the admin node**:

```bash
# WSL workstation
scp -i ~/.ssh/mds_admin_ed25519 juice-shop.tar juice-shop.tar.sha256 mdsadmin@192.168.56.101:~/project-2a/staging/
```

On the **admin node**, I checked the archive against the checksum file:

```bash
# Admin node
cd ~/project-2a/staging
sha256sum -c juice-shop.tar.sha256
```

The check returned `juice-shop.tar: OK`, so I copied the verified archive and checksum file from the **admin node** to the target:

```bash
# Admin node
scp -i ~/.ssh/mds_target_ed25519 ~/project-2a/staging/juice-shop.tar ~/project-2a/staging/juice-shop.tar.sha256 mdsadmin@192.168.77.10:~/project-2a/staging/
```

On the **target server**, I ran the same checksum check:

```bash
# Target server
cd ~/project-2a/staging
sha256sum -c juice-shop.tar.sha256
```

I got `juice-shop.tar: OK` on the target as well, then loaded the verified archive into Docker there:

```bash
# Target server
sudo docker load --input ~/project-2a/staging/juice-shop.tar
```

Docker reported `Loaded image: bkimminich/juice-shop:latest`. At this point, I had loaded the image but had not started the application.

Before starting Juice Shop, I inspected the image on the **target server**. My first attempt from WSL failed because `sudo` needed a terminal. I retried the same inspection command in an interactive target shell, allocating a terminal at both SSH hops so I could respond to the password prompt:

```bash
# Target server
sudo docker image inspect --format '{{.Id}}' bkimminich/juice-shop:latest

# Target server: retry in an interactive target shell.
sudo docker image inspect --format '{{.Id}}' bkimminich/juice-shop:latest
```

The image IDs differed: the target reported `sha256:9a55bcd1…`, while WSL reported `sha256:2d370ec1…`. Before starting the container, I compared the archive manifest, config hash, and image layers to understand the mismatch.

On **WSL**, I checked the archive manifest and hashed its config blob, which matched the WSL image ID. I also corrected my layer-inspection command: I had left the format expression unquoted, so my first result was an error hash rather than a useful fingerprint.

```bash
# WSL workstation
cd ~/project-2a/staging
tar -xOf juice-shop.tar manifest.json
tar -xOf juice-shop.tar blobs/sha256/2d370ec11ab40bc24b3516c042f7317a053c80f668e572538469d1fd7e91d7f8 | sha256sum
docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}} {{json .RepoDigests}}' bkimminich/juice-shop:latest

# WSL workstation: corrected fingerprint of the ordered image layer list.
docker image inspect --format '{{json .RootFS.Layers}}' bkimminich/juice-shop:latest | sha256sum
```

I ran these checks on the **target server** to compare the full image ID, layer list, and platform:

```bash
# Target server
sudo docker image ls --no-trunc bkimminich/juice-shop:latest
sudo docker image inspect --format '{{json .RootFS.Layers}}' bkimminich/juice-shop:latest | sha256sum
sudo docker image inspect --format 'OS={{.Os}} ARCH={{.Architecture}} SIZE={{.Size}}' bkimminich/juice-shop:latest
```

The config blob hashed to `2d370ec1…`, both layer-list checks returned `36fd80fb…`, and the target reported `OS=linux ARCH=amd64`. The image IDs still differed between the two Docker stores, but the verified archive and matching layer lists gave me enough evidence to continue with the lab image.

Once the image checks were complete, I started Juice Shop on the **target server**, bound it to the private lab address, and checked that it was running:

```bash
# Target server
sudo docker run -d --name juice-shop --restart unless-stopped -p 192.168.77.10:3000:3000 bkimminich/juice-shop:latest
sudo docker ps --filter name=juice-shop
```

Docker returned container ID `5440dc6a…`. I confirmed on the **target server** that the container was **Up** and port 3000 was bound to `192.168.77.10`.

I checked the application from the **admin node** with this request; it returned `HTTP 200`:

```bash
# Admin node
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 http://192.168.77.10:3000/
```

I could not reach the target's isolated address directly from Windows, so I opened an SSH tunnel from **WSL** through the admin node and left that terminal running:

```bash
# WSL workstation
ssh -N -L 3000:192.168.77.10:3000 -i ~/.ssh/mds_admin_ed25519 mdsadmin@192.168.56.101
```

I opened Juice Shop in the browser at `http://localhost:3000`. The application was running on the target and reachable through my WSL tunnel. The Docker outage and image recovery happened later in the lab. I began assessing the running application with ZAP in [Section 2](#2-dast--dynamic-application-security-testing).


## 2. DAST — Dynamic Application Security Testing

### 2.1 I ran ZAP baseline and AJAX-enabled baseline scans

I began DAST while Juice Shop was reachable through the original port-3000 tunnel. I pointed ZAP at `http://host.docker.internal:3000`, which let the scanner container reach the application through WSL. ZAP gave me a black-box view: it tested behavior exposed over HTTP without reading the source code. I ran these scans before cloning the source for SAST and SCA. I cover the later API-focused scan in [Section 5](#5-api-security).

#### I prepared ZAP in WSL and checked the tunnel

I chose OWASP ZAP for DAST. Its baseline scan crawls the application and reports passive findings without actively attacking endpoints. I checked whether the ZAP image was already in WSL; it was not, so I pulled it. With the Juice Shop SSH tunnel open in another WSL terminal, I checked that I could reach the application before launching a scan:

```bash
# WSL workstation
docker image ls zaproxy/zap-stable
docker pull zaproxy/zap-stable
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 http://localhost:3000/
```

I pulled the image successfully, and my reachability check returned `HTTP 200`. I then ran ZAP against `http://host.docker.internal:3000`, the address the scanner container used to reach the tunneled service.

#### Commands I ran and the report-permission problem I fixed

My first scan attempt could not save ZAP's automation plan because its container user could not write to the default home directory, `/home/zap`. Running ZAP as my WSL user let it access the report folder, but the home-directory problem remained. I then mounted a separate `zap-home` directory beneath the report mount, but ZAP still could not write `/zap/wrk/home/zap.yaml`. None of those attempts produced the HTML report.

**Initial baseline attempt:**

```bash
# WSL workstation
mkdir -p ~/project-2a/zap-reports
docker run --rm -t \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -r juice-shop-baseline.html
```

**Attempt to run as my WSL user (report permission changed, ZAP home still failed):**

```bash
# WSL workstation
docker run --rm -t -u "$(id -u):$(id -g)" \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -r juice-shop-baseline.html
```

**Attempt with a separate mounted home (ZAP still could not write its plan):**

```bash
# WSL workstation
mkdir -p ~/project-2a/zap-home ~/project-2a/zap-reports
docker run --rm -t \
  -e HOME=/zap/wrk/home \
  -v "$HOME/project-2a/zap-home:/zap/wrk/home:rw" \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -r juice-shop-baseline.html
```

I got the baseline scan working by making the WSL report directory writable and setting ZAP's temporary home to `/tmp`. I used `chmod 777` only on the lab report folder so the container could save its report; I did not change the target's hardening. This run produced my baseline report:

```bash
# WSL workstation
chmod 777 ~/project-2a/zap-reports
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -r juice-shop-baseline.html
```

I recorded **116 URLs**, **0 FAIL alerts**, **3 warning types**, and **58 PASS checks** for this baseline run. The warnings included missing Content Security Policy, cross-domain configuration, and an informational modern-web-application classification.

I ran the AJAX-enabled passive baseline next. My first attempt failed with `Connection refused` because the SSH tunnel was down. After I restored the tunnel and confirmed `HTTP 200`, the scan completed and saved a report containing 35 URLs:

```bash
# WSL workstation
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 http://localhost:3000/
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -j -r juice-shop-ajax.html
```

The AJAX-enabled baseline reported **35 URLs**, **0 FAIL alerts**, **3 warning types**, and **58 PASS checks**. I treated these as baseline results; the later Spider crawl counts appear in Section 2.2.

I checked that the AJAX HTML report existed, then previewed its URL-looking strings:

```bash
# WSL workstation
ls -lh ~/project-2a/zap-reports/juice-shop-ajax.html
grep -o 'http[^"< ]*' ~/project-2a/zap-reports/juice-shop-ajax.html | sort -u | head -n 30
```

I found that the HTML report did not provide a complete URL inventory, so I reran the AJAX-enabled baseline to save JSON as well as HTML. The scan remained passive, and I did not treat its JSON report as a full Spider URL export:

```bash
# WSL workstation
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -j \
  -J juice-shop-ajax.json -r juice-shop-ajax.html
```

I considered `zap-full-scan.py`, but I did not complete that scan. I include only the completed `zap-baseline.py` runs as DAST evidence.

For ZAP to scan through the tunnel, its container had to resolve `host.docker.internal` to WSL and reach forwarded port 3000. When that path failed, I checked scanner-to-target connectivity before treating any output as a scan result. All of my scans targeted the isolated lab instance.

### 2.2 I used the ZAP API to compare the two crawlers

After the baseline scans, I wanted to check whether the traditional Spider had found API routes loaded by JavaScript. I started a temporary ZAP daemon in WSL and queried its Spider API. I retained the daemon command, the traditional Spider calls, and my first failed AJAX request (`inScope=true`), which returned “The starting URI is not in scope.” My retry with `inScope=false` returned an internal error. I later retrieved an AJAX result list containing 91 URLs, but I did not retain the successful scan-start parameters, so I have not attributed that result to an unverified command.

I started ZAP with its API bound to WSL localhost and with API key checks disabled for this temporary lab daemon:

```bash
# WSL workstation
# The API is bound to 127.0.0.1 on the host; do not expose this port to the lab network.
docker run -d --name zap-crawl-api \
  -p 127.0.0.1:8090:8090 \
  -e HOME=/tmp \
  zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 \
  -config api.disablekey=true \
  -config "api.addrs.addr.name=.*" \
  -config api.addrs.addr.regex=true
```

I checked the container, its logs and port mapping, then waited for the API version endpoint to respond:

```bash
# WSL workstation
docker ps --filter name=zap-crawl-api
docker logs --tail 80 zap-crawl-api
docker port zap-crawl-api 8090/tcp
curl -sS http://127.0.0.1:8090/JSON/core/view/version/
```

I started the traditional Spider, checked it until it reached 100%, and retrieved its URL list. My recorded requests used scan ID 0:

```bash
# WSL workstation
curl -sS --get 'http://127.0.0.1:8090/JSON/spider/action/scan/' \
  --data-urlencode 'url=http://host.docker.internal:3000' \
  --data-urlencode 'recurse=true' \
  --data-urlencode 'subtreeOnly=true'
curl -sS --get 'http://127.0.0.1:8090/JSON/spider/view/status/' \
  --data-urlencode 'scanId=0'
curl -sS --get 'http://127.0.0.1:8090/JSON/spider/view/results/' \
  --data-urlencode 'scanId=0' \
  -o ~/project-2a/zap-reports/spider-results.json
```

I got 94 URLs from the traditional crawl, but none had `/api/` paths. My first AJAX request restricted the crawl to ZAP's existing scope. Since I had not added Juice Shop to scope, that attempt did not crawl the site:

```bash
# WSL workstation
curl -sS --get 'http://127.0.0.1:8090/JSON/ajaxSpider/action/scan/' \
  --data-urlencode 'url=http://host.docker.internal:3000' \
  --data-urlencode 'inScope=true' \
  --data-urlencode 'subtreeOnly=true'
curl -sS http://127.0.0.1:8090/JSON/ajaxSpider/view/status/
docker logs --tail 80 zap-crawl-api
```

I saw “The starting URI is not in scope” in the log. I retried with `inScope=false`, but ZAP returned an internal error. I checked the logs and did not count that attempt as a completed crawl:

```bash
# WSL workstation
curl -sS --get 'http://127.0.0.1:8090/JSON/ajaxSpider/action/scan/' \
  --data-urlencode 'url=http://host.docker.internal:3000' \
  --data-urlencode 'inScope=false' \
  --data-urlencode 'subtreeOnly=true'
docker logs --tail 80 zap-crawl-api
```

After the AJAX crawl stopped, I saved its result list. I retained the retrieval commands and the resulting 91-URL list, but not the exact parameters from the successful scan start:

```bash
# WSL workstation
curl -sS http://127.0.0.1:8090/JSON/ajaxSpider/view/status/
curl -sS 'http://127.0.0.1:8090/JSON/ajaxSpider/view/results/' \
  -o ~/project-2a/zap-reports/ajax-spider-results.json
python3 -c 'import json; p="/home/devsecops/project-2a/zap-reports/ajax-spider-results.json"; r=json.load(open(p)).get("results", []); print(f"AJAX Spider URLs: {len(r)}"); print("\n".join(map(str, r[:20])))'
```
I counted the exact URL strings and checked how many paths included `/api/` with a helper that reads both saved Spider result files. Because it compares query strings exactly, changing Socket.IO values can show up as additional entries:

```bash
# WSL workstation; run from the portfolio checkout root.
python3 docs/scripts/api-security/compare_spider_url_lists.py
```
### 2.3 I manually reviewed the API routes found by the AJAX Spider

I found that the AJAX Spider had reached API routes the traditional Spider missed, including `/api/Challenges/` and several `/rest/` endpoints. My saved URL lists contained **91 AJAX URLs, 94 traditional URLs, 10 exact matches, and 81 AJAX-only URL strings**. Some AJAX-only strings differed only because the Socket.IO query values changed, so I did not treat the count as 81 distinct routes. I used the comparison to choose a few read-only API requests for an initial review, after the ZAP crawl and before I cloned the source for SAST.

I started with an unauthenticated `GET` to the application-configuration endpoint. It returned `200 OK`, so I inspected the JSON field names before deciding whether the response exposed anything sensitive:

```bash
# WSL workstation
curl -sS -D - --max-time 10 -o /dev/null http://localhost:3000/rest/admin/application-configuration
```

I recorded the `200 OK` as an observation rather than a confirmed vulnerability. I combined my two configuration-inspection Python snippets into one helper. It prints JSON property paths and common secret-like key names without printing values:

```bash
# WSL workstation; run from the portfolio checkout root.
python3 docs/scripts/api-security/inspect_application_configuration.py
```
I found one top-level property, `config`, and no property names matching the secret-related terms. I then used the helper to list nested configuration paths without printing their values.

I reviewed fields describing frontend configuration, product data, and server settings. One field was a Google OAuth `clientId`, which is an identifier rather than a secret. My name filter was only a first-pass check and could not establish that every value was safe. Based on the property paths and output I reviewed, I treated this as public UI configuration; I did not confirm sensitive-data exposure.

Next, I checked the related application-version endpoint. I first captured its unauthenticated status and headers, then read the small JSON response:

```bash
# WSL workstation
curl -sS -D - --max-time 10 -o /dev/null http://localhost:3000/rest/admin/application-version
curl -sS --max-time 10 http://localhost:3000/rest/admin/application-version
```

I received `{"version":"20.3.0"}` without authentication. I recorded it as low-sensitivity version metadata, not an authorization flaw.

I then requested the discovered Score Board challenge record. This read-only query uses `%20` to encode the space in the challenge name:

```bash
# WSL workstation
curl -sS --max-time 10 'http://localhost:3000/api/Challenges/?name=Score%20Board'
```

I saw challenge catalog fields such as name, category, description, difficulty, and `solved: false`. These fields support the Juice Shop interface, so they did not confirm an API vulnerability. The AJAX results also contained “challenge solved” events for two challenges, but I could not tell from those results alone whether the Spider caused the state changes.

Finally, I checked the response's CORS headers with a test origin. This request did not modify application data:

```bash
# WSL workstation
curl -sS -D - --max-time 10 -o /dev/null \
  -H 'Origin: https://other-origin.example' \
  'http://localhost:3000/api/Challenges/?name=Score%20Board'
```

I recorded these unauthenticated requests as initial triage observations. They gave me a starting point for the later API work. I then moved from live application testing to source analysis in [Section 3](#3-sast--static-application-security-testing). I returned to API-specific testing later in [Section 5](#5-api-security), using ZAP API Scan and authenticated checks to investigate authorization questions.


## 3. SAST — Static Application Security Testing

### 3.1 I cloned the matching Juice Shop source and prepared Snyk

Once I had confirmed Juice Shop was running on the target, I prepared a source checkout in **WSL** for code analysis. The folder was not there yet, so I cloned the official `v20.3.0` release to match the running application. I first checked Git's version, which was `2.53.0`.

```bash
# WSL workstation
git --version
cd ~/project-2a
git clone --depth 1 --branch v20.3.0 https://github.com/juice-shop/juice-shop.git juice-shop-source
```

I installed the Snyk CLI as a user executable in WSL. I found that `/usr/local/bin` was owned by root, so I installed the binary under my home directory instead:

```bash
# WSL workstation
ls -ld /usr/local/bin
mkdir -p "$HOME/.local/bin"
curl -fsSL https://static.snyk.io/cli/latest/snyk-linux -o "$HOME/.local/bin/snyk"
chmod +x "$HOME/.local/bin/snyk"
"$HOME/.local/bin/snyk" --version
```

I confirmed the CLI version was `1.1308.3` and tried to authenticate before scanning. The browser's OAuth callback returned “Not Found,” and the CLI showed that no API credential was set. I checked the available authentication options and switched to token-based authentication. I entered the token at the hidden terminal prompt, so it does not appear here:

```bash
# WSL workstation
"$HOME/.local/bin/snyk" auth
"$HOME/.local/bin/snyk" config get api
"$HOME/.local/bin/snyk" auth --help
"$HOME/.local/bin/snyk" auth --auth-type=token
```

The token-based flow authenticated successfully. With the source checkout ready and Snyk authenticated, I moved on to the Snyk Code scan.

### 3.2 I ran Snyk Code against the source

I performed SAST as a **white-box** assessment because Snyk Code analyzed the source checkout. My first attempt reported that Snyk Code was disabled for the selected organization, so it produced no findings. I enabled the feature in the Snyk web console, then reran the command from the repository. Enabling the feature was a console action, not a shell command.

**First attempt (feature disabled; no scan findings were produced):**

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
"$HOME/.local/bin/snyk" code test
```

**Rerun after enabling Snyk Code:**

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
"$HOME/.local/bin/snyk" code test
```
Snyk Code returned **306 findings**: **26 High**, **11 Medium**, and **269 Low**. I found **240** of the Low records in `test/` paths. I preserved every record in [sast-individual-findings.md](sast-individual-findings.md), then considered file path and challenge context during triage. Because Juice Shop includes intentionally vulnerable training examples, I reviewed each result before treating it as a production defect.

**Checkpoint:** Snyk Code gave me source-level findings and file paths, but it did not show that every finding was reachable or exploitable in a deployed service. With the source review complete, I moved to dependency risk in [Section 4](#4-sca--software-composition-analysis).

## 4. SCA — Software Composition Analysis

### 4.1 I tried Snyk Open Source and checked the missing prerequisites

After SAST, I moved on to SCA. I used Snyk Open Source to compare the project's dependencies with known advisories. Although Juice Shop was running on the target, I ran this scan in **WSL** against the source checkout and its local dependency tree; it did not send requests to the container. I had already completed the initial DAST scans against the live target. I returned to the API assessment later, after restoring a working tunnel.

I first tried to scan the source dependencies, but Snyk could not produce a result: the checkout had no supported lockfile and no installed `node_modules` directory:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
"$HOME/.local/bin/snyk" test
```

I got `SNYK-CLI-0000` with the message **“Missing node_modules folder: we can't test without dependencies. Please run 'npm install' first.”** I checked the manifest and searched for lockfiles. The checkout contained `package.json`, but no `package-lock.json`, npm shrinkwrap, or Yarn lockfile:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
ls -l package.json package-lock.json
find . -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock
```

My first Node.js and npm checks in WSL returned `command not found`. I tried Ubuntu's npm package suggestion, then followed the Node.js 22 setup steps for the Juice Shop `v20.3.0` source. I did not retain the full package installation output, so I include the commands and the later successful scan without reconstructing logs I no longer have:

```bash
# WSL workstation
node --version
npm --version
sudo apt install npm
sudo apt update
sudo apt install -y curl
curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh
sudo -E bash nodesource_setup.sh
sudo apt install -y nodejs
node --version
npm --version
```

### 4.2 I installed dependencies without running package scripts and rescanned

Once Node.js and npm were available, I installed the Juice Shop dependencies without running package lifecycle scripts. This gave Snyk the local dependency tree it needed while avoiding the project's `postinstall` build script during my assessment:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
npm install --ignore-scripts
```

I did not retain the full `npm install` output. After the command completed, I reran Snyk with development dependencies included:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
"$HOME/.local/bin/snyk" test --dev
```

Snyk reported **87 advisory/path entries**: **2 Critical, 36 High, 47 Medium, and 2 Low**. I saw an upgrade recommendation for `@cyclonedx/cyclonedx-npm@4.2.1` alongside advisories in direct and transitive dependencies. I preserved every reported entry and dependency path in [sca-individual-findings.md](sca-individual-findings.md), with the SCA triage rows in [risk-register-sca-sast.csv](risk-register-sca-sast.csv).

I flagged two Critical entries for prompt owner review: arbitrary code injection associated with directly introduced `marsdb@0.6.11`, and directory traversal in `decompress@4.2.1`, reached through `download@8.0.0`. I also found High entries involving legacy JWT packages, lodash, and transitive or build dependencies. I treated these dependency paths as triage evidence; severity alone does not show whether the vulnerable code is reachable in the deployed service.

**Scope limit:** The checkout had no committed lockfile, so npm resolved a local dependency tree for my scan. I could not claim that its selected versions exactly matched the prebuilt image on the target. I recorded the recommendations for the development team and left Juice Shop's dependencies unchanged.

**Checkpoint:** SCA identified known advisories in the local dependency tree, but it did not establish runtime reachability, prove exploitability, or verify a fix. I had now assessed the application source and dependencies. Next, I returned to the running service to assess API-specific behavior in [Section 5](#5-api-security).

## 5. API Security

I combined ZAP API Scan with a small number of manual checks. ZAP discovered routes and sent generated requests across the API definition I imported. I then used two lab accounts to answer questions the unauthenticated scan could not answer: could one user read another user's basket, and would the application accept an unsigned token? I kept the manual checks read-only.

### 5.1 I ran the ZAP API Scan and established the API surface

I used the AJAX Spider results to select routes for the API Scan, including challenge and quantity endpoints, product search, languages, application version and configuration, and user-related routes. I ran the API Scan without authentication against the imported definition, and ZAP added scanner-generated requests. I recorded its counts and alert summary after the scan command.

I configured ZAP API Scan with an OpenAPI definition containing **eight GET-only routes** from the AJAX results. I left `/rest/continue-code` out because it could expose challenge state. The definition and scan command are below. I also saved a copy as [`juice-shop-api-readonly.yaml`](scripts/api-security/juice-shop-api-readonly.yaml) in the helper folder for reuse.

```bash
# WSL workstation; the Juice Shop SSH tunnel on port 3001 stays open in another terminal.
cat > ~/project-2a/zap-reports/juice-shop-api-readonly.yaml <<'EOF'
openapi: 3.0.0
info:
  title: Juice Shop Read-only API Assessment
  version: 1.0.0
servers:
  - url: http://host.docker.internal:3001
paths:
  /api/Challenges/:
    get:
      parameters:
        - name: name
          in: query
          required: false
          schema:
            type: string
      responses:
        '200':
          description: Challenge data
  /api/Quantitys/:
    get:
      responses:
        '200':
          description: Product quantity data
  /api/Users:
    get:
      responses:
        '200':
          description: User list
  /rest/admin/application-configuration:
    get:
      responses:
        '200':
          description: Application configuration
  /rest/admin/application-version:
    get:
      responses:
        '200':
          description: Application version
  /rest/languages:
    get:
      responses:
        '200':
          description: Available languages
  /rest/products/search:
    get:
      parameters:
        - name: q
          in: query
          required: false
          schema:
            type: string
      responses:
        '200':
          description: Product search results
  /rest/user/whoami:
    get:
      responses:
        '200':
          description: Current caller identity
EOF
```

I ran ZAP API Scan against that definition and saved the HTML report. ZAP sent active test probes to the listed GET routes. Since I left the order-creation `POST` route out of the definition, the scan did not intentionally submit an order:

```bash
# WSL workstation
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-api-scan.py -t /zap/wrk/juice-shop-api-readonly.yaml -f openapi -r juice-shop-api-active.html
```

Because I ran the API Scan without credentials, it could not test the two-account authorization case I describe below. With the eight-route definition, I got a report showing **16 imported URLs**, **53 total URLs**, **108 PASS checks**, **0 FAIL alerts**, and **7 warning types**; ZAP also listed **37 GET endpoints**. These counts are the scan output, while the OpenAPI file shows the input I supplied. I followed ZAP's [API Scan documentation](https://www.zaproxy.org/docs/docker/api-scan/). I saved the Python report helpers under [`scripts/api-security/`](scripts/api-security/README.md). They read the saved HTML report and print bounded evidence excerpts; they do not send additional requests.

```bash
# WSL workstation; run from the portfolio checkout root.
python3 docs/scripts/api-security/extract_zap_sql_alert.py
```

ZAP raised a SQL Injection alert for `GET /rest/products/search?q=q%27`, which returned HTTP 500. I reviewed the source and found that `routes/search.ts` interpolated the query value into a SQL template string. I recorded unsafe SQL construction as a source-confirmed weakness, while noting that the scanner's 500 did not prove data extraction. This route is also an intentional Juice Shop training challenge. I extracted the alert evidence with [`extract_zap_sql_alert.py`](scripts/api-security/extract_zap_sql_alert.py).

To trace the SQL alert into the source, I reviewed the search route from **WSL**. `rg` was not installed, so I used the available `grep` and `sed` commands instead:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
grep -n -C 5 'criteria\|literal\|query' routes/search.ts
sed -n '1,140p' routes/search.ts
grep -RIn --include='*.ts' 'req\.query\|sequelize\.literal' routes lib
```

I found that `routes/search.ts` builds a SQL expression using the product-search query value. My source review confirmed unsafe query construction, but I did not demonstrate data extraction.

As I reviewed selected responses, I kept the tool results separate from my manual observations. A `200` response alone did not tell me whether a route was vulnerable; I also considered the returned data and the intended access policy.

Once the port-3001 tunnel returned HTTP 200, I checked selected API responses from **WSL**. I used read-only GET requests to compare status codes, headers, and response fields with ZAP's observations:

```bash
# WSL workstation
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

I recorded each HTTP status, selected headers, and response body where available. In the application-configuration response, I reviewed the IP and timestamp values and checked for common secret-like property names; I did not confirm a secret. My anonymous request to `/api/Users` returned `401`. These requests did not change application state.

I found that the public `/api/Quantitys/` endpoint returned 56 inventory records with exact quantities and per-user purchase limits. I recorded this as a potential business-data exposure for the service owner to assess, since my evidence did not establish whether the lab intended these values to be public. My anonymous `/api/Users` request returned `401`, showing that this route denied anonymous access.

### 5.2 I tested cross-account basket authorization

Because I ran ZAP without authentication, its API scan could not establish cross-account object authorization. Before sending a live request, I examined the basket route and its tests in the source checkout. My saved source output showed `GET /rest/basket/:id`, a lookup by the requested ID, and tests for cross-user access and forged JWTs. I use these commands in the **WSL terminal** to revisit those lines; I did not retain the exact search command from the original review:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
grep -n -C 4 "app.get('/rest/basket/:id'" server.ts
sed -n '1,70p' routes/basket.ts
sed -n '40,125p' test/api/basket.test.ts
```

The source review gave me a hypothesis to check against the running application. I logged in with Account A and Account B, recorded each account's own basket ID, then sent read-only requests for the other account's basket. Both cross-account requests returned HTTP 200 and the other account's basket ID. I recorded this as a lab Broken Object Level Authorization (BOLA) finding, **API-01**, and linked it to GitHub Issue #1.

I limited the test to checking cross-account basket access. I did not inspect basket contents or try a state-changing operation, so my evidence covers only the unauthorized object reference and read behavior I observed.

My first attempt to run the account check through the WSL tunnel timed out. I moved the check to the target VM, where I had confirmed that the container bridge returned HTTP 200. I originally entered the Python directly in the target terminal, then saved it as [`check_two_account_bola.py`](scripts/api-security/check_two_account_bola.py) in the portfolio scripts folder so it could be reviewed and reused. I staged that saved copy on the target through the admin node:

```bash
# Admin node
mkdir -p ~/project-2a/scripts/api-security
```

```bash
# Target server
mkdir -p ~/project-2a/scripts/api-security
```

```bash
# WSL workstation; run from the portfolio checkout root.
scp -r -i ~/.ssh/mds_admin_ed25519 docs/scripts/api-security mdsadmin@192.168.56.101:~/project-2a/scripts/
```

```bash
# Admin node
scp -i ~/.ssh/mds_target_ed25519 ~/project-2a/scripts/api-security/*.py mdsadmin@192.168.77.10:~/project-2a/scripts/api-security/
```

On the target, I passed the container's bridge address to the helper. It prompted for both accounts' credentials without echoing them, checked each account's own basket and the other account's basket, then printed only status codes and returned basket IDs:

```bash
# Target server
CONTAINER_IP="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juice-shop)"
python3 ~/project-2a/scripts/api-security/check_two_account_bola.py "http://${CONTAINER_IP}:3000"
```

My saved terminal output was:

```text
Account A reading its own basket: HTTP 200; returned basket ID=6
Account B reading its own basket: HTTP 200; returned basket ID=7
Account A reading Account B's basket: HTTP 200; returned basket ID=7
Account B reading Account A's basket: HTTP 200; returned basket ID=6
```

I kept bearer tokens and basket contents out of the output. This manual check answered an access-control question the unauthenticated ZAP scan could not cover.

### 5.3 I checked whether an unsigned JWT was accepted

I used a test account to send a read-only basket request with an unsigned JWT (`alg: none`). The service returned HTTP 200 and a basket ID, confirming that the lab accepted an unsigned token for this protected read. I recorded the result as **API-02** and linked it to GitHub Issue #2. I did not test whether the token could impersonate other users or perform write operations.

After the basket test, I ran the unsigned-token check on the target VM. The helper prompts for Account A's email, creates a five-minute JWT with `alg: none` and that account's identity, then requests basket 6. It does not log in or print the email or token. I saved the script as [`check_unsigned_jwt.py`](scripts/api-security/check_unsigned_jwt.py) beside the BOLA helper. I had already staged the folder through the admin node in Section 5.2:

```bash
# Target server
CONTAINER_IP="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juice-shop)"
python3 ~/project-2a/scripts/api-security/check_unsigned_jwt.py "http://${CONTAINER_IP}:3000"
```

My saved terminal output showed `Unsigned-token request: HTTP 200; returned basket ID=6`. I did not modify data.

**Safety and evidence note:** I used this check to assess token validation in the training app. I used lab accounts only and did not change basket state.

### 5.4 I inspected the remaining ZAP alerts and checked the search result safely

After checking account authorization and token handling, I returned to the ZAP API report. I reviewed its CORS, private-IP, timestamp, and content-type alerts, then extracted the Server Error response code entries. The linked helpers [`inspect_zap_api_alerts.py`](scripts/api-security/inspect_zap_api_alerts.py) and [`extract_zap_server_errors.py`](scripts/api-security/extract_zap_server_errors.py) print excerpts from the saved report; they do not send requests:

```bash
# WSL workstation; run from the portfolio checkout root.
python3 docs/scripts/api-security/inspect_zap_api_alerts.py
python3 docs/scripts/api-security/extract_zap_server_errors.py
```

I found 17 server-error responses in the report. The examples available to me involved invalid base paths and scanner-generated probes; I did not see a sensitive response body or stack trace. I treated these as error-handling signals rather than 17 confirmed vulnerabilities. I also needed more context for the CORS and disclosure alerts because my evidence did not establish authenticated cross-origin access or secret exposure.

I also compared a normal product search with a single-quote search using [`compare_product_search_responses.py`](scripts/api-security/compare_product_search_responses.py). The helper prints only the status, content type, and response size. Both requests timed out while my port-3001 tunnel was unstable, so this retest gave me no new SQL injection evidence:

```bash
# WSL workstation; run from the portfolio checkout root with the tunnel open.
python3 docs/scripts/api-security/compare_product_search_responses.py
```

### 5.5 I combined manual and tool results without treating them as duplicates

I recorded how I obtained each result. I found BOLA and unsigned-JWT acceptance through manual checks with two accounts; the unauthenticated ZAP scan did not test those cases. ZAP raised the product-search SQL alert, and I confirmed unsafe query construction in source. For CORS and configuration behavior, I compared ZAP's repeated alerts with my manual response checks so I would not count the same observation twice.

In the API appendix and consolidated assessment, I kept these results distinct:

- **API-01:** confirmed cross-account basket read (manual, two accounts).
- **API-02:** unsigned JWT accepted on a protected basket read (manual).
- **API-03:** unsafe product-search SQL construction (ZAP signal plus source confirmation; runtime exploit effect not demonstrated).
- **API-04:** wildcard CORS policy observed; sensitive credentialed cross-origin access not demonstrated.
- **API-05:** configuration IP/timestamp metadata observed; no secret confirmed and sensitivity depends on owner context.
- **API-06:** malformed-request server errors observed by ZAP; no sensitive response body confirmed.
- **API-07/API-08:** content-type and CSP observations recorded as lower-confidence or lower-impact follow-up items.

With the API evidence recorded alongside the scan results, I brought the findings together for triage and owner handoff in [Section 6](#6-assessment-handoff).

## 6. Assessment handoff

### 6.1 I wrote findings for the teams who own remediation

I focused my role in this lab on assessment and risk communication, leaving source changes to the developers. I documented that the service owner should provide business context, assign an accountable team, set target dates, and decide whether to accept any residual risk. As the DevSecOps practitioner, I made the handoff actionable by preserving evidence, removing duplicates, explaining confidence, connecting findings to risk, and defining how to verify a fix.

I organized the repository to include the consolidated assessment report, SCA/SAST/DAST/API appendices, risk register, detailed SCA/SAST CSV, and first-pass triage. I also created six API remediation issues in GitHub Issues #1–#6, each linking to evidence and setting out proposed acceptance and verification expectations. I treat an issue as a handoff, not proof that the fix is complete.

### 6.2 I kept remediation and verification as future work

I ended this lab after documenting the findings and assigning follow-up; I did not change Juice Shop source code. In a real delivery pipeline, developers would implement the fixes. I would help agree on focused regression tests, rerun the relevant scanner or manual check against the fixed build, capture the evidence, and update the assessment and risk register. The service owner would then close the risk or formally accept any remaining risk based on the evidence and business context. In [What I learned](#what-i-learned), I reflect on what this process taught me about carrying findings from discovery to remediation ownership.

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

