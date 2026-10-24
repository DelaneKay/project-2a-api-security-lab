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

Before preparing Docker on the target, I checked the Docker engine available to my WSL workstation. The CLI was installed, but at first my `devsecops` account could not access `/var/run/docker.sock`. I confirmed the selected context and socket permissions, then added my personal WSL account to the `docker` group. Docker group membership grants root-level control over WSL, so this was a deliberate workstation access change. I closed and reopened the WSL shell before checking the group membership:

```bash
# WSL workstation
docker context ls
ls -l /var/run/docker.sock
sudo usermod -aG docker devsecops
# I closed and reopened the WSL shell before running these checks.
id
docker info
```

The `default` context pointed to `/var/run/docker.sock`. After reopening the shell, `id` showed the `docker` group and `docker info` showed a working Docker Desktop engine. I checked the running containers so I would not disturb another project, then confirmed that Juice Shop was already cached locally:

```bash
# WSL workstation
docker ps
docker image ls
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' bkimminich/juice-shop:latest
```

Two existing containers belonged to my `learn-to-cloud-app` project and used loopback-bound ports, so I left them running. The Juice Shop image was already available as `bkimminich/juice-shop:latest`; I recorded its image ID and repository digest before transferring it. The WSL Docker Desktop engine and the target's Docker engine were separate. The cached image could not run on the isolated target until I installed Docker there and moved the image archive across the lab nodes.

Docker was not installed on the target, and its isolated network could not download the packages. I prepared the Ubuntu packages in WSL, transferred them through the admin node, and checked their checksums at each step. This was the first Docker installation; the later Docker failure happened separately in the lab.

Before installing Docker, I checked free disk space, the Ubuntu release, the available Docker package version, and the packages APT planned to install. I ran these commands on the **target server**, reached from WSL through the admin node:

```bash
# Target server
df -h /
cat /etc/os-release
apt-cache policy docker.io
apt-get -s install docker.io
```

I confirmed the target was Ubuntu 26.04.1. Its package index offered `docker.io` version `29.1.3-0ubuntu4.1`, and the simulation showed eight new packages with none removed. I refreshed WSL's package list and checked its candidate version too:

```bash
# WSL workstation
sudo apt-get update
apt-cache policy docker.io
apt-get -s install docker.io
```

WSL listed more packages in its simulation because WSL and the target already had different dependencies installed. I used the target's package plan to decide which files to transfer.

APT downloaded `docker.io`, `containerd`, and `runc`, but skipped five dependencies that were already installed in WSL. I downloaded those package files separately, then staged the eight packages the target needed:

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

The eight packages totalled about **71 MB**. In WSL, I created a SHA-256 manifest and checked it before sending the files. I then made a staging folder on the **admin node**:

```bash
# Admin node
mkdir -p ~/project-2a/staging/docker-packages
```

From **WSL**, I copied the manifest and packages into that folder:

```bash
# WSL workstation
scp -i ~/.ssh/mds_admin_ed25519 SHA256SUMS *.deb mdsadmin@192.168.56.101:~/project-2a/staging/docker-packages/
```

On the **admin node**, I checked the transferred files against the manifest:

```bash
# Admin node
cd ~/project-2a/staging/docker-packages
sha256sum -c SHA256SUMS
```

I confirmed all eight package files reported `OK` on the admin node.

Next, I created the same staging folder on the **target server**:

```bash
# Target server
mkdir -p ~/project-2a/staging/docker-packages
```

From the **admin node**, I used its SSH key for the target to copy the package files across:

```bash
# Admin node
scp -i ~/.ssh/mds_target_ed25519 ~/project-2a/staging/docker-packages/* mdsadmin@192.168.77.10:~/project-2a/staging/docker-packages/
```

On the **target server**, I checked the manifest again:

```bash
# Target server
cd ~/project-2a/staging/docker-packages
sha256sum -c SHA256SUMS
```

I confirmed all eight packages reported `OK` on the target, so the transfer had not changed them.

The first offline APT attempt hit a problem. On the **target server**, the `--no-download` simulation failed with `Unable to fetch some archives` and made no changes. A simulation using the local package paths showed the eight-package plan, but the real APT install still tried to fetch archives and failed. I kept all three target-side commands here to show what I tried and where it stopped:

```bash
# Target server
cd ~/project-2a/staging/docker-packages
apt-get --no-download -s install ./*.deb

# Target server: simulation using local package paths.
apt-get -s install ./*.deb

# Target server: actual APT attempt, which also failed to fetch archives.
sudo apt-get --no-download install ./*.deb
```

Since the package files were already on the **target server**, I used `dpkg` to install them locally:

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

I confirmed the Docker service was `active`. The route table showed the new `172.17.0.0/16` bridge alongside the lab route `192.168.77.0/24`, and no default route. That confirmed the target still had no direct internet route.

### 1.2 I transferred, verified, and started the first Juice Shop container

The target had no internet route, so I used the `bkimminich/juice-shop:latest` image already stored in WSL. I saved it to an archive for transfer. Before this, WSL reported image ID `sha256:2d370ec1…` and a repository digest for the image.

I saved the image and created a checksum file in **WSL**:

```bash
# WSL workstation
docker save --output ~/project-2a/staging/juice-shop.tar bkimminich/juice-shop:latest
cd ~/project-2a/staging
sha256sum juice-shop.tar > juice-shop.tar.sha256
ls -lh juice-shop.tar juice-shop.tar.sha256
```

The archive was about **347 MB**. I copied the archive and its checksum file from **WSL to the admin node**:

```bash
# WSL workstation
scp -i ~/.ssh/mds_admin_ed25519 juice-shop.tar juice-shop.tar.sha256 mdsadmin@192.168.56.101:~/project-2a/staging/
```

On the **admin node**, I checked the archive against its manifest:

```bash
# Admin node
cd ~/project-2a/staging
sha256sum -c juice-shop.tar.sha256
```

The check returned `juice-shop.tar: OK`. From the **admin node**, I copied the verified archive and checksum file to the target:

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

Before starting Juice Shop, I checked the image on the **target server**. My first attempt from WSL failed because `sudo` needed a terminal. The target-side command was the same on retry; I allocated a terminal at both SSH hops so the password prompt could work:

```bash
# Target server
sudo docker image inspect --format '{{.Id}}' bkimminich/juice-shop:latest

# Target server: retry in an interactive target shell.
sudo docker image inspect --format '{{.Id}}' bkimminich/juice-shop:latest
```

The image IDs did not match: the target reported `sha256:9a55bcd1…`, while WSL reported `sha256:2d370ec1…`. I paused to compare the archive manifest, config hash, and image layers before starting the container.

On **WSL**, I checked the archive manifest and hashed its config blob. The blob matched the WSL image ID. I also fixed a layer-inspection command: I had left its format expression unquoted, so the first result was an error hash rather than a useful layer fingerprint.

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

The config blob hashed to `2d370ec1…`. Both layer-list checks returned `36fd80fb…`, and the target reported `OS=linux ARCH=amd64`. The image IDs were different in the two Docker stores, but the archive checksum and matching layer lists gave me enough evidence to continue with the lab image.

Once the image checks were complete, I started Juice Shop on the **target server**, bound it to the private lab address, and checked that it was running:

```bash
# Target server
sudo docker run -d --name juice-shop --restart unless-stopped -p 192.168.77.10:3000:3000 bkimminich/juice-shop:latest
sudo docker ps --filter name=juice-shop
```

Docker returned container ID `5440dc6a…`. The **target server** showed the container as **Up**, with port 3000 bound to `192.168.77.10`.

I checked the application from the **admin node** with this request; it returned `HTTP 200`:

```bash
# Admin node
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 http://192.168.77.10:3000/
```

Windows could not reach the target's isolated address directly. I opened an SSH tunnel from **WSL** through the admin node and left that terminal running:

```bash
# WSL workstation
ssh -N -L 3000:192.168.77.10:3000 -i ~/.ssh/mds_admin_ed25519 mdsadmin@192.168.56.101
```

The browser opened Juice Shop at `http://localhost:3000`. At that point, I had Juice Shop running on the target and could reach it through the WSL tunnel. The Docker outage and repeat image setup happened later in the lab. In [Section 2](#2-dast--dynamic-application-security-testing), I began assessing the running application with ZAP.


## 2. DAST — Dynamic Application Security Testing

### 2.1 I ran ZAP baseline and AJAX-enabled baseline scans

I ran the first ZAP web scans while the original port-3000 path was responding. The preserved reports and crawler results show that I scanned `http://host.docker.internal:3000`. That forward later became unreliable, so I investigated the connection before continuing the API scan over port 3001. ZAP gave me a black-box DAST view: it interacted with the live application over HTTP without reading the source. The baseline run discovered 116 URLs and reported **0 FAIL alerts**, **3 warning types**, and **58 PASS checks**. The warning types included missing Content Security Policy, cross-domain configuration, and the informational modern-web-application classification.

In a separate run, I got **35 URLs**, **0 FAIL alerts**, **3 warning types**, and **58 PASS checks** from the AJAX-enabled baseline. I recorded these as baseline results; the later Spider API crawl, with 94 traditional Spider URLs and 91 AJAX Spider URLs, appears in Section 2.2.

**Problem I encountered:** One AJAX-enabled baseline attempt hit connection refused while the SSH tunnel was down. After the port-3000 path responded again, I reran the scan successfully. The separate AJAX Spider API scope errors are recorded in Section 2.2. I treated these setup errors as connectivity problems, not application vulnerabilities.

I treated these as black-box scans: ZAP evaluated behavior visible over HTTP without inspecting source code. I ran them before cloning the source for SAST and SCA. I cover ZAP's API-specific scan later, alongside the API Security results in Section 5.

**Checkpoint:** With DAST, I mapped reachable pages and observed how the application responded from the outside. In my report, I separated those responses from issues I confirmed in source and from scanner signals that still need endpoint-specific validation.

#### I prepared ZAP in WSL and checked the tunnel

I chose OWASP ZAP for the DAST scan. Its baseline scan crawls the application and reports passive findings without actively attacking endpoints. I first checked whether the ZAP image was already available in WSL. It was not, so I pulled it. The Juice Shop SSH tunnel was open in another WSL terminal; before starting a scan, I checked that WSL could reach the application through that tunnel:

```bash
# WSL workstation
docker image ls zaproxy/zap-stable
docker pull zaproxy/zap-stable
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 http://localhost:3000/
```

I pulled the image successfully, and my reachability check returned `HTTP 200`. I then ran ZAP against `http://host.docker.internal:3000`, the address the scanner container used to reach the tunneled service.

#### Commands I ran and the report-permission problem I fixed

I kept the failed attempts and their error messages in this walkthrough so the setup problems and the eventual fix are clear. My first scan attempt could not save ZAP's automation plan: ZAP ran as its container user, whose default home `/home/zap` was not writable. Running ZAP as my WSL user fixed access to the report folder but left the default home unwritable. I then tried mounting a separate `zap-home` directory beneath the report mount; ZAP still could not write `/zap/wrk/home/zap.yaml`. Those attempts did not produce the saved HTML report.

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

I got the scan working by making the WSL report directory writable and keeping ZAP's temporary home in `/tmp`. I used `chmod 777` only as a temporary permission change on the lab report folder so the container could write its report; I did not change target-server hardening. This run produced the saved 116-URL baseline report:

```bash
# WSL workstation
chmod 777 ~/project-2a/zap-reports
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -r juice-shop-baseline.html
```

I then ran the AJAX-enabled passive baseline. One attempt failed because the SSH tunnel returned `Connection refused`; after the tunnel returned HTTP 200, this scan completed and saved the 35-URL report:

```bash
# WSL workstation
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 http://localhost:3000/
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -j -r juice-shop-ajax.html
```

I checked that the AJAX HTML report existed, then previewed its URL-looking strings:

```bash
# WSL workstation
ls -lh ~/project-2a/zap-reports/juice-shop-ajax.html
grep -o 'http[^"< ]*' ~/project-2a/zap-reports/juice-shop-ajax.html | sort -u | head -n 30
```

I found that the HTML report did not provide a complete URL inventory, so I reran the AJAX-enabled baseline to save JSON as well as HTML. The scan remained passive, and I did not treat its JSON report as a complete Spider URL export:

```bash
# WSL workstation
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -j \
  -J juice-shop-ajax.json -r juice-shop-ajax.html
```

Someone suggested `zap-full-scan.py`, but I did not complete that scan. I report only the completed `zap-baseline.py` results as evidence.
For ZAP to scan through the tunnel, I needed its container to resolve `host.docker.internal` to WSL and reach forwarded port 3000. When that path failed, I checked scanner-to-target connectivity before treating any output as a scan result. All scans targeted my isolated lab instance.

### 2.2 I used the ZAP API to compare the two crawlers

I wanted to see whether the traditional Spider had found the application's JavaScript-loaded API routes. After the baseline scans, I started a temporary ZAP daemon in WSL and queried its Spider API. I retained the daemon command, traditional Spider calls, and the first failed AJAX request (`inScope=true`, which returned “The starting URI is not in scope”). My retry with `inScope=false` returned an internal error. The eventual AJAX result list contained 91 URLs, but I did not retain the successful scan-start parameters. I have kept that limitation clear instead of attributing the result to a command I cannot verify.

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

The AJAX Spider found API routes the traditional Spider missed, including `/api/Challenges/` and several `/rest/` endpoints. The saved URL lists contained **91 AJAX URLs, 94 traditional URLs, 10 exact matches, and 81 AJAX-only URL strings**. Some AJAX-only strings differed only by changing Socket.IO query values, so the count does not represent 81 distinct routes. I used this discovery comparison to choose a few read-only API requests for an initial review. These checks happened after the ZAP crawl and before I cloned the source for SAST.

I began with an unauthenticated `GET` to the application-configuration endpoint. The response was `200 OK`, so I inspected the JSON field names before deciding whether anything sensitive was exposed:

```bash
# WSL workstation
curl -sS -D - --max-time 10 -o /dev/null http://localhost:3000/rest/admin/application-configuration
```

I recorded the `200 OK` as an observation, not a confirmed vulnerability. I saved the two configuration-inspection Python snippets as one helper. It prints the JSON property paths and common secret-like key names without printing values:

```bash
# WSL workstation; run from the portfolio checkout root.
python3 docs/scripts/api-security/inspect_application_configuration.py
```
I found one top-level property, `config`, and no property names matching the secret-related terms. The helper then listed the nested configuration paths without printing their values.

The fields described frontend configuration, product data, and server settings. One was a Google OAuth `clientId`, an identifier rather than a secret. The name filter was only a first-pass check: it could not establish that every value was safe. Based on the paths and reviewed output, I treated this as public UI configuration and did not confirm sensitive-data exposure.

I checked the related application-version endpoint next. First I captured its unauthenticated status and headers, then read its small JSON response:

```bash
# WSL workstation
curl -sS -D - --max-time 10 -o /dev/null http://localhost:3000/rest/admin/application-version
curl -sS --max-time 10 http://localhost:3000/rest/admin/application-version
```

I received `{"version":"20.3.0"}` without authentication. I recorded it as low-sensitivity version metadata, not an authorization flaw.

I then requested the discovered Score Board challenge record. This was a read-only query; `%20` encodes the space in the challenge name:

```bash
# WSL workstation
curl -sS --max-time 10 'http://localhost:3000/api/Challenges/?name=Score%20Board'
```

I saw challenge catalog fields such as name, category, description, difficulty, and `solved: false`. These fields support the Juice Shop interface, so they did not confirm an API vulnerability. The AJAX results also contained “challenge solved” events for two challenges, but I could not tell from those results alone whether the Spider caused the state changes.

Finally, I checked the response's CORS headers using a test origin. This request also did not modify application data:

```bash
# WSL workstation
curl -sS -D - --max-time 10 -o /dev/null \
  -H 'Origin: https://other-origin.example' \
  'http://localhost:3000/api/Challenges/?name=Score%20Board'
```

I recorded these unauthenticated requests as initial triage observations. They gave me a starting point for the later API work. I then moved from live application testing to source analysis in [Section 3](#3-sast--static-application-security-testing). I returned to API-specific testing later in [Section 5](#5-api-security), using ZAP API Scan and authenticated checks to investigate authorization questions.


## 3. SAST — Static Application Security Testing

### 3.1 I cloned the matching Juice Shop source and prepared Snyk

After I confirmed Juice Shop was running on the target, I prepared the source checkout in **WSL** for code analysis. The source folder was missing when I checked it, so I cloned the official `v20.3.0` release to match the application version. I checked Git first; it reported version `2.53.0`.

```bash
# WSL workstation
git --version
cd ~/project-2a
git clone --depth 1 --branch v20.3.0 https://github.com/juice-shop/juice-shop.git juice-shop-source
```

I installed the Snyk CLI as a user executable in WSL. The first suggested system-wide location, `/usr/local/bin`, was owned by root, so I placed the binary under my home directory instead:

```bash
# WSL workstation
ls -ld /usr/local/bin
mkdir -p "$HOME/.local/bin"
curl -fsSL https://static.snyk.io/cli/latest/snyk-linux -o "$HOME/.local/bin/snyk"
chmod +x "$HOME/.local/bin/snyk"
"$HOME/.local/bin/snyk" --version
```

The CLI reported version `1.1308.3`. I authenticated it before scanning. The browser OAuth callback returned “Not Found,” and checking the CLI showed that no API credential had been set. I inspected the available authentication options and switched to token-based authentication; the token was entered at the hidden terminal prompt and is not included here:

```bash
# WSL workstation
"$HOME/.local/bin/snyk" auth
"$HOME/.local/bin/snyk" config get api
"$HOME/.local/bin/snyk" auth --help
"$HOME/.local/bin/snyk" auth --auth-type=token
```

The token-based flow authenticated successfully. I confirmed the checkout was ready, then enabled Snyk Code for the selected organization after my first scan reported that the feature was disabled. I made that change in the Snyk web console, not in a shell.

### 3.2 I ran Snyk Code against the source

SAST was **white-box** in this project because Snyk Code analyzed the source checkout. My first scan attempt returned a message that Snyk Code was disabled for the selected organization, so it produced no findings. I enabled Snyk Code for that organization in the Snyk web console, then repeated the same command from the repository. The console change was not a shell command.

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

After the SAST scan, I moved to SCA. Snyk Open Source compares project dependencies with known advisories. Although Juice Shop was running on the target, I ran this scan in **WSL** against the source checkout and its local dependency tree; it did not send requests to the target container. The initial DAST scans had already been run against the live target; the API assessment came later, after I restored a working tunnel.

I first tried to scan the source dependencies. Snyk could not produce a result because the checkout had neither a supported lockfile nor an installed `node_modules` directory:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
"$HOME/.local/bin/snyk" test
```

The terminal returned `SNYK-CLI-0000` and said **“Missing node_modules folder: we can't test without dependencies. Please run 'npm install' first.”** I checked the manifest and searched for lockfiles; the checkout contained `package.json`, but no `package-lock.json`, npm shrinkwrap, or Yarn lockfile:

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

Once Node.js and npm were available, I installed the Juice Shop dependency tree without executing package lifecycle scripts. This created the local dependencies Snyk needed and avoided running the project’s `postinstall` build script during the assessment:

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

**Scope limit:** Because the checkout had no committed lockfile, npm resolved a local dependency tree for this scan. The result did not prove that the selected versions exactly matched the prebuilt container image on the target. I recorded the dependency recommendations for the development team and did not change Juice Shop's dependencies.

**Checkpoint:** SCA identified known advisories in the local dependency tree, but it did not establish runtime reachability, prove exploitability, or verify a fix. I had now assessed the application source and dependencies. Next, I returned to the running service to assess API-specific behavior in [Section 5](#5-api-security).

## 5. API Security

I used two methods to assess API security. ZAP API Scan discovered routes and sent generated requests across the imported API surface. I then used two lab accounts to answer questions the unauthenticated scan could not answer: could one user read another user's basket, and would the application accept an unsigned token? I kept those checks read-only.

### 5.1 I ran the ZAP API Scan and established the API surface

I used the AJAX Spider results to select routes for the API Scan, including challenge and quantity endpoints, product search, languages, application version and configuration, and user-related routes. I ran the API Scan without authentication against the imported definition, and ZAP added scanner-generated requests. I recorded its counts and alert summary after the scan command.

I used ZAP's API Scan with an OpenAPI definition containing **eight GET-only routes** discovered in the AJAX results. I left `/rest/continue-code` out because it could expose challenge state. I include the exact definition and scan command below. I also saved the same definition as [`juice-shop-api-readonly.yaml`](scripts/api-security/juice-shop-api-readonly.yaml) in the helper folder for reuse.

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

I then ran the ZAP API Scan against that definition and saved the HTML report. ZAP sent active test probes to the described GET routes. The definition left out the order-creation `POST` route, so the scan did not intentionally submit an order:

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

ZAP reported a SQL Injection alert on `GET /rest/products/search?q=q%27` with an HTTP 500 response. Source review independently found that `routes/search.ts` interpolated the query value into a SQL template string. I recorded unsafe SQL construction as a source-confirmed weakness, while making clear that the scanner's 500 was not proof of data extraction. The SQL injection route is also an intentional Juice Shop training challenge. I extracted the alert evidence with [`extract_zap_sql_alert.py`](scripts/api-security/extract_zap_sql_alert.py).

To trace the SQL alert into the source, I reviewed the search route from **WSL**. `rg` was not installed, so I used the available `grep` and `sed` commands instead:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
grep -n -C 5 'criteria\|literal\|query' routes/search.ts
sed -n '1,140p' routes/search.ts
grep -RIn --include='*.ts' 'req\.query\|sequelize\.literal' routes lib
```

This review found that `routes/search.ts` constructs a SQL expression using the product-search query value. It confirmed unsafe construction in source, but did not demonstrate data extraction.

I kept the tool results separate from my manual observations as I reviewed selected responses. A `200` response alone did not tell me whether a route was vulnerable; I also had to consider the returned data and the intended access policy.

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

Because I ran ZAP without authentication, its API scan could not establish cross-account object authorization. Before sending a live request, I examined the basket route and its tests in the source checkout. My saved source output showed `GET /rest/basket/:id`, a basket lookup by the requested ID, and tests for cross-user access and forged JWTs. I use the following commands from the **WSL terminal** to revisit those lines; I did not retain the exact original source-search command:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
grep -n -C 4 "app.get('/rest/basket/:id'" server.ts
sed -n '1,70p' routes/basket.ts
sed -n '40,125p' test/api/basket.test.ts
```

Source review gave me a test hypothesis, but I still needed a live response from the running container. I used Account A and Account B, recorded each account's own basket ID, then issued read-only requests for the other account's basket. The output showed HTTP 200 in both directions and returned the other account's basket ID. This confirmed a lab Broken Object Level Authorization (BOLA) issue, recorded as **API-01** and linked to GitHub Issue #1.

I limited the test to checking cross-account basket access. I did not inspect basket contents or try a state-changing operation, so my evidence covers only the unauthorized object reference and read behavior I observed.

Before running the account check, my first WSL-through-tunnel script timed out. I moved the successful check to the target VM, where the container bridge returned HTTP 200. The original Python was entered directly in the target terminal; I saved it as [`check_two_account_bola.py`](scripts/api-security/check_two_account_bola.py) in the portfolio scripts folder so it can be reviewed and reused. To run that saved copy on the target, I stage the file through the admin node:

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

On the target, I pass the container's bridge address to the helper. It prompts for Account A and B credentials without echoing them, checks each account's own basket and the other account's basket, and prints only status codes and returned basket IDs:

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

I did not print bearer tokens or basket contents. This manual result answered an access-control question that the unauthenticated ZAP run did not cover.

### 5.3 I checked whether an unsigned JWT was accepted

I used a test account and sent a read-only basket request with an unsigned JWT (`alg: none`). The service returned HTTP 200 and a basket ID. This confirmed that the lab accepted an unsigned token for that protected read, recorded as **API-02** and linked to GitHub Issue #2. The broader consequences, such as using the token to impersonate other users or perform writes, were not tested.

I ran the unsigned-token check on the target VM after the basket test. The Python helper reconstructs the observed test: it prompts for Account A's email, creates a five-minute JWT with `alg: none` and the Account A identity, and requests only basket 6. It does not log in or print the email or token. I saved this as [`check_unsigned_jwt.py`](scripts/api-security/check_unsigned_jwt.py) alongside the BOLA helper. The folder had already been staged through the admin node in Section 5.2:

```bash
# Target server
CONTAINER_IP="$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juice-shop)"
python3 ~/project-2a/scripts/api-security/check_unsigned_jwt.py "http://${CONTAINER_IP}:3000"
```

My saved terminal output showed `Unsigned-token request: HTTP 200; returned basket ID=6`. I did not modify data.

**Safety and evidence note:** The purpose was to demonstrate authentication validation in the training app. I did not test real accounts or a production service, and I did not use the test to modify basket state.

### 5.4 I inspected the remaining ZAP alerts and checked the search result safely

After the account and token checks, I returned to the ZAP API report and reviewed the CORS, private-IP, timestamp, and content-type alerts. I also extracted the Server Error response code entries. The linked helpers [`inspect_zap_api_alerts.py`](scripts/api-security/inspect_zap_api_alerts.py) and [`extract_zap_server_errors.py`](scripts/api-security/extract_zap_server_errors.py) print report excerpts only; they do not send requests:

```bash
# WSL workstation; run from the portfolio checkout root.
python3 docs/scripts/api-security/inspect_zap_api_alerts.py
python3 docs/scripts/api-security/extract_zap_server_errors.py
```

I found 17 server-error responses in the report. The examples available to me involved invalid base paths and scanner-generated probes; I did not see a sensitive response body or stack trace. I treated these as error-handling signals rather than 17 confirmed vulnerabilities. I also needed more context for the CORS and disclosure alerts because my evidence did not establish authenticated cross-origin access or secret exposure.

I then compared a normal product search with a single-quote search using [`compare_product_search_responses.py`](scripts/api-security/compare_product_search_responses.py), which prints only status, content type, and response size. Both requests timed out while the port-3001 tunnel was unstable, so this retest provided no new SQL injection evidence:

```bash
# WSL workstation; run from the portfolio checkout root with the tunnel open.
python3 docs/scripts/api-security/compare_product_search_responses.py
```

### 5.5 I combined manual and tool results without treating them as duplicates

I kept the source of each result clear. My two-account BOLA and unsigned-JWT checks were manual; ZAP's unauthenticated API scan did not reproduce them. ZAP raised the product-search SQL alert, and I used source review to confirm unsafe query construction. For CORS and configuration behavior, I compared ZAP's repeated observations with my manual response checks rather than counting the same behavior twice.

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

I focused my role in this lab on assessment and risk communication. I left source changes with the developers. I expect the service owner to provide business context, assign an accountable team, set target dates, and decide whether to accept any residual risk. As the DevSecOps practitioner, I made the handoff actionable by preserving evidence, deduplicating results, explaining confidence, connecting findings to risk, and defining how a fix should be verified.

I organized the repository to include the consolidated assessment report, SCA/SAST/DAST/API appendices, risk register, detailed SCA/SAST CSV, and first-pass triage. I also created six API remediation issues in GitHub Issues #1–#6, each linking to evidence and setting out proposed acceptance and verification expectations. I treat an issue as a handoff, not proof that the fix is complete.

### 6.2 I kept remediation and verification as future work

I stopped this lab after documenting findings and assigning follow-up; I did not change Juice Shop source code. In a real delivery pipeline, developers would implement the fixes. I would support them by agreeing on focused regression tests, rerunning the relevant scanner or manual check against the fixed build, capturing the evidence, and updating the assessment and risk register. The service owner would then close the risk or formally accept what remains, based on the evidence and business context. In [What I learned](#what-i-learned), I reflect on what this assessment taught me about carrying findings from discovery to remediation ownership.

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

