# Watch

Scope-aware security reconnaissance, research, and AI-assisted verification platform.

> Run reconnaissance only against assets/programs for which you have explicit authorization.

## 1. Architecture

```text
Programs / Scope
      |
      v
Program Sync -> Enumeration -> DNS/NS -> HTTP -> Crawl Fresh
                                      |
                                      v
                              URLs -> Endpoints
                                      |
                                      v
                              Param Discovery

AI research:
CVE/NVD -> References -> Research/Correlation -> Nuclei decision
                                              -> Template generation
                                              -> Semantic validation
                                              -> Dry-run

AI verification:
TestPlan -> Authorization -> Resolution -> Scope -> Executor
         -> Evidence -> Deterministic Verification -> Sealed Finding
```

The AI layer is deliberately separated from the reconnaissance pipeline. LLM output is not authoritative evidence.

## 2. Current deployment

| Item | Value |
|---|---|
| OS | Ubuntu 24.04.4 LTS |
| VM | Google Cloud |
| CPU | 4 vCPU |
| RAM | 12 GB |
| Disk | 48 GB |
| Project | `/opt/watch` |
| Python | 3.12.x |
| venv | `/opt/watch/venv` |
| Go | 1.23.0 |
| MongoDB | Docker Compose |
| API | FastAPI/Uvicorn |
| API port | 5000 |
| Mongo port | 27017 |
| Timezone | Asia/Tehran |

The previous Watch VPS was migrated to this VM. MongoDB `watch` was transferred using `mongodump`/`mongorestore` and application connectivity was verified.

## 3. Project layout

```text
/opt/watch/
├── api.py
├── config.py
├── requirements.txt
├── .env
├── run-pipeline.sh
├── run-heavy-guarded.sh
├── setup-core-pipeline.sh
├── setup-weekly-jobs.sh
├── resolvers.txt
├── database/
│   ├── db.py
│   └── docker-compose.yml
├── programs/
├── enum/
├── ns/
├── http/
├── crawl/
├── nuclei/
├── ai/
│   ├── config.py
│   ├── collectors/
│   ├── schemas/
│   ├── researcher/
│   ├── verification/
│   ├── deterministic/
│   ├── execution/
│   ├── authorizer/
│   ├── scope/
│   ├── evidence/
│   ├── finding/
│   ├── knowledge/
│   └── llm/
├── wordlists/
└── logs/
```

## 4. Server setup

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git python3 python3-pip python3-venv build-essential   docker.io docker-compose-v2 unzip zsh tmux wget dnsutils crunch gzip   pkg-config libssl-dev

sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
chsh -s "$(which zsh)"
```

Create/use the project:

```bash
sudo mkdir -p /opt/watch
sudo chown "$USER:$USER" /opt/watch
cd /opt/watch
```

## 5. Python

```bash
cd /opt/watch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip check
```

The migrated VM passed `pip check` with no broken requirements.

## 6. Go and recon tools

Install Go 1.23.0:

```bash
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

The toolchain is:

```text
subfinder
httpx
dnsx
assetfinder
unfurl
waybackurls
gospider
findomain
katana
x8
massdns
puredns
alterx
crunch
dig
```

Go-installed binaries are under:

```text
$HOME/go/bin
```

`x8` is Rust-based and must be installed with Cargo/Rust, not `go install`:

```bash
cargo install x8
sudo cp ~/.cargo/bin/x8 /usr/local/bin/x8
```

`massdns` is built from source and installed at `/usr/local/bin/massdns`.

Resolver list:

```bash
curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt   -o /opt/watch/resolvers.txt
```

Sanity check:

```bash
for bin in subfinder httpx dnsx assetfinder unfurl waybackurls gospider findomain   katana x8 massdns puredns alterx crunch dig; do
  command -v "$bin" >/dev/null 2>&1 && echo "OK $bin" || echo "MISSING $bin"
done
```

## 7. PATH and zsh subprocesses

Non-interactive `zsh -c` does not reliably source `~/.zshrc`. Watch therefore injects a fixed tool PATH into its shared subprocess runners in `utils/common.py`.

Current PATH components:

```text
/opt/watch/venv/bin
/home/pouya_behnia/go/bin
/usr/local/bin
/usr/local/go/bin
/usr/bin
/bin
```

This prevents failures such as:

```text
zsh: command not found: dnsx
```

Do not solve this by scattering hard-coded PATH changes through individual modules; the shared runner is the intended seam.

## 8. Environment and secrets

Keep secrets in `.env`, never in Git.

Typical variables:

```dotenv
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
API_KEY=...
WATCH_DIR=/opt/watch
```

AI provider credentials are also environment-based, including the provider-specific OpenRouter/AvalAI settings.

Generate an API key with:

```bash
openssl rand -hex 32
```

Never commit API keys, Telegram tokens, LLM credentials, or Mongo passwords.

## 9. MongoDB

MongoDB is managed by:

```text
database/docker-compose.yml
```

Start it:

```bash
cd /opt/watch
docker compose -f database/docker-compose.yml up -d
docker ps
```

Authenticated ping:

```bash
docker exec mongo mongosh   --username pouya   --password 'YOUR_MONGO_PASSWORD'   --authenticationDatabase admin   --quiet   --eval 'db.adminCommand({ping:1})'
```

Expected:

```text
{ ok: 1 }
```

Do not expose port 27017 broadly. If Compass access is required, restrict the cloud firewall to trusted source IPs.

### Main collections

| Collection | Purpose |
|---|---|
| `Programs` | program scope and out-of-scope definitions |
| `Subdomains` | discovered subdomains/providers |
| `LiveSubdomains` | DNS-resolved hosts/IP/CDN |
| `Http` | HTTP probe results |
| `Urls` | crawled URLs |
| `Endpoints` | normalized endpoint inventory |
| `DnsBruteStatus` | DNS wildcard/bruteforce status |

Scope integrity is a core rule: unknown programs and out-of-scope assets must not become normal in-scope records.

## 10. Recon stages

### Enumeration

```bash
python3 enum/watch_enum_all.py
```

### DNS / NS

```bash
python3 ns/watch_ns_all.py
```

DNS bruteforce jobs:

```text
ns/watch_dns_precheck.py
ns/watch_dns_static.py
ns/watch_dns_dynamic.py
```

### HTTP

```bash
python3 http/watch_http_all.py
```

### Crawl Fresh

```bash
python3 crawl/watch_crawl_fresh.py
```

### Crawl ALL

```bash
python3 crawl/watch_crawl_all.py
```

### Parameter discovery

```bash
python3 crawl/watch_param_discovery.py --max-minutes 300
```

Use smaller filters/time limits for validation before launching large authorized workloads.

Crawl persistence is scope-aware and must not turn unrelated third-party hosts found in page content into normal Watch targets.

## 11. Core pipeline

`run-pipeline.sh` is the canonical 12-hour runner:

```text
1. Sync Programs
2. Enumeration
3. DNS Resolution
4. HTTP Scanning
5. Crawl Fresh
```

Manual:

```bash
/opt/watch/run-pipeline.sh
```

Logs:

```text
/opt/watch/logs/
```

## 12. Core scheduling

The source of truth is:

```text
setup-core-pipeline.sh
```

Apply:

```bash
cd /opt/watch
sudo bash setup-core-pipeline.sh
```

Creates/updates:

```text
watch.service
watch.timer
```

Schedule:

```text
00:00 Asia/Tehran
12:00 Asia/Tehran
```

Policy:

- `Persistent=false`
- no randomized delay
- service is triggered by the timer
- shared `/run/watch-pipeline.lock`
- `KillMode=control-group`

Do not manually recreate these unit files; the setup script is authoritative.

## 13. Weekly heavy jobs

Source of truth:

```text
setup-weekly-jobs.sh
run-heavy-guarded.sh
```

Apply:

```bash
sudo bash setup-weekly-jobs.sh
```

| Day | Time | Job |
|---|---:|---|
| Friday | 06:00 | DNS precheck |
| Saturday | 06:00 | Crawl ALL |
| Sunday | 06:00 | Param discovery |
| Monday | 06:00 | DNS static |
| Tuesday | 06:00 | DNS static |
| Wednesday | 06:00 | DNS dynamic |
| Thursday | 06:00 | DNS dynamic |

Heavy jobs may start only during:

```text
06:00 <= Tehran time < 11:30
```

All use `watch-heavy.slice`:

| Resource | Limit |
|---|---:|
| CPU | 60% |
| MemoryHigh | 2500 MiB |
| MemoryMax | 3 GiB |
| IOWeight | 20 |
| OOMScoreAdjust | 500 |

Core and heavy jobs share the pipeline lock.

## 14. Always-on API

`watch-api.service` is independent of the core/heavy schedulers and is not placed in `watch-heavy.slice`.

Enable:

```bash
sudo systemctl enable --now watch-api.service
```

Check:

```bash
sudo systemctl status watch-api.service --no-pager -l
sudo journalctl -u watch-api.service -n 100 --no-pager
sudo ss -lntp | grep ':5000'
```

Restart:

```bash
sudo systemctl restart watch-api.service
```

The API listens on port `5000` and uses API-key authentication.

Swagger:

```text
/docs
```

Program statistics:

```text
/api/stats/by-program
```

If port 5000 is cloud-firewall exposed, restrict it to trusted clients whenever possible.

## 15. Scheduling verification

```bash
systemctl list-timers --all | grep watch
```

Core:

```bash
systemctl show watch.timer   -p UnitFileState -p Persistent -p RandomizedDelayUSec   -p NextElapseUSecRealtime
```

Heavy slice:

```bash
systemctl show watch-heavy.slice   -p CPUQuotaPerSecUSec -p MemoryHigh -p MemoryMax   -p IOWeight -p OOMScoreAdjust
```

Heavy service:

```bash
systemctl show watch-crawl-all.service   -p Slice -p RuntimeMaxUSec -p KillMode
```

## 16. Maintenance scripts

```text
crawl/migrate_urls_to_endpoints.py
crawl/compact_endpoints.py
crawl/cleanup_unknown_scope.py
```

These are maintenance/one-time utilities, not normal scheduled stages.

They were used to:

- backfill endpoint inventory
- normalize path duplicates
- remove out-of-scope/third-party data that leaked before scope filtering was tightened

Run only intentionally.

## 17. AI security-research architecture

The AI code currently has three distinct areas.

### Legacy XSS path

Older XSS verification components remain for compatibility/offline testing and are explicitly non-production.

### Deterministic verification path

```text
TestPlan
 -> Authorization
 -> Target Resolution
 -> Scope Evaluation
 -> HTTP/Nuclei/Browser execution specs
 -> Evidence
 -> Deterministic Verification
 -> Sealed Finding
```

The architecture separates authorization, scope, execution, evidence, verification, and finding materialization.

### CVE/Nuclei research path

```text
NVD CVE
 -> Reference Discovery
 -> Reference Collection
 -> Research/Correlation
 -> Nuclei Template Parsing
 -> Decision
 -> Generation
 -> Semantic Validation
 -> Dry-run
```

Research findings are non-authoritative and must not bypass the deterministic finding authority.

## 18. AI collectors

Current AI collectors cover:

- NVD CVE ingestion
- GitHub/NVD reference discovery
- reference fetching and SHA-256 deduplication
- Mongo HTTP asset ingestion
- Nuclei YAML/template parsing
- discovery and exploit-evidence research helpers

## 19. LLM providers

Provider abstraction:

```text
ai/llm/
```

Current providers:

```text
OpenRouter
AvalAI
```

The provider interface returns typed results. Provider keys are read from environment variables.

OpenRouter supports structured JSON output and avoids logging credentials.

## 20. AI verification safety

Production live execution is currently intentionally blocked:

```text
LIVE_TRAFFIC_ENABLED=False
LIVE_NUCLEI=False
```

The current architecture identifies:

- **B1:** production address-source/resolution review
- **B2:** production Mongo adapters for authorization/ledger/audit/evidence/finding
- **B3:** sandbox, network namespace, egress and resource boundary

Until these are reviewed and implemented, live transport remains disabled.

## 21. AI roadmap

### Stage 1 — offline authorized pipeline

```text
Endpoint
 -> TestPlan
 -> Artifact
 -> AuthorizationRequest
 -> Issue
 -> Resolve
 -> Scope
 -> Execution spec
 -> Evidence
 -> Verify
 -> 5J dry-run
```

No live network I/O.

### Stage 2 — B1 + B2

Add reviewed production address source and Mongo-backed persistence for authorization, evidence, ledger, audit, and sealed findings.

Still no live traffic.

### Stage 3 — B3 + controlled pilot

After sandbox/egress review, enable one tightly controlled execution class while keeping Nuclei/browser blocked initially.

## 22. Development rules

1. Recon only runs against authorized scope.
2. Unknown/out-of-scope data must not be persisted as normal program data.
3. Systemd setup scripts are the source of truth.
4. Do not manually replace scheduled unit files without a deliberate recovery/debugging reason.
5. LLM output is advisory; deterministic verification is authoritative.
6. Research Nuclei findings must not bypass 5J.
7. Do not repurpose legacy `XssFindings` as the authority store for the new finding pipeline.
8. Never commit secrets.
9. Keep live execution gates closed until B1/B2/B3 reviews are complete.

## 23. Validation status — September 2026

| Component | Status |
|---|---|
| Google VM migration | ✅ |
| Python environment | ✅ |
| Dependencies | ✅ |
| Docker/Compose | ✅ |
| Mongo restore | ✅ |
| Application → Mongo | ✅ |
| MongoDB Compass | ✅ |
| FastAPI API | ✅ |
| `watch-api.service` | ✅ |
| Go/toolchain | ✅ |
| Enumeration | ✅ |
| NS/DNS resolution | ✅ |
| HTTP scanning | ✅ |
| Crawl Fresh | ✅ |
| Crawl ALL | ✅ |
| Param Discovery | ✅ |
| Core timer configuration | ✅ |
| Heavy resource limits | ✅ |
| AI offline foundations | ✅ |
| AI live execution | 🔒 intentionally blocked |

## 24. Quick commands

```bash
cd /opt/watch
source venv/bin/activate

# API
sudo systemctl status watch-api.service
sudo systemctl restart watch-api.service

# timers
systemctl list-timers --all | grep watch

# Mongo
docker ps

# logs
ls -lah /opt/watch/logs/

# resource check
free -h
df -h
uptime
docker stats
```

## 25. Long-term architecture

```text
                    Programs / Scope
                           |
                           v
                    Recon Pipeline
              enum -> DNS -> HTTP -> crawl
                           |
                           v
                 Mongo / Endpoint Data
                           |
              +------------+------------+
              |                         |
              v                         v
        AI Research                Test Planning
      CVE / writeups             hypotheses/artifacts
              |                         |
              +------------+------------+
                           |
                           v
                    Authorization
                           |
                           v
                     Scope Gate
                           |
                           v
                 Controlled Executor
                           |
                           v
                    Evidence
                           |
                           v
             Deterministic Verification
                           |
                           v
                    Sealed Finding
                           |
                           v
                    API / Dashboard
```

The central principle is:

> **Recon discovers. Research analyzes. Authorization controls execution. Scope controls targets. Deterministic verification decides what is proven. Sealed findings are the authoritative output.**
