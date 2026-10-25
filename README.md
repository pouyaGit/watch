# Watch — Complete Setup & Reference Guide (updated)

This is the full, current version of the setup guide, covering everything added since the
original build: crawling + parameter discovery, DNS bruteforce (static + dynamic), the new
FastAPI dashboard, and weekly scheduling for the heavy jobs.

---

## 1. Initial server prep

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y curl git python3 python3-pip python3-venv build-essential \
    docker.io docker-compose-v2 unzip zsh tmux wget dnsutils crunch gzip

sudo systemctl enable --now docker
sudo usermod -aG docker $USER

chsh -s $(which zsh)
```

`dnsutils` gives you `dig` (used by the DNS precheck and wildcard detection).
`crunch` is used by the static DNS bruteforce wordlist generation.

**Log out and back in** (needed for the shell change and docker group).

---

## 2. Go + all tools

```bash
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

### Core recon (enum / dns / http)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install github.com/jaeles-project/gospider@latest
```

```bash
cd /tmp
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
```

### Crawling + parameter discovery
```bash
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/Sh1Yo/x8@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

`gau` feeds the crawl lane (archived URLs from wayback/commoncrawl/otx/urlscan). If it is
missing the crawl lane simply runs without it.

x8 needs a parameter-name wordlist. We use SecLists' `burp-parameter-names.txt`:
```bash
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```
The path `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` is the default
`watch_param_discovery.py` looks for. Override with `export X8_WORDLIST=/your/path.txt` if
you keep it somewhere else.

`/opt/watch/wordlists/` is created automatically by `watch_param_discovery.py` — it's where
the per-program combined wordlists (`burp list + fallparams-style extras + x8 discoveries`)
and the exported `{program}_params.txt` files end up.

### DNS bruteforce
```bash
# massdns (build from source -- no go install for this one)
sudo apt install -y libpcap-dev
git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
cd /tmp/massdns && make && sudo cp bin/massdns /usr/local/bin/
cd -

# puredns (resolver + wildcard filtering, wraps massdns)
go install github.com/d3mondev/puredns/v2@latest

# AlterX (pattern-based permutation generator -- replaces dnsgen/altdns, faster, same
# ProjectDiscovery family as dnsx/httpx/katana already installed)
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
```

You also need a **resolvers list** for puredns/dnsx. Save one to `/opt/watch/resolvers.txt`:
```bash
curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  -o /opt/watch/resolvers.txt
wc -l /opt/watch/resolvers.txt   # sanity check -- should be a few thousand lines
```

### Sanity check everything installed correctly
```bash
for bin in subfinder httpx dnsx assetfinder unfurl waybackurls gospider findomain \
           katana x8 massdns puredns alterx crunch dig; do
    command -v "$bin" >/dev/null 2>&1 && echo "OK   $bin" || echo "MISSING $bin"
done
```

---

## 3. Project folder

```bash
sudo mkdir -p /opt/watch
sudo chown $USER:$USER /opt/watch
cd /opt/watch
```

Put the project files here (clone or copy). Expected layout:

```
/opt/watch/
├── api.py                       # FastAPI dashboard + JSON API (replaces old Flask app.py)
├── config.py
├── run-pipeline.sh              # core 12h pipeline (sync/enum/dns/http/crawl-fresh)
├── watch_heavy_worker.py        # 24/7 heavy worker: serializes brute→crawl→param lanes
├── systemd/                     # all unit files (slice/service/timer); see §11c to install
├── resolvers.txt                # resolver list for puredns/dnsx
├── database/
│   └── db.py                    # all Mongo models + upsert/bulk-write helpers
├── utils/
│   └── common.py
├── programs/
│   └── watch_sync_programs.py
├── enum/
│   ├── watch_subfinder.py, watch_findomain.py, watch_crtsh.py,
│   ├── watch_abuseipdb.py, watch_wayback.py
│   └── watch_enum_all.py
├── ns/
│   ├── wildcard_detector.py
│   ├── watch_ns.py, watch_ns_all.py
│   ├── watch_dns_precheck.py    # DNS bruteforce feasibility check (weekly)
│   ├── watch_dns_static.py      # static wordlist DNS bruteforce (one domain)
│   ├── watch_dns_dynamic.py     # AlterX pattern-based DNS bruteforce (one domain)
│   └── watch_brute_worker.py    # brute lane: fair round-robin static+dynamic (run by watch_heavy_worker.py; also usable standalone)
├── http/
│   ├── watch_http.py, watch_http_all.py
├── crawl/
│   ├── watch_crawl.py           # manual/heavy crawl (gospider), not scheduled
│   ├── watch_crawl_fresh.py     # light katana crawl of fresh HTTP results (12h pipeline)
│   ├── watch_crawl_all.py       # full katana crawl of ALL HTTP results (heavy-worker crawl lane)
│   ├── watch_param_discovery.py # x8 hidden parameter discovery (heavy-worker param lane)
│   ├── migrate_urls_to_endpoints.py   # one-time migration script
│   ├── compact_endpoints.py           # one-time path-normalization cleanup
│   └── cleanup_unknown_scope.py       # one-time out-of-scope data cleanup
├── dns_brute_common.py          # shared helpers for the DNS bruteforce scripts
├── wordlists/                   # auto-created; per-program exported wordlists
└── logs/
```

---

## 4. Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate

pip install --break-system-packages \
    mongoengine pymongo python-telegram-bot tldextract python-dotenv requests \
    fastapi "uvicorn[standard]"
```

(`flask` is no longer needed — `api.py` replaced it with FastAPI. `psycopg2-binary` was in the
original guide but isn't actually used anywhere in this project; drop it unless you added
Postgres somewhere yourself.)

---

## 5. MongoDB

```bash
mkdir -p database

cat > database/docker-compose.yml << 'EOF'
services:
  mongo:
    image: mongo:latest
    container_name: mongo
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: pouya
      MONGO_INITDB_ROOT_PASSWORD: YourStrongPassword123
    volumes:
      - watchtower-data:/data/db
    restart: unless-stopped

volumes:
  watchtower-data:
EOF

cd database && docker compose up -d && cd ..
```

**Connection string for connecting from your laptop:**
```
mongodb://pouya:YourStrongPassword123@IP_SERVER:27017/
```

In `database/db.py`:
```python
# LOCAL
# connect(db='watch', host='mongodb://127.0.0.1:27017/watch')

# SERVER
connect(
    db='watch',
    host='mongodb://pouya:YourStrongPassword123@127.0.0.1:27017/watch?authSource=admin'
)
```

### Collections reference

| Collection | Written by | Purpose |
|---|---|---|
| `Programs` | `watch_sync_programs.py` | Scope + out-of-scope list per bug bounty program |
| `Subdomains` | enum scripts, DNS bruteforce | Every discovered subdomain name + which provider(s) found it |
| `LiveSubdomains` | `watch_ns_all.py`, DNS bruteforce | DNS-resolved subdomains with IP + CDN |
| `Http` | `watch_http_all.py`, DNS bruteforce | httpx results: title, status, tech, headers |
| `Urls` | `watch_crawl_fresh.py`, `watch_crawl_all.py` | Every crawled URL, deduped, with extracted query params |
| `Endpoints` | crawl scripts (via `db.py`) | Same URLs but deduped by **normalized path** (`/user/{id}`) — the target list for x8 |
| `ProgramParams` | (currently unused — fallparams was dropped) | Reserved for program-wide param wordlist enrichment |
| `DnsBruteStatus` | `watch_dns_precheck.py`, static/dynamic scripts | Per-domain wildcard feasibility + last-run timestamps (drives resumability) |

---

## 6. `.env`

```bash
cat > .env << 'EOF'
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
HTTPX_BIN=/root/go/bin/httpx
WATCH_DIR=/opt/watch
API_KEY=your_api_key_here
EOF
```

Generate a strong `API_KEY`:
```bash
openssl rand -hex 32
```
This protects `api.py` (the dashboard/API) — without it, anyone who finds your server's IP
can browse your entire recon (scope, subdomains, endpoints, discovered params).

---

## 7. `.zshrc` aliases

```bash
nano ~/.zshrc
```

```bash
# ====================== Watch ======================
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export WATCH_DIR=/opt/watch

alias watch_sync_programs="python3 /opt/watch/programs/watch_sync_programs.py"
alias watch_subfinder="python3 /opt/watch/enum/watch_subfinder.py"
alias watch_findomain="python3 /opt/watch/enum/watch_findomain.py"
alias watch_crtsh="python3 /opt/watch/enum/watch_crtsh.py"
alias watch_abuseipdb="python3 /opt/watch/enum/watch_abuseipdb.py"
alias watch_wayback="python3 /opt/watch/enum/watch_wayback.py"
alias watch_enum_all="python3 /opt/watch/enum/watch_enum_all.py"

alias watch_ns="python3 /opt/watch/ns/watch_ns.py"
alias watch_ns_all="python3 /opt/watch/ns/watch_ns_all.py"
alias watch_dns_precheck="python3 /opt/watch/ns/watch_dns_precheck.py"
alias watch_dns_static="python3 /opt/watch/ns/watch_dns_static.py"
alias watch_dns_dynamic="python3 /opt/watch/ns/watch_dns_dynamic.py"

alias watch_http="python3 /opt/watch/http/watch_http.py"
alias watch_http_all="python3 /opt/watch/http/watch_http_all.py"

alias watch_crawl="python3 /opt/watch/crawl/watch_crawl.py"
alias watch_crawl_fresh="python3 /opt/watch/crawl/watch_crawl_fresh.py"
alias watch_crawl_all="python3 /opt/watch/crawl/watch_crawl_all.py"
alias watch_param_discovery="python3 /opt/watch/crawl/watch_param_discovery.py"

echo "✅ Watch aliases loaded"
```

```bash
source ~/.zshrc
```

---

## 8. Security notes

- `-threads 12 -rate-limit 15` (or similar conservative values) for `watch_http.py` to
  avoid abuse complaints — already the default in this project.
- `api.py` runs on FastAPI with API-key auth (see §6) — never expose it publicly without
  `API_KEY` set.
- Crawl scripts (`watch_crawl_fresh.py` / `watch_crawl_all.py`) drop any host not already
  found via your own `Http` collection — this keeps third-party links (analytics, CDNs,
  unrelated news sites picked up from JS) out of your scope data entirely.
- If you open port 5000 to the internet (to browse the dashboard from your laptop), also
  open it in your cloud provider's firewall panel — `ufw` alone isn't enough on most VPS
  providers.

---

## 9. `run-pipeline.sh` (core 12h pipeline)

```bash
cat > /opt/watch/run-pipeline.sh << 'EOF'
#!/bin/bash

cd /opt/watch
source ~/.zshrc
source venv/bin/activate

set -a
[ -f .env ] && source .env
set +a

LOG_DIR="/opt/watch/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/pipeline_$TIMESTAMP.log"
exec > >(tee -a "$LOG_FILE") 2>&1

send_telegram() {
    local text="$1"
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    [ -z "$TELEGRAM_CHAT_ID" ] && return
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" --data-urlencode "text=${text}" > /dev/null
}

step() {
    local NAME="$1"; shift
    echo; echo "===== $NAME ====="
    send_telegram "Pipeline: starting $NAME"
    local START=$(date +%s)
    "$@"
    local EXIT_CODE=$?
    local DURATION=$(( $(date +%s) - START ))
    echo "===== $NAME Finished in ${DURATION} sec (exit: $EXIT_CODE) ====="
    if [ $EXIT_CODE -eq 0 ]; then
        send_telegram "Pipeline: $NAME finished in ${DURATION}s"
    else
        send_telegram "Pipeline: $NAME FAILED (exit $EXIT_CODE) after ${DURATION}s -- check logs"
    fi
    return $EXIT_CODE
}

TOTAL_START=$(date +%s)
send_telegram "Pipeline run started -- $(TZ=Asia/Tehran date)"

step "Sync Programs"   python3 programs/watch_sync_programs.py
step "Enumeration"     python3 enum/watch_enum_all.py
step "DNS Resolution"  python3 ns/watch_ns_all.py
step "HTTP Scanning"   python3 http/watch_http_all.py
step "Crawl Fresh"     python3 /opt/watch/crawl/watch_crawl_fresh.py

TOTAL_DURATION=$(( $(date +%s) - TOTAL_START ))
echo "Pipeline finished in ${TOTAL_DURATION}s"
send_telegram "Pipeline run finished in ${TOTAL_DURATION}s total -- $(TZ=Asia/Tehran date)"
EOF

chmod +x run-pipeline.sh {programs,enum,ns,http,crawl}/*.py
```

Runs every 12h (00:00 / 12:00 Tehran), takes ~4-5 hours per the benchmarked server load.
Sends a Telegram message before/after every step.

---

## 10. Core systemd timer (12h pipeline + API)

```bash
sudo tee /etc/systemd/system/watch.service > /dev/null << 'EOF'
[Unit]
Description=Watch Bug Bounty Pipeline Service
After=network.target docker.service
Wants=watch.timer

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
ExecStart=/opt/watch/run-pipeline.sh

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/watch.timer > /dev/null << 'EOF'
[Unit]
Description=Run Watch Pipeline every 12 hours (Iran Time)
# Do NOT add Requires=watch.service: the timer triggers the service via Unit=
# below, and a Requires= would make systemd stop the timer whenever the service
# is stopped (e.g. a manual `systemctl stop watch.service` to kill a stuck run),
# silently deactivating the schedule so the next 00:00/12:00 fire is skipped.

[Timer]
Unit=watch.service
OnCalendar=*-*-* 00:00:00 Asia/Tehran
OnCalendar=*-*-* 12:00:00 Asia/Tehran
Persistent=true
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
EOF

sudo tee /etc/systemd/system/watch-api.service > /dev/null << 'EOF'
[Unit]
Description=Watch Fast API
After=network.target docker.service

[Service]
User=root
WorkingDirectory=/opt/watch
Environment="PATH=/opt/watch/venv/bin"
ExecStart=/opt/watch/venv/bin/python3 /opt/watch/api.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now watch.timer
sudo systemctl enable watch.service
sudo systemctl enable --now watch-api
```

---

## 11. Weekly jobs (`watch-dns-precheck` only)

The only remaining weekly timer is the DNS-bruteforce feasibility precheck. The
heavy work (bruteforce, crawl, param discovery, nuclei) now runs continuously in
one serialized worker — see section 11b.

| Day | Job | Purpose |
|---|---|---|
| Friday | `watch-dns-precheck` | Refresh wildcard feasibility per domain (cheap, 60 min budget) — marks which domains the brute lane is *eligible* to run on. |

There is no setup script. Every unit ships as a file under `systemd/`; install
and enable the ones you need (see **section 11c** for the full fresh-install
list). The precheck timer specifically:
```bash
sudo cp /opt/watch/systemd/watch-dns-precheck.service /opt/watch/systemd/watch-dns-precheck.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now watch-dns-precheck.timer
systemctl list-timers --all | grep watch
```

> **Crawl, param discovery and DNS bruteforce are no longer separate timers** —
> they are lanes of the continuous `watch-heavy.service` (section 11b). The old
> per-lane units (`watch-crawl-all`, `watch-param-discovery`, `watch-dns-static`,
> `watch-dns-dynamic`, `watch-brute`) are retired; do not install or enable them.

---

## 11b. Continuous heavy worker (`watch-heavy.service`)

All heavy, long-running work runs in **one always-on, single-threaded worker**
(`watch_heavy_worker.py`) that time-slices its lanes **one at a time**,
round-robin, forever:

```
brute  →  crawl  →  param  →  nuclei  →  brute  → …   (each lane gets WATCH_HEAVY_LANE_MINUTES, then rotate)
```

Each lane is driven by its existing, resumable script, so a lane always resumes
where it left off and none starves the others:

| Lane | Script | What it does |
|---|---|---|
| `brute` | `ns/watch_brute_worker.py --max-minutes N` | Fair round-robin over **feasible** domains (marked by `watch_dns_precheck.py`); for each, **static then dynamic**. Marks each domain at the *start* of its turn so a slow/crashing domain can't starve the rest. |
| `crawl` | `crawl/watch_crawl_all.py --max-minutes N` | katana crawl of known HTTP targets, least-recently-crawled first, seeded with gau archived URLs (in-scope only). Reads targets **straight from MongoDB** (no dependency on the dashboard API). gau-only URLs are stored in `Urls` only. |
| `param` | `crawl/watch_param_discovery.py --max-minutes N` | x8 hidden-parameter discovery on unique endpoints, unchecked first, at a polite rate. |
| `nuclei` | `nuclei/watch_nuclei_run.py --max-minutes N` | Subdomain-takeover pass, then nuclei templates on `Http` hosts, grouped by tech. Findings go to `Finding`. |
| `secret` *(opt-in)* | `secret/watch_secret_run.py --max-minutes N` | Fetches in-scope `.js` URLs from `Urls` and scans them for secrets. Only redacted matches are stored. |
| `ffuf` *(opt-in)* | `content/watch_ffuf_run.py --max-minutes N` | Bounded content discovery on in-scope `Http` hosts with a small wordlist. Sensitive paths become `Finding`s. |

`secret` and `ffuf` are **not** in the default lane list. Enable them by adding them to
`WATCH_HEAVY_LANES` in `watch-heavy.service` (see the settings table below).

**Why one worker instead of three 24/7 services:** the VPS is small (2 cores /
4 GB) and param discovery is *active scanning*. Serializing keeps exactly one
heavy job running at any moment — bounding CPU/RAM/IO (via `watch-heavy.slice`)
and the outbound scan footprint — while still making continuous progress on
every lane.

### Settings (environment variables)

Set these in the `[Service]` block of `/etc/systemd/system/watch-heavy.service`
(as `Environment=KEY=value`) or export them before a manual run. All optional.

| Variable | Default | Meaning |
|---|---|---|
| `WATCH_HEAVY_LANE_MINUTES` | `20` | Per-lane time slice before rotating to the next lane. |
| `WATCH_HEAVY_IDLE_SLEEP` | `900` | Seconds to sleep when a whole cycle found nothing to do anywhere. |
| `WATCH_HEAVY_LANES` | `brute,crawl,nuclei` | Restrict/reorder lanes, e.g. `brute,crawl`. Add `secret,ffuf` to enable the opt-in lanes. Param runs in `watch-param.service`. |
| `WATCH_BRUTE_COOLDOWN_HOURS` | `12` | Min hours before the same domain is bruteforced again (brute lane). |
| `WATCH_STATIC_MAX_CANDIDATES` | `0` (unlimited) | Cap static candidates per domain (`0` = full wordlist; e.g. `200000` for a fast test). |
| `WATCH_BRUTE_VERBOSE` | `0` | `1` restores chatty per-domain "Now bruteforcing…" Telegram banners. Off = only findings, errors, per-cycle heartbeat. |
| `WATCH_DYNAMIC_MAX_INPUT_LINES` | derived | Per-domain ceiling on known subdomains fed to alterx. |
| `X8_WORDLIST` | seclists burp-parameter-names | Param-discovery wordlist (param lane). |
| `GAU_ENABLED` | `1` | `0` disables gau in the crawl lane. |
| `GAU_MAX_SEEDS` | `20000` | Cap on gau URLs fed to katana per domain. |
| `GAU_TIMEOUT` | `300` | gau time budget in seconds; clamped to the remaining lane minutes. |
| `NUCLEI_BATCH_SIZE` | `200` | Hosts per nuclei batch. |
| `NUCLEI_CONCURRENCY` | `10` | nuclei `-c`. |
| `NUCLEI_RATE_LIMIT` | `50` | nuclei `-rl`. |
| `NUCLEI_GROUP_TIMEOUT` | `900` | Hard timeout per nuclei invocation, seconds. |
| `NUCLEI_RESCAN_DAYS` | `7` | Days before a host is re-scanned. |
| `NUCLEI_TAKEOVER_BATCH` | `500` | Subdomains per takeover pass. |
| `SECRET_BATCH` | `300` | URLs per secret-lane run. |
| `SECRET_MAX_BYTES` | `2000000` | Per-file download cap. Larger bodies are cut off. |
| `SECRET_DELAY_MS` | `200` | Pause between fetches. |
| `SECRET_RESCAN_DAYS` | `30` | Days before a URL is scanned again. |
| `SECRET_TIMEOUT` | `10` | Per-request timeout, seconds. |
| `FFUF_BATCH_HOSTS` | `20` | Hosts per ffuf run. |
| `FFUF_HOST_TIMEOUT` | `240` | Hard timeout per host, seconds. |
| `FFUF_RATE` | `10` | ffuf requests per second. |
| `FFUF_THREADS` | `4` | ffuf threads. |
| `FFUF_RESCAN_DAYS` | `14` | Days before a host is fuzzed again. |
| `FFUF_WORDLIST` | `wordlists/watch_content_small.txt` | Content-discovery wordlist. |

Resource limits come from **`watch-heavy.slice`** (`systemd/watch-heavy.slice`):
`CPUQuota=60%`, `MemoryMax=3G`, `MemoryHigh=2500M`, `IOWeight=20`. Install the
slice before the service.

### Start / stop / status

```bash
# the slice must exist first (resource caps):
sudo cp /opt/watch/systemd/watch-heavy.slice /opt/watch/systemd/watch-heavy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now watch-heavy.service

systemctl status watch-heavy.service
journalctl -u watch-heavy.service -f      # watch it rotate brute → crawl → param → nuclei

sudo systemctl restart watch-heavy.service   # after editing settings (e.g. WATCH_HEAVY_LANES)
```

### 11c. Fresh install — all systemd units

There is no setup script; every unit is a file under `systemd/`. On a new box:

```bash
sudo cp /opt/watch/systemd/watch-heavy.slice \
        /opt/watch/systemd/watch-heavy.service \
        /opt/watch/systemd/watch-ct-stream.service \
        /opt/watch/systemd/watch.service \
        /opt/watch/systemd/watch-dns-precheck.service /opt/watch/systemd/watch-dns-precheck.timer \
        /opt/watch/systemd/watch-health.service      /opt/watch/systemd/watch-health.timer \
        /opt/watch/systemd/watch-digest.service      /opt/watch/systemd/watch-digest.timer \
        /opt/watch/systemd/watch-maintenance.service /opt/watch/systemd/watch-maintenance.timer \
        /etc/systemd/system/
sudo systemctl daemon-reload
# always-on services:
sudo systemctl enable --now watch-heavy.service watch-ct-stream.service watch-api.service
# timers:
sudo systemctl enable --now watch.timer watch-dns-precheck.timer \
        watch-health.timer watch-digest.timer watch-maintenance.timer
# gau (crawl lane): 
go install github.com/lc/gau/v2/cmd/gau@latest
```

(`watch.timer` and `watch-api.service` are documented in sections 10 and 13.
The retired per-lane units — `watch-brute`, `watch-crawl-all`, `watch-crawl`,
`watch-param-discovery`, `watch-dns-static`, `watch-dns-dynamic` — must NOT be
installed.)

Quick manual test (one bounded cycle, no 24/7):
```bash
cd /opt/watch && python3 watch_heavy_worker.py --once --lane-minutes 5
```

Prerequisites: run `watch_dns_precheck.py` at least once (so the brute lane has
feasible domains), and make sure the brute/crawl/param tools are installed
(`puredns`, `dnsx`, `alterx`, `katana`, `x8`) — see sections 2 and 2·DNS.

> **Standalone brute service retired.** The old `watch-brute.service` (continuous
> brute only) is replaced by `watch-heavy.service`. If upgrading:
> `sudo systemctl disable --now watch-brute.service`.

---

## 12. What each stage actually does

- **`watch_sync_programs.py`** — reads your program definitions (scope/out-of-scope) into
  `Programs`. Everything downstream checks against this.
- **`watch_enum_all.py`** — subdomain enumeration via subfinder, crt.sh, findomain,
  assetfinder, abuseipdb, waybackurls → `Subdomains`, tagged by provider.
- **`watch_ns_all.py`** — resolves subdomains with `dnsx`, filters wildcards
  (IP-subset cascading check via `wildcard_detector.py`) → `LiveSubdomains`.
  Resolve tuning is env-overridable (defaults in parentheses): `NS_DNSX_THREADS`
  (50), `NS_DNSX_RATE_LIMIT` (150 queries/sec), `NS_DNSX_RESOLVERS` (the four
  reliable public anycast resolvers). The default resolver set is deliberately
  *not* the full `resolvers.txt` — dnsx has no trusted/untrusted split like
  puredns, so a big untrusted list trades answer accuracy for speed; throughput
  is raised via rate + threads on known-good resolvers instead. The biggest win
  is on large rate-bound scopes (e.g. a 206k-name scope: ~115 min at the old
  `-rl 30` → ~23 min at `-rl 150`); small scopes are DNS-latency-bound and change
  little. Wildcard probes use the plain batch resolver, not the incremental
  selector.
- **`watch_http_all.py`** — `httpx` scan (title/status/tech/headers) on live subdomains →
  `Http`.
- **`watch_crawl_fresh.py`** *(every 12h)* — light `katana` crawl of just the last 24h of
  `Http` results (no sitemap fetch, capped at 5000 URLs/domain, 3-minute crawl ceiling) →
  `Urls` + `Endpoints`, scope-filtered, bulk-written.
- **`watch_crawl_all.py`** *(heavy-worker crawl lane)* — same, but on **every** `Http`
  result, including sitemap/robots.txt (`-kf all`), capped at 50000 URLs/domain. Resumable —
  picks up the least-recently-crawled domain first. Reads its target list straight from
  MongoDB (`Http.url`), not the auth-gated `/api/http/all` route.
- **`watch_param_discovery.py`** *(heavy-worker param lane)* — runs `x8` on unique
  `Endpoints` (deduped by normalized path, so `/user/123` and `/user/456` are tested once),
  merges base (SecLists) + program-specific wordlist, writes results back + exports
  `/opt/watch/wordlists/{program}_params.txt`.
- **`watch_dns_precheck.py`** *(weekly, Friday)* — tests a random nonexistent subdomain per
  program domain; if it resolves, the domain has a blanket wildcard and bruteforcing it is
  pointless. Result stored in `DnsBruteStatus.feasible`.
- **`watch_dns_static.py`** *(driven by the continuous worker; also runnable standalone
  per-domain)* — merges assetnote wordlists + crunch (1-4 char) into candidates, resolves
  with `puredns` (its own wildcard filtering), stores new subdomains with provider
  `staticBF`, runs a quick `httpx` pass. Honours `WATCH_STATIC_MAX_CANDIDATES`.
- **`watch_dns_dynamic.py`** *(driven by the continuous worker; also runnable standalone)* —
  generates permutations from known subdomains with `alterx`, resolves with `puredns`,
  filters wildcards with the shared multi-level `WildcardDetector`, stores new subdomains
  with provider `dynamicBF`.
- **`watch_brute_worker.py`** *(the `watch-brute.service` long-running process)* — the 24/7
  orchestrator: round-robins feasible domains, marks each at the start of its turn (fair, no
  starvation), runs static then dynamic per domain, sleeps until the oldest is eligible
  again. See section 11b for settings. Note: wildcard probes use the plain batch resolver,
  not the incremental selector — the selector is only for the bulk scope resolve in
  `watch_ns_all.py`, so a single random probe no longer costs a full selection cycle.
- **`watch_nuclei_run.py`** *(heavy-worker nuclei lane)* — subdomain-takeover pass on
  `Subdomains`, then nuclei on `Http` hosts grouped by technology. Each finding is upserted
  into `Finding` (deduped on target + name); only new medium+ findings alert.
- **`watch_secret_run.py`** *(opt-in secret lane)* — fetches in-scope `.js` URLs (no
  redirects followed, streamed size cap), runs regex rules (AWS keys, Slack/Stripe tokens,
  Google API keys, private key blocks, JWTs, generic secret assignments) and stores only
  redacted matches in `Finding`. Out-of-scope URLs are marked and never fetched.
- **`watch_ffuf_run.py`** *(opt-in ffuf lane)* — ffuf with `-ac` and a status filter on
  in-scope `Http` hosts. Output is written only at exit, so each run is capped below the
  host timeout to keep partial results. Sensitive paths (`.env`, `.git/config`, backups,
  actuator, admin, ...) are `medium`; everything else is `info`.
- **`scripts/watch_health.py`** *(watch-health timer)* — checks the systemd units in
  `WATCH_HEALTH_UNITS`, MongoDB ping and optional `WATCH_HEALTH_URLS`. Alerts once when a
  check goes down and once when it recovers.
- **`scripts/watch_digest.py`** *(watch-digest timer)* — one Telegram summary per day with
  new subdomains, live hosts, HTTP services and findings by severity, per program.
- **`scripts/watch_maintenance.py`** *(watch-maintenance timer)* — prunes `Urls` not seen
  within `URLS_RETENTION_MONTHS` and trims `ChangeEvent` to `CHANGE_EVENTS_MAX` rows.
- **`api.py`** — FastAPI dashboard + JSON API, described below.

---

## 13. The dashboard (`api.py`)

Visit `http://YOUR_SERVER_IP:5000/?api_key=YOUR_KEY` once (the key gets carried in every
link on the page after that — no need to keep typing it).

- **Fresh HTTP banner** at the top — last-24h `Http` results, one click away.
- **One card per program**, with:
  - Counts + links: Subdomains, Live, HTTP, URLs, Endpoints, Wordlist (plain-text download)
  - **Technology badges** (from `Http.tech`) — click one to filter HTTP results by tech
  - **Provider badges** — `staticBF`/`dynamicBF` shown first with a distinct orange
    "🔥" style since those are the highest-value finds (things nobody else found via
    normal enumeration); the rest (subfinder, crtsh, etc.) shown as regular gray badges
- All list pages are paginated (`?page=`/`?limit=`).
- **`/docs`** — full interactive Swagger UI, exempt from the API-key check so it always
  loads; use the 🔒 **Authorize** button once to test authenticated endpoints from there.
- **`/api/stats/by-program`** — raw JSON counts per program per collection, all
  server-side `count()` — no more loading entire collections into Python just to count them.

Run it:
```bash
python3 api.py
# or via systemd: sudo systemctl restart watch-api
```

---

## 14. One-time maintenance scripts (already run once, kept for reference)

- **`migrate_urls_to_endpoints.py`** — backfilled `Endpoints` from existing `Urls` data.
- **`compact_endpoints.py`** — collapsed path-with-numeric-ID duplicates
  (`/user/123` → `/user/{id}`) after discovering the endpoint count had exploded to 596k.
- **`cleanup_unknown_scope.py`** — removed out-of-scope/third-party URLs that leaked in
  before the scope filter was added to the crawl scripts.

You shouldn't need these again unless something similar happens — but they're safe to
re-run if it does.

---

## 15. Manual testing (recommended before trusting a new schedule)

```bash
# full pipeline
/opt/watch/run-pipeline.sh

# just one stage
python3 http/watch_http_all.py

# crawl, filtered to one domain, time-boxed
python3 crawl/watch_crawl_fresh.py --filter dell.com

# DNS bruteforce feasibility + one bruteforce type, filtered + time-boxed
python3 ns/watch_dns_precheck.py --filter dell.com --max-minutes 10
python3 ns/watch_dns_static.py --filter dell.com --max-minutes 30

# continuous brute worker: one fast pass over all eligible domains (test), then exit.
# cap static candidates and ignore cooldown so it actually runs every domain once.
WATCH_STATIC_MAX_CANDIDATES=200000 python3 ns/watch_brute_worker.py --once --cooldown-hours 0
# ...or scope it to one program and keep Telegram quiet during the test:
WATCH_STATIC_MAX_CANDIDATES=200000 TELEGRAM_BOT_TOKEN= TELEGRAM_CHAT_ID= \
  python3 ns/watch_brute_worker.py --once --filter indeed --cooldown-hours 0

# param discovery, small test batch
python3 crawl/watch_param_discovery.py --filter dell.com --limit 10 --max-minutes 10
```

```bash
sudo systemctl status watch.timer
sudo systemctl status watch-api
systemctl list-timers --all | grep watch
sudo journalctl -u watch-api -n 50 --no-pager
```

---

## 16. Recon expansion: health, digest, retention, scope rules

**Scope and tooling rules that apply to every component**

- Every external call is checked against the program's scope *and* out-of-scope list
  before it is made (`utils/recon.py` → `in_scope`, `scope_index`).
- Every external tool runs through `run_tool()`: argv list, no `shell=True`, a hard
  `timeout -k` wrapper, and partial output is kept when the timeout fires.
- **No port scanning.** naabu and any other port scanner are not installed or called.
- `asnmap` is **deferred**: it is optional in the spec and not installed on this host.
- `trufflehog` is **not installed**. The secret lane uses its own regex rules instead.
- The new web UI (`/ui/findings`) sits behind the same auth middleware as the rest of the dashboard.

**Timers**

| Timer | When | Unit | What it does |
|---|---|---|---|
| `watch-health.timer` | every 10 min | `watch-health.service` | Unit, MongoDB and URL checks; alerts on DOWN and RECOVERED transitions only |
| `watch-digest.timer` | daily 09:00 Asia/Tehran | `watch-digest.service` | One summary message; skipped if one was sent in the last 20 h |
| `watch-maintenance.timer` | Sunday 04:00 Asia/Tehran | `watch-maintenance.service` | Prunes old `Urls`, trims `ChangeEvent`, ensures indexes |

Install:
```bash
sudo cp /opt/watch/systemd/watch-health.service      /opt/watch/systemd/watch-health.timer \
        /opt/watch/systemd/watch-digest.service      /opt/watch/systemd/watch-digest.timer \
        /opt/watch/systemd/watch-maintenance.service /opt/watch/systemd/watch-maintenance.timer \
        /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now watch-health.timer watch-digest.timer watch-maintenance.timer
systemctl list-timers --all | grep -E 'watch-(health|digest|maintenance)'
```

**Lane selection**

Default `WATCH_HEAVY_LANES=brute,crawl,nuclei,secret` (the `secret` JS-scan
lane is enabled). `param` runs in its own `watch-param.service`, not in the heavy rotation. `ffuf` (aggressive content discovery) is left OFF; add it to
`WATCH_HEAVY_LANES` in `/etc/systemd/system/watch-heavy.service` only if you want
it, then `sudo systemctl daemon-reload && sudo systemctl restart watch-heavy.service`.

**Health settings**

| Variable | Default | Meaning |
|---|---|---|
| `WATCH_HEALTH_UNITS` | `watch-heavy.service,watch-ct-stream.service,watch.timer` | Units checked with `systemctl is-active`. |
| `WATCH_HEALTH_URLS` | empty | Comma list of URLs. Only non-5xx responses count as healthy. |
| `WATCH_HEALTH_TIMEOUT` | `10` | Per-check timeout, seconds. |
| `WATCH_HEALTH_STATE` | `logs/health_state.json` | Transition state. |

**Digest settings:** `WATCH_DIGEST_WINDOW_HOURS` (24, used only when there is no previous run),
`WATCH_DIGEST_STATE` (`logs/digest_state.json`). The state advances only after Telegram accepts
the message, so a failed send is retried on the next run.

**Retention settings:** `URLS_RETENTION_MONTHS` (12), `CHANGE_EVENTS_MAX` (200000),
`MAINTENANCE_BATCH` (5000). Run the script without `--apply` to see what would be removed.

```bash
python3 scripts/watch_health.py --dry-run
python3 scripts/watch_digest.py --dry-run
python3 scripts/watch_maintenance.py          # dry run; add --apply to delete
```

**Indexes** added for the dashboard and digest queries: `Subdomains.scope`, `Subdomains.providers`,
`Subdomains.created_date`, `Http.created_date`, `LiveSubdomains.created_date`. `ensure_indexes`
runs with `watch_maintenance.py --ensure-indexes` (the weekly timer does this).