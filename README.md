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
```

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
├── setup-weekly-jobs.sh         # installs the 5 weekly systemd timers
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
│   ├── watch_dns_precheck.py    # DNS bruteforce feasibility check
│   ├── watch_dns_static.py      # static wordlist DNS bruteforce
│   └── watch_dns_dynamic.py     # AlterX pattern-based DNS bruteforce
├── http/
│   ├── watch_http.py, watch_http_all.py
├── crawl/
│   ├── watch_crawl.py           # manual/heavy crawl (gospider), not scheduled
│   ├── watch_crawl_fresh.py     # light katana crawl of fresh HTTP results (12h pipeline)
│   ├── watch_crawl_all.py       # full katana crawl of ALL HTTP results (weekly)
│   ├── watch_param_discovery.py # x8 hidden parameter discovery (weekly)
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
Requires=watch.service

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

## 11. Weekly heavy jobs (crawl-all, param discovery, DNS bruteforce)

These don't fit in the 12h cycle — they're resumable (`--max-minutes` + least-recently-run
ordering) and run once a week each, in the server's free window.

**Free window on this server:** pipeline runs 00:00→~05:00 and 12:00→~17:00 Tehran, so free
time is 06:00→12:00 and 18:00→00:00. Jobs are scheduled at **06:00** with a 300-minute
(5h) budget, leaving a 1h buffer before the noon pipeline run.

| Day | Job | Purpose |
|---|---|---|
| Friday | `watch-dns-precheck` | Refresh wildcard feasibility per domain (cheap, 60 min budget) |
| Saturday | `watch-crawl-all` | Full katana crawl (incl. sitemaps) of every known HTTP target |
| Sunday | `watch-param-discovery` | x8 hidden parameter discovery on unique endpoints |
| Mon, Tue | `watch-dns-static` | Static wordlist DNS bruteforce |
| Wed, Thu | `watch-dns-dynamic` | AlterX pattern-based DNS bruteforce |

Install all five with the provided script:
```bash
bash setup-weekly-jobs.sh
systemctl list-timers --all | grep watch
```

The evening window (18:00-00:00) is intentionally left free for now — useful headroom once
you scale from 2-3 programs to the 10-12 you're planning for nuclei.

---

## 12. What each stage actually does

- **`watch_sync_programs.py`** — reads your program definitions (scope/out-of-scope) into
  `Programs`. Everything downstream checks against this.
- **`watch_enum_all.py`** — subdomain enumeration via subfinder, crt.sh, findomain,
  assetfinder, abuseipdb, waybackurls → `Subdomains`, tagged by provider.
- **`watch_ns_all.py`** — resolves subdomains with `dnsx`, filters wildcards
  (IP-subset cascading check via `wildcard_detector.py`) → `LiveSubdomains`.
- **`watch_http_all.py`** — `httpx` scan (title/status/tech/headers) on live subdomains →
  `Http`.
- **`watch_crawl_fresh.py`** *(every 12h)* — light `katana` crawl of just the last 24h of
  `Http` results (no sitemap fetch, capped at 5000 URLs/domain, 3-minute crawl ceiling) →
  `Urls` + `Endpoints`, scope-filtered, bulk-written.
- **`watch_crawl_all.py`** *(weekly)* — same, but on **every** `Http` result, including
  sitemap/robots.txt (`-kf all`), capped at 50000 URLs/domain. Resumable — picks up the
  least-recently-crawled domain first.
- **`watch_param_discovery.py`** *(weekly)* — runs `x8` on unique `Endpoints` (deduped by
  normalized path, so `/user/123` and `/user/456` are tested once), merges base
  (SecLists) + program-specific wordlist, writes results back + exports
  `/opt/watch/wordlists/{program}_params.txt`.
- **`watch_dns_precheck.py`** *(weekly, Friday)* — tests a random nonexistent subdomain per
  program domain; if it resolves, the domain has a blanket wildcard and bruteforcing it is
  pointless. Result stored in `DnsBruteStatus.feasible`.
- **`watch_dns_static.py`** *(weekly, Mon/Tue)* — merges assetnote wordlists + crunch
  (1-4 char) into candidates, resolves with `puredns` (its own wildcard filtering), stores
  new subdomains with provider `staticBF`, runs a quick `httpx` pass, sends Telegram.
- **`watch_dns_dynamic.py`** *(weekly, Wed/Thu)* — generates permutations from known
  subdomains with `alterx`, resolves with `puredns`, applies an *extra* TTL + HTTP-body-hash
  wildcard check on top, stores new subdomains with provider `dynamicBF`.
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

# param discovery, small test batch
python3 crawl/watch_param_discovery.py --filter dell.com --limit 10 --max-minutes 10
```

```bash
sudo systemctl status watch.timer
sudo systemctl status watch-api
systemctl list-timers --all | grep watch
sudo journalctl -u watch-api -n 50 --no-pager
```