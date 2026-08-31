#!/bin/bash

set -euo pipefail

SYSTEMD_DIR="/etc/systemd/system"

echo "=== Setting up Watch Heavy Weekly Jobs ==="

# ==================================================
# Resource slice
# ==================================================

sudo tee "${SYSTEMD_DIR}/watch-heavy.slice" > /dev/null << 'UNIT'
[Unit]
Description=Resource Limits for Watch Heavy Jobs

[Slice]
# VPS: 2 CPU cores
# Heavy workload may use at most ~60% of total CPU.
CPUQuota=60%

# VPS: 4 GB RAM
MemoryHigh=2500M
MemoryMax=3G

# Keep disk I/O low priority.
IOWeight=20

# Make these processes more likely to be selected by OOM
# than essential system services.
OOMScoreAdjust=500
UNIT

# ==================================================
# DNS PRECHECK - Friday
# ==================================================

sudo tee "${SYSTEMD_DIR}/watch-dns-precheck.service" > /dev/null << 'UNIT'
[Unit]
Description=Watch DNS Bruteforce Feasibility Precheck
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Slice=watch-heavy.slice

Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin"

ExecStart=/opt/watch/run-heavy-guarded.sh \
    /opt/watch/venv/bin/python3 \
    /opt/watch/ns/watch_dns_precheck.py \
    --max-minutes 60

RuntimeMaxSec=90min
KillMode=control-group
TimeoutStopSec=30s
UNIT

sudo tee "${SYSTEMD_DIR}/watch-dns-precheck.timer" > /dev/null << 'UNIT'
[Unit]
Description=Run Watch DNS Precheck every Friday at 06:00 Asia/Tehran

[Timer]
Unit=watch-dns-precheck.service
OnCalendar=Fri *-*-* 06:00:00 Asia/Tehran
Persistent=false

[Install]
WantedBy=timers.target
UNIT

# ==================================================
# CRAWL ALL - Saturday
# ==================================================

sudo tee "${SYSTEMD_DIR}/watch-crawl-all.service" > /dev/null << 'UNIT'
[Unit]
Description=Watch Full Crawl
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Slice=watch-heavy.slice

Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin"

ExecStart=/opt/watch/run-heavy-guarded.sh \
    /opt/watch/venv/bin/python3 \
    /opt/watch/crawl/watch_crawl_all.py \
    --max-minutes 300

# Hard upper bound.
RuntimeMaxSec=330min
KillMode=control-group
TimeoutStopSec=30s
UNIT

sudo tee "${SYSTEMD_DIR}/watch-crawl-all.timer" > /dev/null << 'UNIT'
[Unit]
Description=Run Watch Full Crawl every Saturday at 06:00 Asia/Tehran

[Timer]
Unit=watch-crawl-all.service
OnCalendar=Sat *-*-* 06:00:00 Asia/Tehran
Persistent=false

[Install]
WantedBy=timers.target
UNIT

# ==================================================
# PARAM DISCOVERY - Sunday
# ==================================================

sudo tee "${SYSTEMD_DIR}/watch-param-discovery.service" > /dev/null << 'UNIT'
[Unit]
Description=Watch Param Discovery
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Slice=watch-heavy.slice

Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin"

ExecStart=/opt/watch/run-heavy-guarded.sh \
    /opt/watch/venv/bin/python3 \
    /opt/watch/crawl/watch_param_discovery.py \
    --max-minutes 300

RuntimeMaxSec=330min
KillMode=control-group
TimeoutStopSec=30s
UNIT

sudo tee "${SYSTEMD_DIR}/watch-param-discovery.timer" > /dev/null << 'UNIT'
[Unit]
Description=Run Watch Param Discovery every Sunday at 06:00 Asia/Tehran

[Timer]
Unit=watch-param-discovery.service
OnCalendar=Sun *-*-* 06:00:00 Asia/Tehran
Persistent=false

[Install]
WantedBy=timers.target
UNIT

# ==================================================
# DNS STATIC - Monday + Tuesday
# ==================================================

sudo tee "${SYSTEMD_DIR}/watch-dns-static.service" > /dev/null << 'UNIT'
[Unit]
Description=Watch DNS Static Bruteforce
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Slice=watch-heavy.slice

Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin"

ExecStart=/opt/watch/run-heavy-guarded.sh \
    /opt/watch/venv/bin/python3 \
    /opt/watch/ns/watch_dns_static.py \
    --max-minutes 300

RuntimeMaxSec=330min
KillMode=control-group
TimeoutStopSec=30s
UNIT

sudo tee "${SYSTEMD_DIR}/watch-dns-static.timer" > /dev/null << 'UNIT'
[Unit]
Description=Run Watch DNS Static every Monday and Tuesday at 06:00 Asia/Tehran

[Timer]
Unit=watch-dns-static.service
OnCalendar=Mon,Tue *-*-* 06:00:00 Asia/Tehran
Persistent=false

[Install]
WantedBy=timers.target
UNIT

# ==================================================
# DNS DYNAMIC - Wednesday + Thursday
# ==================================================

sudo tee "${SYSTEMD_DIR}/watch-dns-dynamic.service" > /dev/null << 'UNIT'
[Unit]
Description=Watch DNS Dynamic Bruteforce
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Slice=watch-heavy.slice

Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin"

ExecStart=/opt/watch/run-heavy-guarded.sh \
    /opt/watch/venv/bin/python3 \
    /opt/watch/ns/watch_dns_dynamic.py \
    --max-minutes 300

RuntimeMaxSec=330min
KillMode=control-group
TimeoutStopSec=30s
UNIT

sudo tee "${SYSTEMD_DIR}/watch-dns-dynamic.timer" > /dev/null << 'UNIT'
[Unit]
Description=Run Watch DNS Dynamic every Wednesday and Thursday at 06:00 Asia/Tehran

[Timer]
Unit=watch-dns-dynamic.service
OnCalendar=Wed,Thu *-*-* 06:00:00 Asia/Tehran
Persistent=false

[Install]
WantedBy=timers.target
UNIT

# ==================================================
# Apply
# ==================================================

sudo systemctl daemon-reload

# Never allow an old running heavy job to survive setup.
for s in \
    watch-dns-precheck \
    watch-crawl-all \
    watch-param-discovery \
    watch-dns-static \
    watch-dns-dynamic
do
    sudo systemctl stop "$s.service" 2>/dev/null || true
    sudo systemctl disable "$s.service" 2>/dev/null || true
    sudo systemctl reset-failed "$s.service" 2>/dev/null || true
done

# Enable timers only.
for t in \
    watch-dns-precheck \
    watch-crawl-all \
    watch-param-discovery \
    watch-dns-static \
    watch-dns-dynamic
do
    sudo systemctl enable "${t}.timer"
    sudo systemctl restart "${t}.timer"
done

echo
echo "=== Heavy Jobs setup complete ==="
echo
systemctl list-timers --all | grep -E 'watch-(dns|crawl|param)'
