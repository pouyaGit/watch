#!/bin/bash
# Sets up systemd services + timers for the heavy weekly jobs
# (crawl_all, param discovery, DNS bruteforce) -- separate from the 12h
# core pipeline (watch.timer), so they run in the server's free time
# without blocking enum/dns/http.
#
# Schedule (Tehran time, all at 06:00 -- right at the start of the free morning
# window (pipeline runs 00:00-~05:00 and 12:00-~17:00 Tehran, per benchmark), 1h buffer before the noon run):
#   Fri            watch-dns-precheck   (cheap, refreshes feasibility)
#   Sat            watch-crawl-all
#   Sun            watch-param-discovery
#   Mon, Tue       watch-dns-static
#   Wed, Thu       watch-dns-dynamic
#
# Each job is capped with --max-minutes so it stops cleanly before the
# next core pipeline run and resumes where it left off next time.

set -e

# ---------- watch-dns-precheck ----------
sudo tee /etc/systemd/system/watch-dns-precheck.service > /dev/null << 'UNIT'
[Unit]
Description=Watch DNS Bruteforce Feasibility Precheck
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Environment="PATH=/opt/watch/venv/bin"
ExecStart=/opt/watch/venv/bin/python3 /opt/watch/ns/watch_dns_precheck.py --max-minutes 60
UNIT

sudo tee /etc/systemd/system/watch-dns-precheck.timer > /dev/null << 'UNIT'
[Unit]
Description=Run DNS precheck weekly (Friday)

[Timer]
Unit=watch-dns-precheck.service
OnCalendar=Fri *-*-* 06:00:00 Asia/Tehran
Persistent=true
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
UNIT

# ---------- watch-crawl-all ----------
sudo tee /etc/systemd/system/watch-crawl-all.service > /dev/null << 'UNIT'
[Unit]
Description=Watch Full Crawl (all HTTP targets, not just fresh)
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Environment="PATH=/opt/watch/venv/bin"
ExecStart=/opt/watch/venv/bin/python3 /opt/watch/crawl/watch_crawl_all.py --max-minutes 300
UNIT

sudo tee /etc/systemd/system/watch-crawl-all.timer > /dev/null << 'UNIT'
[Unit]
Description=Run full crawl weekly (Saturday)

[Timer]
Unit=watch-crawl-all.service
OnCalendar=Sat *-*-* 06:00:00 Asia/Tehran
Persistent=true
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
UNIT

# ---------- watch-param-discovery ----------
sudo tee /etc/systemd/system/watch-param-discovery.service > /dev/null << 'UNIT'
[Unit]
Description=Watch Param Discovery (x8 on unique endpoints)
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Environment="PATH=/opt/watch/venv/bin"
ExecStart=/opt/watch/venv/bin/python3 /opt/watch/crawl/watch_param_discovery.py --max-minutes 300
UNIT

sudo tee /etc/systemd/system/watch-param-discovery.timer > /dev/null << 'UNIT'
[Unit]
Description=Run param discovery weekly (Sunday)

[Timer]
Unit=watch-param-discovery.service
OnCalendar=Sun *-*-* 06:00:00 Asia/Tehran
Persistent=true
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
UNIT

# ---------- watch-dns-static ----------
sudo tee /etc/systemd/system/watch-dns-static.service > /dev/null << 'UNIT'
[Unit]
Description=Watch DNS Static Bruteforce
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Environment="PATH=/opt/watch/venv/bin"
ExecStart=/opt/watch/venv/bin/python3 /opt/watch/ns/watch_dns_static.py --max-minutes 300
UNIT

sudo tee /etc/systemd/system/watch-dns-static.timer > /dev/null << 'UNIT'
[Unit]
Description=Run static DNS bruteforce (Monday and Tuesday)

[Timer]
OnCalendar=Mon,Tue *-*-* 06:00:00 Asia/Tehran
Persistent=true
RandomizedDelaySec=10min
Unit=watch-dns-static.service

[Install]
WantedBy=timers.target
UNIT

# ---------- watch-dns-dynamic ----------
sudo tee /etc/systemd/system/watch-dns-dynamic.service > /dev/null << 'UNIT'
[Unit]
Description=Watch DNS Dynamic Bruteforce
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch
Environment="PATH=/opt/watch/venv/bin"
ExecStart=/opt/watch/venv/bin/python3 /opt/watch/ns/watch_dns_dynamic.py --max-minutes 300
UNIT

sudo tee /etc/systemd/system/watch-dns-dynamic.timer > /dev/null << 'UNIT'
[Unit]
Description=Run dynamic DNS bruteforce (Wednesday and Thursday)

[Timer]
OnCalendar=Wed,Thu *-*-* 06:00:00 Asia/Tehran
Persistent=true
RandomizedDelaySec=10min
Unit=watch-dns-dynamic.service

[Install]
WantedBy=timers.target
UNIT

# ---------- apply ----------
sudo systemctl daemon-reload

for t in watch-dns-precheck watch-crawl-all watch-param-discovery watch-dns-static watch-dns-dynamic; do
    sudo systemctl enable --now "${t}.timer"
done

echo "Done. Check with: systemctl list-timers --all | grep watch"