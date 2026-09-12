#!/bin/bash

set -euo pipefail

SYSTEMD_DIR="/etc/systemd/system"

echo "=== Setting up Watch Core Pipeline ==="

# --------------------------------------------------
# watch.service
# --------------------------------------------------

sudo tee "${SYSTEMD_DIR}/watch.service" > /dev/null << 'UNIT'
[Unit]
Description=Watch Bug Bounty Core Pipeline
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/watch

# systemd runs the service with a minimal PATH and never sources ~/.zshrc, so
# the Go security tools must be exposed explicitly. This mirrors the heavy-job
# PATH added in setup-weekly-jobs.sh (commit bedff46) and includes the real
# install location /home/pouya_behnia/go/bin.
Environment="PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/home/pouya_behnia/go/bin:/usr/local/bin:/usr/bin:/bin"

# Core Pipeline and Heavy Jobs share the same lock.
# Never allow them to run at the same time.
ExecStart=/usr/bin/flock -n /run/watch-pipeline.lock /opt/watch/run-pipeline.sh

# Real hard runtime bound. RuntimeMaxSec= is IGNORED for Type=oneshot, so the
# supported mechanism is TimeoutStartSec=: for a oneshot service the start job
# is not complete until ExecStart exits, and systemd terminates the unit if that
# exceeds this value. Type=oneshot disables this timeout by default; 6h is
# longer than the 5.5h heavy-job ceiling and leaves ~18h before the next daily
# core run (00:00 Tehran).
TimeoutStartSec=6h

KillMode=control-group
TimeoutStopSec=30s
UNIT

# --------------------------------------------------
# watch.timer
# --------------------------------------------------

sudo tee "${SYSTEMD_DIR}/watch.timer" > /dev/null << 'UNIT'
[Unit]
Description=Run Watch Core Pipeline daily at 00:00 (Asia/Tehran)

[Timer]
Unit=watch.service

# EXACTLY 00:00 Tehran time (core pipeline / recon window 00:00-06:00).
# The 12:00-00:00 window belongs to AI/research; there is no 12:00 core trigger.
OnCalendar=*-*-* 00:00:00 Asia/Tehran

# Never execute a missed run after reboot.
Persistent=false

[Install]
WantedBy=timers.target
UNIT

# --------------------------------------------------
# Apply
# --------------------------------------------------

sudo systemctl daemon-reload

# The core service must NOT be enabled through multi-user.target.
# It may only be started by watch.timer.
sudo systemctl disable watch.service 2>/dev/null || true
sudo systemctl reset-failed watch.service 2>/dev/null || true

# Only the timer is enabled.
sudo systemctl enable watch.timer
sudo systemctl restart watch.timer

echo
echo "=== Core Pipeline setup complete ==="
echo
echo "Timer:"
systemctl list-timers --all | grep 'watch.timer' || true

echo
echo "Service:"
systemctl show watch.service \
    -p Type \
    -p User \
    -p Environment \
    -p ExecStart \
    -p KillMode \
    -p TimeoutStartUSec \
    -p RuntimeMaxUSec \
    -p TimeoutStopUSec

echo
echo "Enabled state:"
systemctl is-enabled watch.service 2>/dev/null || true
systemctl is-enabled watch.timer