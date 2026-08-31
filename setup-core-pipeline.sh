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

# Core Pipeline and Heavy Jobs share the same lock.
# Never allow them to run at the same time.
ExecStart=/usr/bin/flock -n /run/watch-pipeline.lock /opt/watch/run-pipeline.sh

KillMode=control-group
TimeoutStopSec=30s
UNIT

# --------------------------------------------------
# watch.timer
# --------------------------------------------------

sudo tee "${SYSTEMD_DIR}/watch.timer" > /dev/null << 'UNIT'
[Unit]
Description=Run Watch Core Pipeline every 12 hours (Asia/Tehran)

[Timer]
Unit=watch.service

# EXACTLY 00:00 and 12:00 Tehran time.
OnCalendar=*-*-* 00:00:00 Asia/Tehran
OnCalendar=*-*-* 12:00:00 Asia/Tehran

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
    -p ExecStart \
    -p KillMode \
    -p TimeoutStopUSec

echo
echo "Enabled state:"
systemctl is-enabled watch.service 2>/dev/null || true
systemctl is-enabled watch.timer