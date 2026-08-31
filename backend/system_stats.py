"""
backend/system_stats.py — CPU / RAM / disk / load collectors for the dashboard.

psutil.cpu_percent(interval=...) BLOCKS for the interval. We use a tiny
interval (0.3s) so the dashboard doesn't feel laggy on each htmx poll;
for a serious system monitor you'd want to keep a singleton sampler
running in the background, but that's overkill for a single-user dashboard.

Failures are swallowed per-metric and returned as None so a transient
psutil hiccup doesn't take down the whole /api/system/stats response.
"""
import os

import psutil


def _gb(n):
    return round(n / (1024 ** 3), 2)


def _mb(n):
    return round(n / (1024 ** 2), 1)


def collect():
    out = {
        "cpu_percent": None,
        "ram_used_mb": None,
        "ram_total_mb": None,
        "ram_percent": None,
        "disk_used_gb": None,
        "disk_total_gb": None,
        "disk_percent": None,
        "load_avg": None,
    }

    try:
        out["cpu_percent"] = psutil.cpu_percent(interval=0.3)
    except Exception:
        pass

    try:
        vm = psutil.virtual_memory()
        out["ram_used_mb"] = _mb(vm.used)
        out["ram_total_mb"] = _mb(vm.total)
        out["ram_percent"] = vm.percent
    except Exception:
        pass

    try:
        target = "/opt/watch"
        if not os.path.exists(target):
            target = "/"
        du = psutil.disk_usage(target)
        out["disk_used_gb"] = _gb(du.used)
        out["disk_total_gb"] = _gb(du.total)
        out["disk_percent"] = du.percent
    except Exception:
        pass

    try:
        out["load_avg"] = list(os.getloadavg())
    except Exception:
        # getloadavg() is not available on Windows; harmless on Linux.
        pass

    return out