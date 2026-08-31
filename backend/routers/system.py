"""
backend/routers/system.py — Server resource stats (CPU/RAM/disk/load).

The endpoints are intentionally behind verify_api_key because /api/system/stats
returns info that helps an attacker profile the box (RAM size, disk usage
tells them how much local state is around). It would be a tiny lift to
exempt it, but for a single-user internal dashboard there is no reason to.
"""
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from backend.deps import verify_api_key
from backend.system_stats import collect

router = APIRouter()

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "web" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


@router.get("/api/system/stats", dependencies=[Depends(verify_api_key)],
            response_class=HTMLResponse)
def system_stats_html(request: Request):
    """HTML fragment for htmx polling on the dashboard."""
    s = collect()
    return templates.TemplateResponse(
        request,
        "_system_stats.html",
        {
            "cpu_label": _fmt_cpu(s.get("cpu_percent")),
            "ram_label": _fmt_ram_pct(s.get("ram_percent")),
            "ram_sub":   _fmt_ram_sub(s.get("ram_used_mb"), s.get("ram_total_mb")),
            "disk_label": _fmt_disk_pct(s.get("disk_percent")),
            "disk_sub":  _fmt_disk_sub(s.get("disk_used_gb"), s.get("disk_total_gb")),
            "load_label": _fmt_load(s.get("load_avg")),
        },
    )


@router.get("/api/system/stats.json", dependencies=[Depends(verify_api_key)])
def system_stats_json():
    """Raw JSON variant, kept for completeness."""
    return collect()


def _fmt_cpu(v):
    return f"{v:.0f}%" if v is not None else "n/a"


def _fmt_ram_pct(v):
    return f"{v:.0f}%" if v is not None else "n/a"


def _fmt_ram_sub(used_mb, total_mb):
    if used_mb is None or total_mb is None:
        return ""
    if total_mb >= 1024:
        return f"{used_mb/1024:.1f} / {total_mb/1024:.1f} GB"
    return f"{used_mb:.0f} / {total_mb:.0f} MB"


def _fmt_disk_pct(v):
    return f"{v:.0f}%" if v is not None else "n/a"


def _fmt_disk_sub(used_gb, total_gb):
    if used_gb is None or total_gb is None:
        return ""
    return f"{used_gb:.1f} / {total_gb:.1f} GB"


def _fmt_load(load):
    if not load:
        return "n/a"
    return ", ".join(f"{x:.2f}" for x in load)