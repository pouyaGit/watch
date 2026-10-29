"""Starter workers — GET-only DNS + HTTP. No port scan, no fuzz, no exploit."""
import re, subprocess, urllib.request, urllib.error
UA = {"User-Agent": "hermes-recon-safe/1.0 (low-impact GET only)"}
MAX_BODY = 200_000
SKIP_PATH = re.compile(r"/(logout|delete|remove|update|deactivate)", re.I)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
def dns_records(host):
    out = {}
    for rt in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA"):
        try:
            p = subprocess.run(["dig", "+short", "+time=3", "+tries=1", host, rt], capture_output=True, text=True, timeout=10)
            out[rt] = sorted(l.strip() for l in p.stdout.splitlines() if l.strip())[:10]
        except Exception:
            out[rt] = []
    return out
def http_check(host, limiter=None, target=""):
    if limiter: limiter.acquire(host, target)
    url = f"https://{host}/"
    try:
        req = urllib.request.Request(url, headers=UA, method="GET")
        r = urllib.request.build_opener(NoRedirect).open(req, timeout=12)
        body = r.read(MAX_BODY + 1)[:MAX_BODY]
        txt = body.decode("utf-8", "ignore")
        m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
        return {"host": host, "url": url, "status": r.status, "title": (m.group(1).strip()[:200] if m else ""), "server": r.headers.get("Server", "")[:200], "headers": dict(list(r.headers.items())[:40]), "body_len": len(body)}
    except urllib.error.HTTPError as e:
        return {"host": host, "url": url, "status": e.code, "headers": dict((e.headers or {}).items()), "title": "", "server": "", "body_len": 0}
    except Exception as e:
        return {"host": host, "url": url, "status": 0, "error": str(e)[:200]}
