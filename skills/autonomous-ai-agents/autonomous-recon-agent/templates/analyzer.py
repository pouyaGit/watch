"""Starter analyzer — passive patterns only. Every hit is POTENTIAL + manual review."""
import re
def analyze_http(host, url, status, headers, title="", robots=""):
    out = []; h = {k.lower(): v for k, v in (headers or {}).items()}
    missing = [x for x in ("content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy") if x not in h]
    if status == 200 and len(missing) >= 3:
        out.append(("security-misconfig:headers", "Low", "Low", f"Missing: {', '.join(missing)}"))
    if re.search(r"/\d+\.\d+", h.get("server", "")) or h.get("x-powered-by"):
        out.append(("tech-exposure:server-banner", "Low", "Info", f"server={h.get('server','')[:80]}"))
    if h.get("access-control-allow-origin") == "*":
        out.append(("cors:permissive", "Medium", "Medium", "ACAO=*"))
    if robots:
        sens = [l for l in robots.splitlines() if re.search(r"(admin|backup|config|\.env|private|internal|api)", l, re.I)][:5]
        if sens: out.append(("info-disclosure:robots", "Low", "Info", " | ".join(s[:120] for s in sens)))
    return out
def analyze_dns_takeover(host, dns):
    cn, a = (dns or {}).get("CNAME", []), (dns or {}).get("A", [])
    dead = re.compile(r"(github\.io|herokuapp\.com|azurewebsites\.net|s3\.amazonaws|cloudfront\.net)", re.I)
    if cn and not a:
        for c in cn:
            if dead.search(c):
                return [("takeover:potential-dangling-cname", "Low", "Medium", f"{host} CNAME -> {c}, no A. POTENTIAL only — manual check required")]
    return []
