"""Starter Safety Guard — token bucket + adaptive backoff + server monitor."""
import json, os, shutil, threading, time
GLOBAL_CEILING = 15.0
DEFAULT_RATE = 2.0
MIN_RATE = 0.5
DEFENSIVE_CODES = {429, 403, 408, 502, 503, 504}
COOLDOWN_S = 600
class RateLimiter:
    def __init__(self, state_dir):
        self._lock = threading.Lock()
        self._g = GLOBAL_CEILING; self._gl = time.monotonic()
        self._host = {}; self._rates = {}; self._sd = state_dir
        try:
            self._rates = json.load(open(os.path.join(state_dir, "rate_state.json"))).get("rates", {})
        except Exception:
            pass
    def rate_for(self, t):
        return max(MIN_RATE, min(GLOBAL_CEILING, self._rates.get(t, DEFAULT_RATE)))
    def set_rate(self, t, r):
        self._rates[t] = max(MIN_RATE, min(GLOBAL_CEILING, r))
        try:
            json.dump({"rates": self._rates}, open(os.path.join(self._sd, "rate_state.json"), "w"))
        except Exception:
            pass
    def acquire(self, host, target, timeout=30):
        rate = self.rate_for(target); start = time.monotonic()
        while True:
            with self._lock:
                now = time.monotonic()
                self._g = min(GLOBAL_CEILING, self._g + (now - self._gl) * GLOBAL_CEILING)
                self._gl = now
                last, tok = self._host.get(host, [now, rate])
                tok = min(rate, tok + (now - last) * rate)
                if self._g >= 1.0 and tok >= 1.0:
                    self._g -= 1.0; self._host[host] = [now, tok - 1.0]
                    return time.monotonic() - start
                self._host[host] = [now, tok]
            time.sleep(0.1)
            if time.monotonic() - start > timeout:
                return time.monotonic() - start
def server_health(base):
    out = {"ok": True, "reasons": []}
    try:
        out["load1"] = os.getloadavg()[0]
        if out["load1"] > 3.0:
            out["ok"] = False; out["reasons"].append(f"load {out['load1']:.1f}")
    except Exception:
        out["load1"] = -1
    try:
        mi = {}
        for line in open("/proc/meminfo"):
            k, v = line.split(":", 1); mi[k.strip()] = int(v.split()[0])
        pct = 100 * (1 - mi["MemAvailable"] / mi["MemTotal"])
        out["ram_pct"] = round(pct, 1)
        if pct > 85:
            out["ok"] = False; out["reasons"].append(f"ram {pct:.0f}%")
    except Exception:
        out["ram_pct"] = -1
    try:
        du = shutil.disk_usage(base); pct = 100 * du.used / du.total
        out["disk_pct"] = round(pct, 1)
        if pct > 90:
            out["ok"] = False; out["reasons"].append(f"disk {pct:.0f}%")
    except Exception:
        out["disk_pct"] = -1
    return out
