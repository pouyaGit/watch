"""Re-resolve EVERY supposedly-dead CNAME target individually with dig
(3 resolvers + retries). dnsx bulk was demonstrably lossy: targets it reported
dead answered fine to dig.
"""
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

d = json.load(open('/opt/watch/logs/bb4/cname_sweep.json'))
dead = sorted({r['cname'] for r in d['rows'] if r['suspicious']})
print(f"[*] re-resolving {len(dead)} targets that dnsx reported dead", flush=True)

RESOLVERS = ["", "@1.1.1.1", "@8.8.8.8"]


def check(t):
    for res in RESOLVERS:
        cmd = ["dig", "+short", "+time=3", "+tries=2"]
        if res:
            cmd.append(res)
        cmd += [t, "A"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out = [x for x in p.stdout.split() if x and not x.startswith(";")]
            if out:
                return t, True, out[0]
        except Exception:
            continue
    return t, False, ""


alive = {}
with ThreadPoolExecutor(max_workers=40) as ex:
    for i, (t, ok, ip) in enumerate(ex.map(check, dead), 1):
        if ok:
            alive[t] = ip
        if i % 500 == 0:
            print(f"  [{i}/{len(dead)}] alive so far={len(alive)}", flush=True)

print(f"\n[+] {len(alive)}/{len(dead)} targets that dnsx called dead DO resolve")
json.dump(alive, open('/opt/watch/logs/bb4/cname_alive_correction.json', 'w'),
          indent=1)

# recompute genuinely dead
truly = [t for t in dead if t not in alive]
print(f"[+] {len(truly)} genuinely non-resolving targets remain")
import collections
c = collections.Counter('.'.join(t.split('.')[-3:]) for t in truly)
for k, v in c.most_common(15):
    print(f"    {v:5} {k}")

byhost = collections.Counter()
for r in d['rows']:
    if r['suspicious'] and r['cname'] in set(truly):
        suf = '.'.join(r['cname'].split('.')[-3:])
        byhost[suf] += 1
