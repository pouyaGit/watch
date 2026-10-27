import collections
import json

rows = [json.loads(l) for l in open('/opt/watch/logs/bb4/confirm/classified.jsonl')]
want = ('dell', 'digicert', 'indeed', 'wien')
sel = [r for r in rows
       if any(w in r['program'].lower() for w in want)]
print('candidates in the 4 Watch programs:', len(sel))
c = collections.Counter((r['program'], r['cls']) for r in sel)
for k, v in sorted(c.items()):
    print(f"  {v:4d}  {k[0]:24} {k[1]}")

print('\n== consumed-but-refused / error-page ones (bypass surface):')
for r in sel:
    if r['cls'] in ('validated-rejected', 'redirect-changed-host'):
        print(f"[{r['cls']}] {r['program']}")
        print('   ', r['endpoint'][:170])
        print(f"    base {r['baseline']['status']} -> {(r['baseline']['location'] or '')[:70]}")
        print(f"    cana {r['canary']['status']} -> {(r['canary']['location'] or '')[:70]}")
