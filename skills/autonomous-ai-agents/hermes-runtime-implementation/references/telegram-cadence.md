# Telegram Cadence Reference

## Intervals
- **Activity Pulse**: 600s (10 minutes) — short delta of last 10m activity
- **Full Status**: 1800s (30 minutes) — complete operator status
- **Daily Report**: Once per day at/after 08:00 UTC
- **Finding Alerts**: Immediate, deduplicated, queued with retry

## Message Formats

### Activity Pulse (build_pulse)
```
⏱ HERMES — LAST 10 MIN

Asset Discovery:
• target1 ✓
• target2 ✗

HTTP Inspection:
• target1 ✓

State: RUNNING
```

### Full Status (build_status)
Per-spec §4/§5: state, current activity, active targets, workers, queue, DNS, HTTP, JS, endpoints, parameters, findings, resources, safety, model/budget, idle reason, **PER-TARGET COVERAGE**.

## Implementation Pattern
In `notify.py`:
```python
ACTIVITY_INTERVAL_S = 600
STATUS_INTERVAL_S = 1800

def send_status(force=False, pulse=False):
    now = time.time()
    if pulse:
        last = kv_get("last_pulse_ts", 0)
        if now - last < ACTIVITY_INTERVAL_S:
            return False
        text = status_mod.build_pulse()
        key = "last_pulse_ts"
    else:
        last = kv_get("last_status_ts", 0)
        if now - last < STATUS_INTERVAL_S:
            return False
        text = status_mod.build_status()
        key = "last_status_ts"
    ok = send_raw(text)
    if ok:
        kv_set(key, now)
    return ok
```

## Scheduler Integration
Only `daemon.py` main loop calls `notify.send_status()`. In each 30s tick:
```python
notify.send_status(pulse=True)   # interval-gated to 10m
notify.send_status(pulse=False)  # interval-gated to 30m
```

## Verification
```bash
HERMES_NOTIFY_SINK=file:/tmp/test.log python3 -c "
import sys; sys.path.insert(0, 'lib')
import notify, status
notify.send_status(force=True, pulse=True)
notify.send_status(force=True, pulse=False)
"
cat /tmp/test.log
```

## Restart Resilience
- `last_pulse_ts` and `last_status_ts` persisted in SQLite `kv` table
- No duplicate messages on restart — intervals checked against wall clock
- No `force=True` in production path; only used for testing
