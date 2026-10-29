# Activity Events Schema Reference

## Table Definition
```sql
CREATE TABLE activity_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,          -- epoch seconds (float)
    target TEXT,             -- target directory name (e.g., 'test.target')
    module TEXT,             -- module identifier (e.g., 'dns_recon', 'http_recon')
    job_type TEXT,           -- job type from jobs table
    items_processed INTEGER DEFAULT 0,
    items_created INTEGER DEFAULT 0,
    status TEXT DEFAULT 'COMPLETED',  -- COMPLETED | FAILED
    duration REAL DEFAULT NULL       -- job duration in seconds
);
```

## Indices
- No explicit index needed for current query volume (last 600s window).
- If table grows, add `CREATE INDEX idx_activity_ts ON activity_events(timestamp)`.

## Event Producer
`findings_state.log_activity_event(target, module, job_type, items_processed, items_created, status)`
Called from `cycle.py:execute_job` after each job finishes.

## Pulse Query (build_pulse)
```python
c.execute(
    "SELECT target, module, job_type, items_processed, items_created, status, duration "
    "FROM activity_events WHERE timestamp >= ? ORDER BY timestamp DESC",
    (now - 600,)
)
```
Aggregates by module label, limits to 3 entries per module.

## Verification Steps (§runtime verification)
1. **Confirm scheduler is single owner** — grep all `.py` for `send_status` and confirm only `daemon.py` calls it. Any other caller is a stale scheduler.
2. **Confirm cadence after restart** — check `kv` table for `last_pulse_ts` / `last_status_ts`; verify daemon loop respects intervals.
3. **Confirm event diversity** — insert a test event with known `job_type`, query `activity_events` within 600s window, verify pulse aggregates only recent events.
4. **Confirm no Telegram self-reporting** — `activity_events` rows must not include `module='notify'` or `module='status'`.
5. **Confirm per-target coverage** — full status must include a DNS/HTTP/JS check per target, not just global aggregates.