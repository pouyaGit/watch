"""Starter store — SQLite jobs/assets/findings/cycles + atomic claim + recovery."""
import hashlib, json, os, sqlite3, time, uuid
SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY, target TEXT, job_type TEXT, priority TEXT, created_at REAL, scheduled_at REAL, status TEXT, attempt_count INT DEFAULT 0, rate_limit REAL, concurrency INT, started_at REAL, finished_at REAL, error TEXT);
CREATE TABLE IF NOT EXISTS assets(host TEXT PRIMARY KEY, target TEXT, verdict TEXT, first_seen REAL, last_seen REAL, dns_a TEXT, http_status INT, http_title TEXT, server TEXT, tech TEXT, last_change REAL);
CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY, target TEXT, host TEXT, url TEXT, finding_type TEXT, confidence TEXT, severity TEXT, evidence TEXT, fingerprint TEXT UNIQUE, first_seen REAL, last_seen REAL, status TEXT, manual TEXT);
CREATE TABLE IF NOT EXISTS cycles(ts REAL PRIMARY KEY, assets_discovered INT, jobs_completed INT, jobs_failed INT, findings_created INT);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""
DB = os.environ.get("HERMES_RECON_DB", "/root/hermes-recon/state/hermes.db")
def conn():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=30); c.row_factory = sqlite3.Row
    for s in SCHEMA.strip().split(";"):
        if s.strip(): c.execute(s)
    c.commit(); return c
def fingerprint(*parts):
    return hashlib.sha256("|".join(p.strip().lower() for p in parts).encode()).hexdigest()[:16]
def enqueue(target, job_type, priority="medium", delay=0):
    c = conn(); jid = uuid.uuid4().hex[:12]; now = time.time()
    c.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (jid, target, job_type, priority, now, now + delay, "PENDING", 0, 2.0, 1, None, None, ""))
    c.commit(); c.close(); return jid
def claim_job():
    c = conn(); now = time.time()
    o = "CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"
    r = c.execute(f"SELECT * FROM jobs WHERE status='PENDING' AND scheduled_at<=? ORDER BY {o}, created_at LIMIT 1", (now,)).fetchone()
    if not r: c.close(); return None
    c.execute("UPDATE jobs SET status='RUNNING', started_at=?, attempt_count=attempt_count+1 WHERE job_id=? AND status='PENDING'", (now, r["job_id"]))
    c.commit(); ok = c.total_changes > 0; row = dict(r) if ok else None; c.close(); return row
def finish_job(jid, ok=True, error=""):
    c = conn()
    c.execute("UPDATE jobs SET status=?, finished_at=?, error=? WHERE job_id=?", ("COMPLETED" if ok else "FAILED", time.time(), error[:500], jid))
    c.commit(); c.close()
def recover_jobs():
    c = conn()
    n = c.execute("SELECT COUNT(*) n FROM jobs WHERE status='RUNNING'").fetchone()["n"]
    c.execute("UPDATE jobs SET status='PENDING', scheduled_at=? WHERE status='RUNNING'", (time.time() + 5,))
    c.commit(); c.close(); return n
