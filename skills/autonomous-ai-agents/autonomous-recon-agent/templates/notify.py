"""Starter notify — wraps `hermes send`. HIGH immediate, LOW aggregated."""
import subprocess
def send(text, to="telegram"):
    try:
        return subprocess.run(["hermes", "send", "--to", to, text], capture_output=True, text=True, timeout=60).returncode == 0
    except Exception:
        return False
def finding_alert(target, host, ftype, conf, ev, fid):
    return send(f"\U0001F534 HERMES — POTENTIAL FINDING\n\nTarget:\n{target}\n\nHost:\n{host}\n\nType:\n{ftype}\n\nConfidence:\n{conf}\n\nEvidence:\n{ev[:800]}\n\nExploitation:\nNOT PERFORMED.\n\nFinding: {fid}\nStatus:\nWAITING FOR MANUAL VERIFICATION")
