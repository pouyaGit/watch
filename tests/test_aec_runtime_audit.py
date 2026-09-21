"""EPIC7 Part 16: append-only observation audit trail."""

from __future__ import annotations

import unittest


def valid_event(**overrides):
    event = {
        "request_id": "obsreq-abc123",
        "research_job_id": "job-123",
        "case_id": "case-123",
        "target_id": "tgt-000000000001",
        "authorization_reference": "authz-123",
        "policy_version": "v1",
        "decision": "AUTHORIZED",
        "execution_state": "DISPATCHED",
        "reason": "",
    }
    event.update(overrides)
    return event


class TestAuditAppendOnly(unittest.TestCase):
    def test_append_returns_entry(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event())
        self.assertEqual(entry["seq"], 1)
        self.assertEqual(entry["request_id"], "obsreq-abc123")

    def test_entries_accumulate(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        trail.append(valid_event(request_id="obsreq-other"))
        self.assertEqual(len(trail.entries()), 2)

    def test_entries_never_mutate(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        with self.assertRaises(TypeError):
            trail.entries()[0] = {}  # tuple is immutable

    def test_seq_increments(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        first = trail.append(valid_event())
        second = trail.append(valid_event())
        self.assertEqual(second["seq"], first["seq"] + 1)

    def test_no_write_methods(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        for name in ("update", "delete", "remove", "clear"):
            self.assertFalse(hasattr(trail, name))


class TestAuditContent(unittest.TestCase):
    def test_records_request(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event())
        self.assertEqual(entry["request_id"], "obsreq-abc123")

    def test_records_authorization(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event())
        self.assertEqual(entry["authorization_reference"], "authz-123")

    def test_records_target(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event())
        self.assertEqual(entry["target_id"], "tgt-000000000001")

    def test_records_policy(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event())
        self.assertEqual(entry["policy_version"], "v1")

    def test_records_decision_and_state(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event())
        self.assertEqual(entry["decision"], "AUTHORIZED")
        self.assertEqual(entry["execution_state"], "DISPATCHED")

    def test_records_refusal_reason(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event(
            decision="REFUSED", execution_state="REFUSED",
            reason="SCOPE_MISMATCH"))
        self.assertEqual(entry["reason"], "SCOPE_MISMATCH")

    def test_evidence_reference_recorded(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event(evidence_reference="ev-abc123"))
        self.assertEqual(entry["evidence_reference"], "ev-abc123")


class TestAuditHashChain(unittest.TestCase):
    def test_first_entry_has_prev_none(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        entry = trail.append(valid_event())
        self.assertIsNone(entry["previous_hash"])

    def test_second_entry_chains(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        first = trail.append(valid_event())
        second = trail.append(valid_event(request_id="obsreq-other"))
        self.assertEqual(second["previous_hash"], first["entry_hash"])

    def test_hash_changes_with_content(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        first = trail.append(valid_event())
        second = trail.append(valid_event(decision="REFUSED"))
        self.assertNotEqual(first["entry_hash"], second["entry_hash"])


class TestAuditVerify(unittest.TestCase):
    def test_verify_ok(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        trail.append(valid_event(request_id="obsreq-other"))
        self.assertTrue(trail.verify())

    def test_verify_detects_tamper(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        trail.append(valid_event(request_id="obsreq-other"))
        entries = list(trail.entries())
        tampered = dict(entries[1])
        tampered["decision"] = "AUTHORIZED_BY_FORCE"
        self.assertFalse(trail.verify(entries=(entries[0], tampered)))

    def test_verify_empty_ok(self):
        from aec.runtime.results.audit import AuditTrail

        self.assertTrue(AuditTrail().verify())

    def test_verify_detects_chain_break(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        trail.append(valid_event(request_id="obsreq-other"))
        entries = list(trail.entries())
        broken = dict(entries[1])
        broken["previous_hash"] = None
        self.assertFalse(trail.verify(entries=(entries[0], broken)))


class TestAuditReplay(unittest.TestCase):
    def test_replay_deterministic(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        trail.append(valid_event(request_id="obsreq-other"))

        events = [e["decision"] for e in trail.entries()]
        replay = trail.replay()
        self.assertEqual(list(replay), events)

    def test_replay_identical_decisions(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event(decision="REFUSED"))
        trail.append(valid_event(request_id="obsreq-other"))
        self.assertEqual(trail.replay(), ("REFUSED", "AUTHORIZED"))

    def test_audit_supports_investigation(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event(request_id="obsreq-a"))
        trail.append(valid_event(request_id="obsreq-b"))
        ids = [e["request_id"] for e in trail.entries()]
        self.assertEqual(ids, ["obsreq-a", "obsreq-b"])


class TestAuditExport(unittest.TestCase):
    def test_export_json(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        data = trail.export_json()
        self.assertIn("entries", data)
        self.assertIn("verified", data)
        self.assertEqual(len(data["entries"]), 1)

    def test_export_no_secrets(self):
        from aec.runtime.results.audit import AuditTrail

        trail = AuditTrail()
        trail.append(valid_event())
        data = trail.export_json()
        joined = str(data)
        for secret in ("Bearer", "password=", "cookie="):
            self.assertNotIn(secret, joined)


if __name__ == "__main__":
    unittest.main()