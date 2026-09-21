"""EPIC8 Part 7: unified audit timeline — events, actors, ordering."""

from __future__ import annotations

import unittest

ACTIONS = frozenset({
    "case.created", "assignment.created", "authorization.requested",
    "authorization.approved", "observation.executed", "evidence.stored",
    "review.requested",
})


def view():
    from backend.routers import aec
    return aec.build_audit_view()


class TestEventSet(unittest.TestCase):
    def test_actions_closed(self):
        for event in view()["events"]:
            self.assertIn(event["action"], ACTIONS)

    def test_all_action_kinds_present(self):
        kinds = {event["action"] for event in view()["events"]}
        self.assertEqual(kinds, ACTIONS)

    def test_timestamps_increasing(self):
        stamps = [event["timestamp"] for event in view()["events"]]
        self.assertEqual(stamps, sorted(stamps))

    def test_actor_never_empty(self):
        for event in view()["events"]:
            self.assertTrue(event["actor"])

    def test_result_never_empty(self):
        for event in view()["events"]:
            self.assertTrue(event["result"])

    def test_events_have_reference(self):
        for event in view()["events"]:
            self.assertIn("reference", event)


class TestEventSemantics(unittest.TestCase):
    def test_authorization_approved_has_grant_payload(self):
        for event in view()["events"]:
            if event["action"] == "authorization.approved":
                self.assertIn("granted", event["result"].lower())

    def test_observation_executed_has_state(self):
        for event in view()["events"]:
            if event["action"] == "observation.executed":
                self.assertIn("COMPLETED", event["result"])

    def test_evidence_stored_has_evidence_ref(self):
        for event in view()["events"]:
            if event["action"] == "evidence.stored":
                self.assertTrue(event["reference"].startswith("ev-"))


class TestAuditSecurity(unittest.TestCase):
    def test_no_secrets(self):
        blob = str(view()).lower()
        for secret in ("cookie", "authorization:", "bearer", "password",
                       "set-cookie", "token="):
            self.assertNotIn(secret, blob)

    def test_no_raw_urls(self):
        blob = str(view())
        self.assertNotIn("https://", blob)

    def test_no_verdict_vocabulary(self):
        blob = str(view()).lower()
        for word in ("confirmed", "finding", "exploit", "vulnerable"):
            self.assertNotIn(word, blob)

    def test_deterministic(self):
        from backend.routers import aec
        first = aec.build_audit_view()
        second = aec.build_audit_view()
        self.assertEqual(first, second)


class TestAuditEmptyState(unittest.TestCase):
    def test_empty(self):
        from backend.routers import aec
        view = aec.build_audit_view(empty=True)
        self.assertEqual(view["events"], [])


class TestAuditHandler(unittest.TestCase):
    def test_endpoint_registered(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        self.assertIn("/api/aec/audit", paths)

    def test_handler_get_only(self):
        from backend.routers import aec
        by_path = {r.path: r.methods for r in aec.router.routes
                   if hasattr(r, "methods")}
        self.assertEqual(by_path["/api/aec/audit"], {"GET"})

    def test_handler_deterministic(self):
        from backend.routers import aec
        self.assertEqual(aec.get_audit(), aec.get_audit())


if __name__ == "__main__":
    unittest.main()