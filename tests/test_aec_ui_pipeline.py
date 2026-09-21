"""EPIC8 Part 4: research pipeline view — stages, states, blocked reasons."""

from __future__ import annotations

import unittest

STAGES = ("candidate", "case", "assignment", "research_job",
          "authorization", "observation", "evidence", "review")


def view():
    from backend.routers import aec
    return aec.build_pipeline_view()


class TestStageOrder(unittest.TestCase):
    def test_eight_stages_in_order(self):
        stages = [stage["stage"] for stage in view()["stages"]]
        self.assertEqual(stages, list(STAGES))

    def test_stage_shapes(self):
        for stage in view()["stages"]:
            self.assertEqual(sorted(stage),
                             sorted(["stage", "state", "blocks", "badge"]))

    def test_stage_names_are_snake(self):
        for stage in view()["stages"]:
            self.assertRegex(stage["stage"], r"^[a-z_]+$")


class TestCurrentState(unittest.TestCase):
    def test_evidence_stage_state(self):
        stages = {s["stage"]: s for s in view()["stages"]}
        self.assertIn(stages["evidence"]["state"],
                      {"WAITING_EVIDENCE", "EVIDENCE_PARTIAL",
                       "EVIDENCE_READY", ""})

    def test_review_stage_is_pending(self):
        stages = {s["stage"]: s for s in view()["stages"]}
        state = stages["review"]["state"]
        self.assertIn(state, {"PENDING", "REQUIRED", ""})

    def test_authorization_stage_state(self):
        stages = {s["stage"]: s for s in view()["stages"]}
        state = stages["authorization"]["state"]
        self.assertIn(state, {"ALLOW", "AUTHORIZED", "GRANTED", ""})


class TestBlockedReasons(unittest.TestCase):
    def test_waiting_evidence_has_reason(self):
        stages = {s["stage"]: s for s in view()["stages"]}
        if stages["evidence"]["state"] == "WAITING_EVIDENCE":
            self.assertTrue(stages["evidence"]["blocks"])

    def test_blocks_are_strings(self):
        for stage in view()["stages"]:
            for block in stage["blocks"]:
                self.assertIsInstance(block, str)

    def test_review_reason_when_required(self):
        stages = {s["stage"]: s for s in view()["stages"]}
        if stages["review"]["state"]:
            self.assertTrue(stages["review"]["blocks"])


class TestPipelineSecurity(unittest.TestCase):
    def test_no_secrets(self):
        blob = str(view()).lower()
        for secret in ("cookie", "authorization:", "bearer",
                       "password", "set-cookie"):
            self.assertNotIn(secret, blob)

    def test_no_urls(self):
        blob = str(view())
        self.assertNotIn("https://", blob)

    def test_no_verdict_vocabulary(self):
        blob = str(view()).lower()
        for word in ("confirmed", "finding", "exploit", "vulnerable"):
            self.assertNotIn(word, blob)

    def test_deterministic(self):
        from backend.routers import aec
        first = aec.build_pipeline_view()
        second = aec.build_pipeline_view()
        self.assertEqual(first, second)


class TestEmptyPipeline(unittest.TestCase):
    def test_empty_stages(self):
        from backend.routers import aec
        view = aec.build_pipeline_view(empty=True)
        for stage in view["stages"]:
            self.assertEqual(stage["state"], "")
            self.assertEqual(stage["blocks"], [])


class TestHandler(unittest.TestCase):
    def test_pipeline_endpoint_registered(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        # the research-pipeline visualization is served by the slash-form
        # research/jobs endpoint (EPIC8 Part 4+8)
        self.assertIn("/api/aec/research/jobs", paths)

    def test_stage_state_never_verdict(self):
        for stage in view()["stages"]:
            self.assertNotIn(stage["state"].lower(),
                             {"confirmed", "vulnerable"})


if __name__ == "__main__":
    unittest.main()