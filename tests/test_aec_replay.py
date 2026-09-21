"""EPIC6 Part 12: deterministic replay — identity, byte-identical output."""

from __future__ import annotations

import unittest

WATCH_RECORD = {
    "subdomain": "shop.example.com",
    "url": "/orders?order_id=",
    "endpoint": "/orders",
    "parameter": "order_id",
    "method": "GET",
    "location": "query",
    "technology": ["flask"],
    "source": "watch",
    "id": "srv-1",
    "category": "IDOR_CANDIDATE",
}

GRANTED = {"status": "GRANTED", "expires_tick": 100}


class TestReplayIdentity(unittest.TestCase):
    def test_identity_deterministic(self):
        from aec.replay import identity

        first = identity.identity_for(
            records=[WATCH_RECORD], origin="fixture",
            authz={WATCH_RECORD["id"]: GRANTED},
            policy_version="v1")
        second = identity.identity_for(
            records=[WATCH_RECORD], origin="fixture",
            authz={WATCH_RECORD["id"]: GRANTED},
            policy_version="v1")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_identity_changes_with_input(self):
        from aec.replay import identity

        base = dict(WATCH_RECORD)
        changed = dict(WATCH_RECORD, parameter="account_id")
        first = identity.identity_for([base], "fixture",
                                      {base["id"]: GRANTED}, "v1")
        second = identity.identity_for([changed], "fixture",
                                       {changed["id"]: GRANTED}, "v1")
        self.assertNotEqual(first, second)

    def test_identity_changes_with_origin(self):
        from aec.replay import identity

        watch = identity.identity_for(
            [WATCH_RECORD], "watch",
            {WATCH_RECORD["id"]: GRANTED}, "v1")
        fixture = identity.identity_for(
            [WATCH_RECORD], "fixture",
            {WATCH_RECORD["id"]: GRANTED}, "v1")
        self.assertNotEqual(watch, fixture)

    def test_identity_changes_with_authz(self):
        from aec.replay import identity

        base = identity.identity_for(
            [WATCH_RECORD], "fixture",
            {WATCH_RECORD["id"]: GRANTED}, "v1")
        denied = identity.identity_for(
            [WATCH_RECORD], "fixture",
            {WATCH_RECORD["id"]: {"status": "DENIED"}}, "v1")
        self.assertNotEqual(base, denied)

    def test_identity_changes_with_policy(self):
        from aec.replay import identity

        v1 = identity.identity_for([WATCH_RECORD], "fixture",
                                   {WATCH_RECORD["id"]: GRANTED}, "v1")
        v2 = identity.identity_for([WATCH_RECORD], "fixture",
                                   {WATCH_RECORD["id"]: GRANTED}, "v2")
        self.assertNotEqual(v1, v2)

    def test_input_order_matters(self):
        from aec.replay import identity

        other = dict(WATCH_RECORD, id="srv-2")
        first = identity.identity_for(
            [WATCH_RECORD, other], "fixture",
            {WATCH_RECORD["id"]: GRANTED, other["id"]: GRANTED}, "v1")
        second = identity.identity_for(
            [other, WATCH_RECORD], "fixture",
            {WATCH_RECORD["id"]: GRANTED, other["id"]: GRANTED}, "v1")
        self.assertNotEqual(first, second)

    def test_source_mode_label_in_identity(self):
        from aec.replay import identity

        documented = identity.document([WATCH_RECORD], "fixture",
                                       {WATCH_RECORD["id"]: GRANTED}, "v1")
        self.assertEqual(
            documented["source_mode"], "OFFLINE_FIXTURE")


class TestDeterministicReplay(unittest.TestCase):
    def test_byte_identical_serialization(self):
        from aec.runtime import loop
        from aec.replay import kernel

        first = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED})
        second = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED})
        self.assertEqual(
            kernel.serialize_run(first), kernel.serialize_run(second))

    def test_replay_matches_original(self):
        from aec.runtime import loop
        from aec.replay import kernel

        original = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED})
        replayed = kernel.replay(original, run_research=loop.run_execution)
        self.assertEqual(replayed, original)
        self.assertEqual(
            kernel.serialize_run(replayed), kernel.serialize_run(original))

    def test_corrupted_input_refused(self):
        from aec.replay import kernel

        with self.assertRaises(ValueError):
            kernel.replay({"not": "a run"}, run_research=None)

    def test_corrupted_replay_input_rejected(self):
        from aec.runtime import loop
        from aec.replay import kernel

        original = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED})
        document = original.to_dict()
        document["source_mode"] = "LIVE_DATA"
        with self.assertRaises(ValueError):
            kernel.validate(document)

    def test_source_mode_never_swapped(self):
        from aec.runtime import loop
        from aec.replay import kernel

        fixture = loop.run_execution(
            [WATCH_RECORD], "fixture",
            authz={WATCH_RECORD["id"]: GRANTED})
        document = fixture.to_dict()
        document["source_mode"] = "REAL_WATCH_DATA"
        with self.assertRaises(ValueError):
            kernel.validate(document)

    def test_replay_identity_matches_runtime(self):
        from aec.runtime import loop
        from aec.replay import identity

        run = loop.run_execution([WATCH_RECORD], "fixture",
                                 authz={WATCH_RECORD["id"]: GRANTED})
        documented = identity.document(
            [WATCH_RECORD], "fixture",
            {WATCH_RECORD["id"]: GRANTED}, "v1")
        self.assertEqual(run.replay_identity, documented["replay_identity"])

    def test_real_and_fixture_not_interchangeable(self):
        from aec.replay import kernel

        with self.assertRaises(ValueError):
            kernel.validate({"source_mode": "REAL_WATCH_DATA"} | {
                "run_id": "run-x", "jobs": (), "evidence": (),
                "failures": (), "review_records": ()})


if __name__ == "__main__":
    unittest.main()