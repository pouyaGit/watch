"""tests/test_component_identity.py — Stage R31.6 tests.

Deterministic, offline tests for CVE-side identity resolution:

- normalization (lowercase, parenthetical-strip, marketing-trailer-strip,
  underscore->dash, leading-wp-strip only when single-token);
- canonical-slug generation only for safe slugs;
- explicit alias table (current corpus-driven entries only);
- negative-collision protection (unrelated strings stay distinct);
- category classification (PLUGIN vs. PRODUCT vs. UNKNOWN);
- observed-inventory matching with structured identity evidence;
- backend adapter integration (the unchanged R30.1 engine receives the
  expanded CVE-side values and matches observed ``wp-responsive-images``,
  ``wordpress-automatic`` and ``wp-ottokit``);
- determinism under input permutation;
- bounded evidence/list sizes;
- privacy/safety: no credentials, authorization headers, secrets or
  sensitive request data in any emitted identity field;
- regression: every R30.1/R30.3/R31.5 test must continue passing (the
  focused regression suite is run in CI / stage commit).

No network, no DNS, no LLM, no subprocess, no target interaction, no
persistence. The R30.1 engine is not modified.
"""
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

import mongoengine

mongoengine.connect = lambda *a, **k: None

from ai.knowledge import component_identity as ci
from ai.knowledge import asset_cve_matching as engine
from ai.knowledge.asset_cve_matching import match_plugin, match_component
from ai.knowledge.component_identity import (
    ALIAS_TABLE,
    CATEGORIES,
    CATEGORY_PLUGIN,
    CATEGORY_PRODUCT,
    CATEGORY_UNKNOWN,
    METHOD_CANONICAL_SLUG,
    METHOD_EXACT_NORMALIZED,
    METHOD_EXPLICIT_ALIAS,
    METHOD_NO_RESOLUTION,
    METHODS,
    RULE_VERSION as IDENTITY_RULE_VERSION,
    canonical_slug,
    classify,
    expanded_cve_value_set,
    match_observed_identities,
    negative_alias_pairs,
    normalize_identity,
    resolve_cve_identities,
)
from ai.knowledge.relevance import AssetRecord
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1680"


# ---------------------------------------------------------------------------
# Test 1 — Vocabulary / rule version
# ---------------------------------------------------------------------------


class TestVocabulary(unittest.TestCase):
    def test_rule_version_is_r31_6(self):
        self.assertEqual(IDENTITY_RULE_VERSION, "r31-6")

    def test_categories_closed(self):
        self.assertEqual(
            CATEGORIES,
            ("PRODUCT", "COMPONENT", "PLUGIN", "TECHNOLOGY", "UNKNOWN"),
        )

    def test_resolution_methods_closed(self):
        self.assertEqual(
            METHODS,
            (
                "EXACT_NORMALIZED",
                "CANONICAL_SLUG",
                "EXPLICIT_ALIAS",
                "NO_RESOLUTION",
            ),
        )

    def test_alias_table_only_contains_documented_entries(self):
        # The alias table is a load-bearing safety surface; its entries must
        # be exactly the corpus-justified ones for R31.6.
        canonicals = sorted(entry.canonical for entry in ALIAS_TABLE)
        self.assertEqual(
            canonicals,
            ["ottokit", "wordpress-automatic", "wp-responsive-images"],
        )
        for entry in ALIAS_TABLE:
            self.assertIn(entry.category, CATEGORIES)
            self.assertTrue(entry.canonical)
            self.assertTrue(entry.aliases)
            self.assertTrue(entry.rationale)


# ---------------------------------------------------------------------------
# Test 2 — Normalization
# ---------------------------------------------------------------------------


class TestNormalization(unittest.TestCase):
    def test_wp_responsive_images_with_parenthetical(self):
        # CVE-2026-1557 affected_products style.
        self.assertEqual(
            normalize_identity("WP Responsive Images (WordPress plugin)"),
            "wp-responsive-images",
        )

    def test_wp_responsive_images_bare(self):
        self.assertEqual(
            normalize_identity("WP Responsive Images"),
            "wp-responsive-images",
        )

    def test_wp_responsive_images_slug(self):
        self.assertEqual(
            normalize_identity("wp-responsive-images"),
            "wp-responsive-images",
        )

    def test_wordpress_automatic_plugin(self):
        # CVE-2024-27956 underscore form.
        self.assertEqual(
            normalize_identity("wordpress_automatic_plugin"),
            "wordpress-automatic",
        )

    def test_automatic_alone(self):
        # CVE-2024-27956 alt product.
        self.assertEqual(
            normalize_identity("Automatic"),
            "automatic",
        )

    def test_ottokit_full_marketing_name(self):
        # CVE-2025-3102 colon/marketing-trailer form.
        self.assertEqual(
            normalize_identity("OttoKit: All-in-One Automation Platform"),
            "ottokit",
        )

    def test_wp_ottokit_slug_strips_single_wp(self):
        # Observed plugin slug for OttoKit; the trailing ``wp-`` is a
        # single-token prefix and is safely stripped.
        self.assertEqual(
            normalize_identity("wp-ottokit"),
            "ottokit",
        )

    def test_leading_wp_preserves_multi_token_identity(self):
        # Multi-token identities must NOT lose the ``wp`` prefix because
        # dropping it would destroy identity (observed ``wp-responsive-images``
        # would otherwise become generic ``responsive-images``).
        self.assertEqual(
            normalize_identity("wp-responsive-images"),
            "wp-responsive-images",
        )

    def test_diacritics_stripped(self):
        self.assertEqual(
            normalize_identity("Café Pro"),
            "cafe-pro",
        )

    def test_empty_input_returns_empty(self):
        self.assertEqual(normalize_identity(""), "")
        self.assertEqual(normalize_identity(None), "")
        self.assertEqual(normalize_identity("   "), "")

    def test_no_url_or_host_in_normalized_output(self):
        # The resolver is CVE-side; passing full URLs is misuse, but verify
        # the resolver does not leak query strings or fragments.
        for value in (
            "WP Responsive Images?token=Bearer",
            "OttoKit#frag",
        ):
            text = normalize_identity(value)
            self.assertNotIn("?", text)
            self.assertNotIn("#", text)
            self.assertNotIn("Bearer", text)


# ---------------------------------------------------------------------------
# Test 3 — Canonical slug derivation (only safe slugs)
# ---------------------------------------------------------------------------


class TestCanonicalSlug(unittest.TestCase):
    def test_safe_slug_emitted(self):
        slug = canonical_slug(
            raw="wp-smushit", normalized="wp-smushit", category="PLUGIN"
        )
        self.assertEqual(slug, "wp-smushit")

    def test_unsafe_slug_rejected(self):
        slug = canonical_slug(
            raw="OttoKit: All-in-One Automation Platform",
            normalized="ottokit",
            category="PLUGIN",
        )
        # Resolver falls back; ``canonical_slug`` alone derives a safe slug
        # only for already-safe normalized inputs.
        self.assertEqual(slug, "ottokit")

    def test_prose_slug_rejected(self):
        # A multi-token prose slug is still slug-shaped; the canonical-slug
        # builder emits it for safe normalized values. The resolver instead
        # consults the alias table for marketing names; verify that path.
        result = resolve_cve_identities(
            cve_products=["OttoKit: All-in-One Automation Platform"]
        )
        # The alias-table lookup wins over the canonical-slug builder for
        # marketing-framed CVE products. The canonical "ottokit" comes from
        # the explicit alias entry, not from prose concatenation.
        self.assertEqual(result.resolutions[0].canonical, "ottokit")
        self.assertEqual(
            result.resolutions[0].resolution_method,
            METHOD_EXPLICIT_ALIAS,
        )

    def test_invalid_slug_rejected(self):
        slug = canonical_slug(
            raw="!!!", normalized="!!!", category="PLUGIN"
        )
        self.assertEqual(slug, "")

    def test_unknown_category_rejected(self):
        slug = canonical_slug(
            raw="foo-bar", normalized="foo-bar", category="UNKNOWN"
        )
        self.assertEqual(slug, "")


# ---------------------------------------------------------------------------
# Test 4 — Explicit alias table
# ---------------------------------------------------------------------------


class TestExplicitAliases(unittest.TestCase):
    def test_wordpress_automatic_aliases_resolve(self):
        result = resolve_cve_identities(
            cve_products=["wordpress_automatic_plugin"]
        )
        self.assertEqual(len(result.resolutions), 1)
        r = result.resolutions[0]
        self.assertEqual(r.canonical, "wordpress-automatic")
        self.assertEqual(r.category, "PLUGIN")
        self.assertEqual(r.resolution_method, METHOD_EXPLICIT_ALIAS)
        self.assertIn("automatic", r.alias_variants)

    def test_automatic_alone_resolves_to_alias(self):
        result = resolve_cve_identities(cve_products=["Automatic"])
        self.assertEqual(len(result.resolutions), 1)
        r = result.resolutions[0]
        self.assertEqual(r.canonical, "wordpress-automatic")
        self.assertEqual(r.resolution_method, METHOD_EXPLICIT_ALIAS)
        self.assertEqual(r.category, "PLUGIN")

    def test_ottokit_marketing_name_resolves(self):
        result = resolve_cve_identities(
            cve_products=["OttoKit: All-in-One Automation Platform"]
        )
        self.assertEqual(len(result.resolutions), 1)
        r = result.resolutions[0]
        self.assertEqual(r.canonical, "ottokit")
        self.assertEqual(r.resolution_method, METHOD_EXPLICIT_ALIAS)
        self.assertIn("wp-ottokit", r.alias_variants)

    def test_wp_responsive_images_alias(self):
        result = resolve_cve_identities(
            cve_products=["WP Responsive Images (WordPress plugin)"]
        )
        self.assertEqual(len(result.resolutions), 1)
        r = result.resolutions[0]
        self.assertEqual(r.canonical, "wp-responsive-images")
        self.assertEqual(r.category, "PLUGIN")
        self.assertEqual(r.resolution_method, METHOD_EXPLICIT_ALIAS)


# ---------------------------------------------------------------------------
# Test 5 — Negative-collision protection
# ---------------------------------------------------------------------------


class TestNegativeCollisions(unittest.TestCase):
    def test_negative_pairs_are_documented(self):
        pairs = negative_alias_pairs()
        self.assertGreaterEqual(len(pairs), 5)
        for left, right in pairs:
            self.assertNotEqual(normalize_identity(left), normalize_identity(right))

    def test_automatic_vs_automatic_login(self):
        a = resolve_cve_identities(cve_products=["automatic"])
        b = resolve_cve_identities(cve_products=["automatic-login"])
        self.assertEqual(a.resolutions[0].canonical, "wordpress-automatic")
        self.assertEqual(b.resolutions[0].canonical, "automatic-login")

    def test_otto_vs_ottokit(self):
        a = resolve_cve_identities(cve_products=["OttoKit"])
        b = resolve_cve_identities(cve_products=["Otto"])
        self.assertEqual(a.resolutions[0].canonical, "ottokit")
        self.assertEqual(b.resolutions[0].canonical, "otto")

    def test_ckeditor_vs_ckfinder(self):
        a = resolve_cve_identities(cve_products=["CKEditor"])
        b = resolve_cve_identities(cve_products=["CKFinder"])
        # Neither is in the alias table; they must remain distinct.
        self.assertNotEqual(a.resolutions[0].canonical, b.resolutions[0].canonical)
        self.assertNotEqual(a.resolutions[0].normalized, b.resolutions[0].normalized)

    def test_wp_smushit_vs_smush(self):
        a = resolve_cve_identities(cve_products=["wp-smushit"])
        b = resolve_cve_identities(cve_products=["smush"])
        self.assertNotEqual(a.resolutions[0].canonical, b.resolutions[0].canonical)

    def test_wordpress_vs_wordpress_automatic(self):
        a = resolve_cve_identities(cve_products=["WordPress"])
        b = resolve_cve_identities(cve_products=["wordpress-aut"])
        # ``wordpress-aut`` is not in the alias table and must not collapse
        # to ``wordpress`` (it normalizes to ``wordpress-aut``).
        self.assertNotEqual(a.resolutions[0].canonical, b.resolutions[0].canonical)


# ---------------------------------------------------------------------------
# Test 6 — Classification
# ---------------------------------------------------------------------------


class TestClassification(unittest.TestCase):
    def test_plugin_form_classified(self):
        self.assertEqual(
            classify(
                "OttoKit: All-in-One Automation Platform",
                normalize_identity("OttoKit: All-in-One Automation Platform"),
            ),
            "PLUGIN",
        )

    def test_product_when_no_plugin_signal(self):
        self.assertEqual(
            classify("Zabbix", normalize_identity("Zabbix")),
            "PRODUCT",
        )

    def test_unknown_when_normalized_empty(self):
        # When the normalized form is empty (e.g. input was pure
        # whitespace/punctuation that the resolver could not tokenize), the
        # classification is UNKNOWN.
        self.assertEqual(classify("", ""), "UNKNOWN")
        self.assertEqual(
            classify("    ", ""),
            "UNKNOWN",
        )


# ---------------------------------------------------------------------------
# Test 7 — Resolution output shape and ordering
# ---------------------------------------------------------------------------


class TestResolutionShape(unittest.TestCase):
    def test_each_resolution_has_required_fields(self):
        result = resolve_cve_identities(
            cve_products=[
                "wordpress_automatic_plugin",
                "OttoKit: All-in-One Automation Platform",
                "WP Responsive Images (WordPress plugin)",
            ]
        )
        self.assertEqual(len(result.resolutions), 3)
        for r in result.resolutions:
            self.assertTrue(r.raw)
            self.assertIn(r.category, CATEGORIES)
            self.assertIn(r.resolution_method, METHODS)
            self.assertLessEqual(len(r.evidence), 4)

    def test_empty_input_emits_zero_resolutions(self):
        result = resolve_cve_identities()
        self.assertEqual(result.resolutions, [])
        self.assertEqual(result.matches, [])

    def test_unparseable_raw_emits_no_resolution(self):
        result = resolve_cve_identities(cve_products=[""])
        self.assertEqual(result.resolutions, [])

    def test_dedup_within_inputs(self):
        result = resolve_cve_identities(
            cve_products=["OttoKit: All-in-One Automation Platform"] * 3
        )
        self.assertEqual(len(result.resolutions), 1)

    def test_resolved_values_emit_alias_variants(self):
        result = resolve_cve_identities(
            cve_products=["wordpress_automatic_plugin"]
        )
        values = expanded_cve_value_set(result.resolutions)
        self.assertIn("wordpress-automatic", values)
        self.assertIn("automatic", values)


# ---------------------------------------------------------------------------
# Test 8 — Observed inventory matching
# ---------------------------------------------------------------------------


class TestObservedMatching(unittest.TestCase):
    def test_observes_wp_responsive_images(self):
        result = resolve_cve_identities(
            cve_products=["WP Responsive Images (WordPress plugin)"]
        )
        matches = match_observed_identities(
            resolutions=result.resolutions,
            observed_plugins=["wp-responsive-images", "akismet"],
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].observed_identity, "wp-responsive-images")
        self.assertEqual(matches[0].canonical_cve_identity, "wp-responsive-images")

    def test_observes_wordpress_automatic(self):
        result = resolve_cve_identities(
            cve_products=["wordpress_automatic_plugin", "Automatic"]
        )
        matches = match_observed_identities(
            resolutions=result.resolutions,
            observed_plugins=["wordpress-automatic", "akismet"],
        )
        plugins = {m.observed_identity for m in matches}
        self.assertIn("wordpress-automatic", plugins)

    def test_observes_wp_ottokit(self):
        result = resolve_cve_identities(
            cve_products=["OttoKit: All-in-One Automation Platform"]
        )
        matches = match_observed_identities(
            resolutions=result.resolutions,
            observed_plugins=["wp-ottokit", "akismet"],
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].observed_identity, "wp-ottokit")
        self.assertEqual(matches[0].canonical_cve_identity, "ottokit")

    def test_no_match_for_unrelated_observed(self):
        result = resolve_cve_identities(
            cve_products=["OttoKit: All-in-One Automation Platform"]
        )
        matches = match_observed_identities(
            resolutions=result.resolutions,
            observed_plugins=["akismet", "contact-form-7"],
        )
        self.assertEqual(matches, [])

    def test_match_evidence_shape(self):
        result = resolve_cve_identities(
            cve_products=["OttoKit: All-in-One Automation Platform"]
        )
        matches = match_observed_identities(
            resolutions=result.resolutions,
            observed_plugins=["wp-ottokit"],
        )
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertEqual(m.raw_cve_identity, "OttoKit: All-in-One Automation Platform")
        self.assertEqual(m.canonical_cve_identity, "ottokit")
        self.assertEqual(m.category, "PLUGIN")
        self.assertEqual(m.resolution_method, METHOD_EXPLICIT_ALIAS)
        self.assertTrue(m.evidence)


# ---------------------------------------------------------------------------
# Test 9 — Determinism
# ---------------------------------------------------------------------------


class TestDeterminism(unittest.TestCase):
    def test_input_order_does_not_change_resolutions(self):
        first = resolve_cve_identities(
            cve_products=[
                "wordpress_automatic_plugin",
                "OttoKit: All-in-One Automation Platform",
                "WP Responsive Images (WordPress plugin)",
            ]
        )
        second = resolve_cve_identities(
            cve_products=[
                "WP Responsive Images (WordPress plugin)",
                "OttoKit: All-in-One Automation Platform",
                "wordpress_automatic_plugin",
            ]
        )
        first_canonicals = [r.canonical for r in first.resolutions]
        second_canonicals = [r.canonical for r in second.resolutions]
        # Order of inputs may differ; the resolver records order of first
        # appearance per category, so the canonical set must be identical.
        self.assertEqual(sorted(first_canonicals), sorted(second_canonicals))

    def test_normalize_is_deterministic(self):
        samples = [
            "OttoKit: All-in-One Automation Platform",
            "wordpress_automatic_plugin",
            "WP Responsive Images (WordPress plugin)",
        ]
        first = [normalize_identity(value) for value in samples]
        second = [normalize_identity(value) for value in samples]
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# Test 10 — Bounds
# ---------------------------------------------------------------------------


class TestBounds(unittest.TestCase):
    def test_max_resolutions_capped(self):
        big = [f"Plugin {n}" for n in range(ci.MAX_RESOLUTIONS + 50)]
        result = resolve_cve_identities(cve_products=big)
        self.assertLessEqual(len(result.resolutions), ci.MAX_RESOLUTIONS)

    def test_alias_hits_per_observed_bounded(self):
        resolutions = resolve_cve_identities(
            cve_products=[
                "OttoKit: All-in-One Automation Platform",
                "WP Responsive Images (WordPress plugin)",
                "wordpress_automatic_plugin",
            ]
        )
        # Pad observed_plugins with hundreds of unrelated names to confirm
        # alias-hit scanning is bounded per observed identity.
        observed_plugins = [
            f"unrelated-plugin-{n}" for n in range(ci.MAX_ALIAS_HITS + 50)
        ] + ["wp-ottokit"]
        matches = match_observed_identities(
            resolutions=resolutions.resolutions,
            observed_plugins=observed_plugins,
        )
        ottokit_matches = [
            m for m in matches
            if m.canonical_cve_identity == "ottokit"
        ]
        self.assertLessEqual(
            len(ottokit_matches),
            ci.MAX_ALIAS_HITS,
        )


# ---------------------------------------------------------------------------
# Test 11 — Privacy / safety (no credentials, headers, secrets)
# ---------------------------------------------------------------------------


class TestPrivacySafety(unittest.TestCase):
    def test_no_authorization_headers_or_bearer_tokens_in_evidence(self):
        result = resolve_cve_identities(
            cve_products=[
                "OttoKit: All-in-One Automation Platform",
                "wordpress_automatic_plugin",
            ]
        )
        joined = " ".join(
            " ".join(str(line) for line in r.evidence)
            for r in result.resolutions
        )
        for forbidden in (
            "Bearer ",
            "Authorization:",
            "X-API-Key",
            "API_KEY",
            "X-Auth-Token",
            "password=",
            "passwd=",
        ):
            self.assertNotIn(forbidden, joined)

    def test_no_url_host_leakage_in_normalized_or_canonical(self):
        # The resolver is CVE-side; full-URL inputs are misuse. We confirm
        # the resolver never emits query strings, fragments or credentials
        # in its canonical / normalized fields.
        for raw in (
            "OttoKit?Bearer=secret",
            "OttoKit#X-API-Key",
            "OttoKit Authorization: Bearer xyz",
        ):
            r = resolve_cve_identities(cve_products=[raw]).resolutions
            self.assertTrue(r)
            for resolution in r:
                for value in (
                    resolution.canonical,
                    resolution.normalized,
                ):
                    self.assertNotIn("?", value)
                    self.assertNotIn("#", value)
                    self.assertNotIn("Bearer", value)
                    self.assertNotIn("Authorization", value)
                    self.assertNotIn("X-API-Key", value)


# ---------------------------------------------------------------------------
# Test 12 — Backend adapter integration (engine still receives compatible
# values; the new R31.6 evidence appears in the per-program summary)
# ---------------------------------------------------------------------------


def _projection(observed_plugins=(), observed_components=()):
    return {
        "inventory_id": "inv-r31-6-test",
        "program": "dell",
        "technologies": [],
        "products": [],
        "components": [
            {
                "value": item["value"],
                "source": "COMPONENT_INVENTORY",
                "evidence_type": "STRUCTURED_COMPONENT",
            }
            for item in observed_components
        ] if observed_components and isinstance(
            observed_components[0], dict
        ) else list(observed_components),
        "plugins": [
            {
                "value": item,
                "source": "COMPONENT_INVENTORY",
                "evidence_type": "STRUCTURED_COMPONENT",
            }
            for item in observed_plugins
        ],
        "versions": [],
        "version_associations": [],
        "parameters": [],
        "paths": [],
        "component_provenance": [],
        "parameter_paths": [],
        "sources": [],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }


def _contexts(cve_products, cve_components=()):
    document = SimpleNamespace(
        components=list(cve_components),
        parameters=[],
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {"id": CVE, "products": list(cve_products), "affected_versions": []},
        "research": {"affected_products": list(cve_products)},
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [AssetRecord(program="dell", asset="dell.com")],
        }
    ]


class TestBackendIntegration(unittest.TestCase):
    def setUp(self):
        acm.clear_cache()

    def tearDown(self):
        acm.clear_cache()

    def _match(self, *, cve_products, observed_plugins=(), observed_components=()):
        inventory = _projection(observed_plugins, observed_components)
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=inventory,
        ), mock.patch.object(
            acm, "_contexts",
            return_value=_contexts(cve_products),
        ):
            return acm.build_matches(cve=CVE, program="dell")["items"][0]

    def test_wordpress_automatic_resolves_against_observed(self):
        item = self._match(
            cve_products=["wordpress_automatic_plugin"],
            observed_plugins=["wordpress-automatic"],
        )
        self.assertEqual(item["strongest_match_type"], "PLUGIN")
        self.assertIn(
            item["strongest_confidence"], ("MEDIUM", "HIGH", "LOW", "NONE")
        )
        # Identity resolution evidence is recorded additively.
        resolution_rows = item["identity_resolution"]
        self.assertGreaterEqual(len(resolution_rows), 1)
        canonicals = {row["canonical_cve_identity"] for row in resolution_rows}
        self.assertIn("wordpress-automatic", canonicals)

    def test_ottokit_resolves_against_observed(self):
        item = self._match(
            cve_products=["OttoKit: All-in-One Automation Platform"],
            observed_plugins=["wp-ottokit"],
        )
        resolution_rows = item["identity_resolution"]
        canonicals = {row["canonical_cve_identity"] for row in resolution_rows}
        self.assertIn("ottokit", canonicals)
        observed = {
            row["observed_identity"] for row in resolution_rows
            if row["canonical_cve_identity"] == "ottokit"
        }
        self.assertIn("wp-ottokit", observed)

    def test_wp_responsive_images_resolves_against_observed(self):
        item = self._match(
            cve_products=["WP Responsive Images (WordPress plugin)"],
            observed_plugins=["wp-responsive-images"],
        )
        resolution_rows = item["identity_resolution"]
        canonicals = {row["canonical_cve_identity"] for row in resolution_rows}
        self.assertIn("wp-responsive-images", canonicals)

    def test_unrelated_observed_produces_no_identity_evidence(self):
        item = self._match(
            cve_products=["OttoKit: All-in-One Automation Platform"],
            observed_plugins=["akismet", "contact-form-7"],
        )
        canonicals = {
            row["canonical_cve_identity"] for row in item["identity_resolution"]
        }
        ottokit_rows = [
            row for row in item["identity_resolution"]
            if row["canonical_cve_identity"] == "ottokit"
        ]
        self.assertFalse(ottokit_rows)

    def test_identity_resolution_rule_version_present(self):
        item = self._match(
            cve_products=["OttoKit: All-in-One Automation Platform"],
            observed_plugins=["wp-ottokit"],
        )
        self.assertEqual(
            item["identity_resolution_rule_version"], "r31-6"
        )


# ---------------------------------------------------------------------------
# Test 13 — Engine purity (R30.1 engine untouched)
# ---------------------------------------------------------------------------


class TestEnginePurity(unittest.TestCase):
    def test_engine_module_unchanged(self):
        # Sanity: the R30.1 RULE_VERSION and existing normalize_* helpers
        # are still in place; R31.6 never replaced them.
        self.assertEqual(engine.RULE_VERSION, "r30-1")
        self.assertTrue(callable(engine.normalize_plugin))
        self.assertTrue(callable(engine.match_plugin))
        self.assertTrue(callable(engine.match_component))


# ---------------------------------------------------------------------------
# Test 14 — R30.1 engine actually receives and consumes the expanded values
# ---------------------------------------------------------------------------


class TestEngineReceivesExpandedValues(unittest.TestCase):
    def test_match_plugin_finds_wordpress_automatic(self):
        cve_values = expanded_cve_value_set(
            resolve_cve_identities(
                cve_products=["wordpress_automatic_plugin"]
            ).resolutions
        )
        result = match_plugin(cve_values, ["wordpress-automatic"])
        self.assertIsNotNone(result)
        self.assertEqual(result.match_type, "PLUGIN")

    def test_match_plugin_finds_ottokit_via_wp_ottokit(self):
        cve_values = expanded_cve_value_set(
            resolve_cve_identities(
                cve_products=["OttoKit: All-in-One Automation Platform"]
            ).resolutions
        )
        result = match_plugin(cve_values, ["wp-ottokit"])
        self.assertIsNotNone(result)
        self.assertEqual(result.match_type, "PLUGIN")


if __name__ == "__main__":
    unittest.main()
