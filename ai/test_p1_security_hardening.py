"""Phase P1 regression tests — security pipeline hardening.

Offline / local only. Stdlib ``unittest`` only (plus ``unittest.mock``
for call-gating proofs). No network, DNS, browser, JavaScript, Nuclei
execution, subprocess security execution, LLM, MongoDB production, or
live traffic. No test spawns a subprocess, opens a socket, or touches
a live database: ``run_task`` is exercised only on its fail-closed
paths (unknown id / unsafe script), which raise before any TaskRun
document, log file, or child process exists.

Covers:

- P1-1: legacy World A executors are marked non-production and have
  no production-reachable path.
- P1-2: task/subprocess surface rejects arbitrary job, module,
  executable, and argument injection; no shell execution.
- P1-3: only genuine 5J CONFIRMED findings reach the authoritative
  notification seam; recon notifications preserved but separate.
- P1-4: legacy XssFindings cannot become authoritative.
- P1-5: legacy Nuclei artifacts cannot become authoritative.
- Global invariants: sole finding materializer (5J), exactly one
  authoritative ``sealed-finding/v1``, no legacy object crosses
  into 5J, no live execution enabled by this phase.
"""

from __future__ import annotations

import ast
import io
import os
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from ai.correlator.watch_targets import (
    WatchTarget,
    WatchTargetSelection,
)
from ai.finding.eligibility import check_eligibility
from ai.finding.legacy_block import source_references_banned
from ai.finding.materializer import (
    FindingInfrastructure,
    materialize,
)
from ai.finding.notify import (
    AlertLedgerMemory,
    FindingAlert,
    RecordingNotificationSink,
    alert_id_for,
)
from ai.finding.sealed import (
    FINDING_SCHEMA_VERSION,
    SealedFinding,
)
from ai.finding.store_memory import (
    FindingStoreMemory,
    WorkflowStoreMemory,
)
from ai.researcher.nuclei_runner import NucleiRunner, NucleiRunResult
from ai.schemas.finding import NucleiFinding
from ai.schemas.xss_finding import XSSFinding
from ai.test_deterministic_verifier import (
    AUTHZ_ORACLE,
    World,
    build_http_record,
    build_oracle_record,
)
from ai.verification.deterministic.materialization import (
    MATERIALIZATION_SCHEMA_VERSION,
)
from ai.verification.deterministic.result import compute_result_hash

import backend.task_runner as task_runner
import backend.tasks_registry as registry

import watch_xss_verify

REPO_ROOT = Path(__file__).resolve().parent.parent
FINDING_DIR = Path(__file__).parent / "finding"
DETERMINISTIC_DIR = Path(__file__).parent / "verification" / "deterministic"

LEGACY_EXECUTOR_MODULES = (
    "ai.verification.http_executor",
    "ai.verification.browser_executor",
    "ai.verification.composite_executor",
    "ai.verification.verifier",
    "ai.verification.xss_pipeline",
)

#: Modules that must never import legacy finding/executor factories.
AUTHORITATIVE_DIRS = (
    Path(__file__).parent / "finding",
    Path(__file__).parent / "execution",
    Path(__file__).parent / "evidence",
    DETERMINISTIC_DIR,
)

#: Legacy surfaces no authoritative module may import.
BANNED_LEGACY_IMPORTS = (
    "ai.schemas.xss_finding",
    "ai.schemas.finding",
    "ai.verification.verifier",
    "ai.verification.http_executor",
    "ai.verification.browser_executor",
    "ai.verification.composite_executor",
    "ai.verification.xss_pipeline",
    "ai.researcher.nuclei_runner",
    "ai.researcher.nuclei_pipeline",
    "watch_xss_verify",
    "database.db",
)


def make_infra(world: World) -> tuple[FindingInfrastructure, dict]:
    """Fresh trusted 5J infra bundle wired to one evidence world."""
    audit: list = []
    sink = RecordingNotificationSink()
    infra = FindingInfrastructure(
        evidence_reader=world.seam(),
        finding_store=FindingStoreMemory(),
        workflow_store=WorkflowStoreMemory(),
        audit_sink=audit,
        notification_sink=sink,
        alert_ledger=AlertLedgerMemory(),
    )
    return infra, {"audit": audit, "sink": sink}


def confirmed_result(world: World | None = None):
    """Genuine CONFIRMED + eligible 5I result over sealed fixtures."""
    world = world or World()
    record, _ = build_oracle_record(world)
    outcome = world.verify(record, world.authz[AUTHZ_ORACLE])
    assert outcome.accepted and outcome.result is not None
    assert outcome.result.outcome == "CONFIRMED"
    assert outcome.result.finding_eligible
    return world, record, outcome.result


def potential_result(world: World | None = None):
    """Genuine POTENTIAL 5I result over sealed fixtures."""
    world = world or World()
    record, _ = build_http_record(world)
    outcome = world.verify(record, list(world.authz.values())[0])
    assert outcome.accepted and outcome.result is not None
    assert outcome.result.outcome == "POTENTIAL"
    return world, record, outcome.result


def module_imports(source: str) -> set[str]:
    """Top-level module names imported by source (AST, prose-free)."""
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
    return imported


# ------------------------------------------------------------------
# P1-1 — legacy World A executors
# ------------------------------------------------------------------


class LegacyExecutorTests(unittest.TestCase):
    def test_legacy_executors_carry_non_production_marker(self) -> None:
        import importlib

        for name in LEGACY_EXECUTOR_MODULES:
            with self.subTest(module=name):
                module = importlib.import_module(name)
                self.assertTrue(
                    getattr(module, "LEGACY_NON_PRODUCTION", False),
                    name,
                )
                self.assertIn("NON-PRODUCTION", module.__doc__ or "")

    def test_no_reenable_flag_in_legacy_surface(self) -> None:
        paths = [REPO_ROOT / "watch_xss_verify.py"] + [
            REPO_ROOT / (name.replace(".", "/") + ".py")
            for name in LEGACY_EXECUTOR_MODULES
        ]
        for path in paths:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("ALLOW_LEGACY", source)
                self.assertNotIn("LEGACY_ENABLE", source)
                self.assertNotIn("ENABLE_LEGACY", source)

    def test_no_production_module_imports_legacy_executors(self) -> None:
        legacy = {
            "ai.verification.http_executor",
            "ai.verification.browser_executor",
            "ai.verification.composite_executor",
            "ai.verification.verifier",
            "ai.verification.xss_pipeline",
        }
        offenders: list[str] = []
        roots = [REPO_ROOT / "backend", REPO_ROOT / "api.py"]
        for root in roots:
            paths = (
                [root] if root.is_file() else sorted(root.rglob("*.py"))
            )
            for path in paths:
                source = path.read_text(encoding="utf-8")
                if module_imports(source) & legacy:
                    offenders.append(str(path))
        # Registry scripts (crawl/ns jobs) are production-launched.
        for task_id, entry in registry.TASKS_REGISTRY.items():
            source = Path(entry["script"]).read_text(encoding="utf-8")
            if module_imports(source) & legacy:
                offenders.append(f"registry:{task_id}")
        self.assertEqual(offenders, [])

    def test_legacy_entrypoint_stays_disabled(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            status = watch_xss_verify.main(["--max-cases", "5"])
        self.assertEqual(status, 2)
        self.assertIn("disabled", buf.getvalue().lower())


# ------------------------------------------------------------------
# P1-2 — task/subprocess orchestration surface
# ------------------------------------------------------------------


class TaskRegistryTests(unittest.TestCase):
    def test_registry_is_static_allowlist(self) -> None:
        self.assertEqual(
            sorted(registry.TASKS_REGISTRY),
            [
                "crawl_all",
                "crawl_fresh",
                "dns_dynamic",
                "dns_precheck",
                "dns_static",
                "param_discovery",
            ],
        )
        for task_id, entry in registry.TASKS_REGISTRY.items():
            registry._validate_entry(task_id, entry)
            rel = os.path.relpath(entry["script"], registry.PROJECT_ROOT)
            self.assertIn(
                os.path.dirname(rel), registry.ALLOWED_SCRIPT_DIRS
            )
            self.assertTrue(entry["script"].endswith(".py"))
            self.assertNotIn("watch_xss_verify", entry["script"])
            self.assertNotIn("verif", entry["script"])
            self.assertNotIn("finding", entry["script"])
            self.assertNotIn("nuclei", entry["script"].lower())

    def test_attacker_task_ids_rejected(self) -> None:
        for evil in (
            "../etc/passwd",
            "..\\windows\\evil",
            "crawl_all; rm -rf /",
            "crawl_all|evil",
            "crawl_all$(evil)",
            "crawl_all`evil`",
            "crawl_all\n--evil",
            "",
            "watch_xss_verify",
            "verify",
            "nuclei",
            "xss",
            "finding",
            "CRAWL_ALL",
            " crawl_all",
        ):
            with self.subTest(task_id=evil):
                self.assertIsNone(registry.get_task(evil))
                with self.assertRaises(ValueError):
                    task_runner.run_task(evil)

    def test_mutated_registry_escape_blocked(self) -> None:
        evil_entries = (
            {"script": "/tmp/evil.py", "default_args": []},
            {"script": "/etc/cron.d/evil", "default_args": []},
            {
                "script": "/opt/watch/watch_xss_verify.py",
                "default_args": [],
            },
            {
                "script": "/opt/watch/ai/verification/verifier.py",
                "default_args": [],
            },
            {
                "script": "crawl/watch_crawl_all.py",
                "default_args": [],
            },
            {
                "script": "/opt/watch/crawl/../watch_xss_verify.py",
                "default_args": [],
            },
        )
        for entry in evil_entries:
            with self.subTest(script=entry["script"]):
                with mock.patch.object(
                    task_runner, "get_task", return_value=entry
                ):
                    with self.assertRaises(ValueError):
                        task_runner.run_task("crawl_all")

    def test_registry_validation_rejects_bad_entries(self) -> None:
        bad = (
            (
                "evil",
                {"script": "/tmp/evil.py", "default_args": []},
            ),
            (
                "evil",
                {
                    "script": "/opt/watch/ai/verification/verifier.py",
                    "default_args": [],
                },
            ),
            (
                "evil",
                {
                    "script": "/opt/watch/watch_xss_verify.py",
                    "default_args": [],
                },
            ),
            (
                "evil",
                {
                    "script": "/opt/watch/crawl/job.sh",
                    "default_args": [],
                },
            ),
            (
                "evil",
                {
                    "script": "/opt/watch/crawl/job.py",
                    "default_args": ["ok", "a;evil"],
                },
            ),
            (
                "evil;id",
                {
                    "script": "/opt/watch/crawl/job.py",
                    "default_args": [],
                },
            ),
            (
                "evil",
                {
                    "script": "/opt/watch/crawl/job.py",
                    "default_args": "not-a-list",  # type: ignore[dict-value]
                },
            ),
        )
        for task_id, entry in bad:
            with self.subTest(task_id=task_id, entry=entry):
                with self.assertRaises((ValueError, TypeError)):
                    registry._validate_entry(task_id, entry)

    def test_no_shell_execution_path(self) -> None:
        source = (REPO_ROOT / "backend" / "task_runner.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("shell=True", source)
        tree = ast.parse(source, filename="task_runner.py")
        popen_kw = [
            kw.arg
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(getattr(node, "func", None), "attr", "")
            == "Popen"
            for kw in node.keywords
        ]
        self.assertNotIn("shell", popen_kw)
        # Spawn inputs come exclusively from the validated registry
        # entry (interpreter + confined script + static args).
        self.assertIn("VENV_PYTHON, script_path", source)
        self.assertIn("_assert_script_confined", source)

    def test_no_dynamic_registry_extension_point(self) -> None:
        source = (REPO_ROOT / "backend" / "tasks_registry.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source, filename="tasks_registry.py")
        funcs = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for dynamic in (
            "register",
            "add_task",
            "update_task",
            "load_registry",
            "exec",
            "eval",
        ):
            self.assertNotIn(dynamic, funcs)
        # TaskSchedule exists as an unused Phase-2 model only: no
        # runner/router code consumes it.
        for path in sorted((REPO_ROOT / "backend").rglob("*.py")):
            if path.name == "models.py":
                continue
            self.assertNotIn(
                "TaskSchedule", path.read_text(encoding="utf-8"), path.name
            )


# ------------------------------------------------------------------
# P1-3 — finding/alert boundary
# ------------------------------------------------------------------


class NotificationBoundaryTests(unittest.TestCase):
    def test_potential_cannot_notify(self) -> None:
        world, _, result = potential_result()
        infra, ctx = make_infra(world)
        out = materialize(result, infra)
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)
        self.assertEqual(ctx["sink"].published, [])

    def test_unknown_cannot_notify(self) -> None:
        world, _, result = confirmed_result()
        unknown = result.model_copy(update={"outcome": "UNKNOWN"})
        infra, ctx = make_infra(world)
        out = materialize(unknown, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(ctx["sink"].published, [])

    def test_legacy_objects_cannot_notify(self) -> None:
        world, _, _ = confirmed_result()
        infra, ctx = make_infra(world)
        legacy_xss = XSSFinding(
            finding_id="xf-" + "1" * 32,
            case_id="case-1",
            target="https://example.com/",
            endpoint="https://example.com/?q=1",
            method="GET",
            xss_type="reflected",
            context_type="html_body",
            status="CONFIRMED",
            confidence=0.99,
            payload_reference="<script>alert(1)</script>",
        )
        legacy_nuclei = NucleiFinding(
            cve_id="CVE-2026-0001",
            target="https://example.com/",
            program="acme",
            template_id="cve-2026-0001",
            severity="critical",
            matched=True,
            scope_status="in_scope",
            presence_status="present",
            version_status="affected",
            raw_output="[critical] matched stdout",
        )
        for legacy in (legacy_xss, legacy_nuclei, {"finding_id": "x"}):
            with self.subTest(kind=type(legacy).__name__):
                out = materialize(legacy, infra)
                self.assertFalse(out.accepted)
                self.assertIsNone(out.finding)
        self.assertEqual(ctx["sink"].published, [])

    def test_only_genuine_confirmed_reaches_seam(self) -> None:
        world, _, result = confirmed_result()
        infra, ctx = make_infra(world)
        out = materialize(result, infra)
        self.assertTrue(out.accepted)
        assert out.finding is not None
        self.assertEqual(len(ctx["sink"].published), 1)
        alert = ctx["sink"].published[0]
        # Notification fields derive from the sealed finding only.
        self.assertIsInstance(alert, FindingAlert)
        self.assertEqual(alert.finding_id, out.finding.finding_id)
        self.assertEqual(alert.program_name, out.finding.program_name)
        self.assertEqual(alert.severity, out.finding.severity)
        self.assertEqual(
            alert.classification_hash,
            compute_result_hash(result),
        )
        self.assertEqual(
            alert.alert_id, alert_id_for(out.finding.finding_id)
        )

    def test_dedup_replay_does_not_renotify(self) -> None:
        world, _, result = confirmed_result()
        infra, ctx = make_infra(world)
        first = materialize(result, infra)
        second = materialize(result, infra)
        self.assertTrue(first.accepted)
        self.assertTrue(second.accepted)
        self.assertTrue(second.deduplicated)
        self.assertEqual(len(ctx["sink"].published), 1)

    def test_sink_rejects_arbitrary_caller_objects(self) -> None:
        sink = RecordingNotificationSink()
        for bogus in (
            "alert-text",
            {"finding_id": "xf-" + "0" * 32},
            XSSFinding(
                finding_id="xf-" + "2" * 32,
                case_id="case-2",
                target="https://example.com/",
                endpoint="https://example.com/",
                method="GET",
                xss_type="reflected",
                context_type="html_body",
                status="CONFIRMED",
                confidence=1.0,
            ),
        ):
            with self.subTest(bogus=type(bogus).__name__):
                with self.assertRaises(TypeError):
                    sink.publish(bogus)  # type: ignore[arg-type]
        self.assertEqual(sink.published, [])

    def test_recon_notifications_preserved_and_separate(self) -> None:
        import database.notifications as recon

        for name in (
            "notify_title_change",
            "notify_status_change",
            "notify_new_http",
        ):
            self.assertTrue(callable(getattr(recon, name)), name)
        # No 5J module references the recon notification surface:
        # finding alerts originate from FINDING_PERSISTED only.
        for path in sorted(FINDING_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            for token in (
                "send_message",
                "notify_title_change",
                "notify_status_change",
                "notify_new_http",
                "telegram",
            ):
                self.assertNotIn(token, source, path.name)


# ------------------------------------------------------------------
# P1-4 — legacy XssFindings persistence surface
# ------------------------------------------------------------------


class XssFindingsBoundaryTests(unittest.TestCase):
    def test_schema_marked_legacy_non_authoritative(self) -> None:
        # AST-only: importing database.db would construct a (lazy,
        # never-dialed) Mongo client at module load, so the schema
        # marker is verified from source — strictly offline.
        source = (REPO_ROOT / "database" / "db.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source, filename="db.py")
        docs = [
            ast.get_docstring(node) or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            and node.name == "XssFindings"
        ]
        self.assertEqual(len(docs), 1)
        self.assertIn("LEGACY", docs[0])
        self.assertIn("NON-AUTHORITATIVE", docs[0])
        self.assertIn("5J", docs[0])

    def test_only_disabled_job_writes_xss_findings(self) -> None:
        referrers: dict[str, list[int]] = {}
        for path in sorted(REPO_ROOT.rglob("*.py")):
            if "agent-reports" in path.parts or path.name.startswith(
                "test_"
            ):
                continue
            try:
                tree = ast.parse(
                    path.read_text(encoding="utf-8"), filename=path.name
                )
            except (OSError, SyntaxError):
                continue
            lines = [
                node.lineno
                for node in ast.walk(tree)
                if isinstance(node, ast.Name)
                and node.id == "XssFindings"
            ] + [
                node.lineno
                for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef)
                and node.name == "XssFindings"
            ]
            if lines:
                referrers[str(path.relative_to(REPO_ROOT))] = lines
        self.assertEqual(
            sorted(referrers),
            ["database/db.py", "watch_xss_verify.py"],
        )

    def test_no_authoritative_module_uses_xss_findings(self) -> None:
        offenders: list[str] = []
        for directory in AUTHORITATIVE_DIRS:
            for path in sorted(directory.glob("*.py")):
                source = path.read_text(encoding="utf-8")
                if source_references_banned(source):
                    offenders.append(str(path))
        self.assertEqual(offenders, [])

    def test_5j_never_writes_xss_findings(self) -> None:
        world, _, result = confirmed_result()
        infra, _ = make_infra(world)
        out = materialize(result, infra)
        self.assertTrue(out.accepted)
        # The only stores 5J touches are the injected memory seams.
        self.assertIn(
            out.finding_id,
            infra.finding_store.list_ids(result.program_name),
        )
        for path in sorted(FINDING_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=path.name)
            names = {
                node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
            } | {
                node.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
            }
            self.assertNotIn("XssFindings", names, path.name)
            self.assertNotIn("mongo_persist", names, path.name)
        imports = set()
        for path in sorted(FINDING_DIR.glob("*.py")):
            imports |= module_imports(path.read_text(encoding="utf-8"))
        for banned in ("mongoengine", "pymongo", "database", "watch_xss_verify"):
            self.assertFalse(
                any(
                    mod == banned or mod.startswith(banned + ".")
                    for mod in imports
                ),
                banned,
            )

    def test_legacy_xss_finding_cannot_enter_authoritative_store(self) -> None:
        world, _, _ = confirmed_result()
        infra, _ = make_infra(world)
        legacy = XSSFinding(
            finding_id="xf-" + "3" * 32,
            case_id="case-3",
            target="https://example.com/",
            endpoint="https://example.com/?q=1",
            method="GET",
            xss_type="reflected",
            context_type="html_body",
            status="POTENTIAL",
            confidence=0.5,
        )
        out = materialize(legacy, infra)
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)
        self.assertEqual(infra.finding_store.list_ids("acme"), ())


# ------------------------------------------------------------------
# P1-5 — legacy Nuclei finding artifacts
# ------------------------------------------------------------------


class NucleiBoundaryTests(unittest.TestCase):
    def _selection(self) -> WatchTargetSelection:
        return WatchTargetSelection(
            cve_id="CVE-2026-0001",
            targets=[
                WatchTarget(
                    target="https://example.com/",
                    program="acme",
                    technology="tech",
                    product_match="match",
                    version_status="affected",
                    presence_status="present",
                    presence_version=None,
                    scope_status="READY_FOR_SCAN",
                    scope_reason="test",
                )
            ],
            excluded=[],
            candidate_count=1,
        )

    def test_to_findings_output_cannot_enter_5j(self) -> None:
        runner = NucleiRunner()
        findings = runner.to_findings(
            cve_id="CVE-2026-0001",
            template_id="cve-2026-0001",
            severity="critical",
            selection=self._selection(),
            results=[
                NucleiRunResult(
                    target="https://example.com/",
                    program="acme",
                    status="COMPLETED",
                    command=["nuclei"],
                    output="[critical] template matched",
                )
            ],
        )
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].matched)
        world, _, _ = confirmed_result()
        infra, _ = make_infra(world)
        for finding in findings:
            out = materialize(finding, infra)
            self.assertFalse(out.accepted)
            self.assertIsNone(out.finding)
        self.assertEqual(infra.finding_store.list_ids("acme"), ())

    def test_caller_severity_cannot_become_authoritative(self) -> None:
        world, _, result = confirmed_result()
        infra, _ = make_infra(world)
        out = materialize(result, infra)
        self.assertTrue(out.accepted)
        assert out.finding is not None
        # 5J severity is verbatim 5I classification, never caller text.
        self.assertEqual(out.finding.severity, result.severity)
        forged = NucleiFinding(
            cve_id="CVE-2026-0001",
            target="https://example.com/",
            program=result.program_name,
            template_id="t",
            severity="critical",
            matched=True,
            scope_status="in_scope",
            presence_status="present",
            version_status="affected",
        )
        refused = materialize(forged, infra)
        self.assertFalse(refused.accepted)

    def test_legacy_surfaces_marked_non_authoritative(self) -> None:
        from ai.researcher import nuclei_pipeline, nuclei_runner
        from ai.schemas import finding as finding_schema

        for doc, label in (
            (NucleiRunner.__doc__, "NucleiRunner"),
            (NucleiRunner.to_findings.__doc__, "to_findings"),
            (
                nuclei_pipeline.NucleiPipeline.__doc__,
                "NucleiPipeline",
            ),
            (
                nuclei_pipeline.NucleiPipeline.save_findings.__doc__,
                "save_findings",
            ),
            (finding_schema.NucleiFinding.__doc__, "NucleiFinding"),
        ):
            with self.subTest(surface=label):
                lowered = (doc or "").lower()
                self.assertIn("non-authoritative", lowered, label)
        # Pipeline-level marker: research-only end to end.
        self.assertIn(
            "research only",
            (nuclei_pipeline.NucleiPipeline.__doc__ or "").lower(),
        )
        _ = nuclei_runner  # import-surface probe (module importable)

    def test_legacy_nuclei_json_has_no_authoritative_reader(self) -> None:
        allowed_files = {
            "ai/researcher/nuclei_pipeline.py",  # sole writer
            "ai/finding/legacy_block.py",  # hard-block inventory prose
        }
        offenders: list[str] = []
        for path in sorted(REPO_ROOT.rglob("*.py")):
            if "agent-reports" in path.parts:
                continue
            rel = str(path.relative_to(REPO_ROOT))
            if rel.startswith("ai/test_") or "/test_" in rel:
                continue
            if "/tests/" in rel:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if "nuclei/findings" in source and rel not in allowed_files:
                offenders.append(rel)
        self.assertEqual(offenders, [])


# ------------------------------------------------------------------
# Global security invariants
# ------------------------------------------------------------------


class AuthorityInvariantTests(unittest.TestCase):
    def test_exactly_one_authoritative_sealed_finding_v1(self) -> None:
        self.assertEqual(FINDING_SCHEMA_VERSION, "sealed-finding/v1")
        self.assertEqual(
            MATERIALIZATION_SCHEMA_VERSION, "5i-materialized-finding/v1"
        )
        self.assertNotEqual(
            FINDING_SCHEMA_VERSION, MATERIALIZATION_SCHEMA_VERSION
        )
        import ai.verification.deterministic as det

        self.assertFalse(hasattr(det, "SealedFinding"))

    def test_no_authoritative_path_imports_legacy_surface(self) -> None:
        offenders: list[str] = []
        for directory in AUTHORITATIVE_DIRS:
            for path in sorted(directory.glob("*.py")):
                if path.name.startswith("test_"):
                    continue
                imported = module_imports(
                    path.read_text(encoding="utf-8")
                )
                hits = {
                    mod
                    for mod in imported
                    for banned in BANNED_LEGACY_IMPORTS
                    if mod == banned
                    or mod.startswith(banned + ".")
                }
                tree = ast.parse(
                    path.read_text(encoding="utf-8"), filename=path.name
                )
                names = {
                    node.id
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Name)
                }
                if (
                    "materialize_finding" in names
                    or "DeprecatedSeamFinding" in names
                ):
                    hits.add("<retired-5i-seam>")
                if hits:
                    offenders.append(f"{path}: {sorted(hits)}")
        self.assertEqual(offenders, [])

    def test_finding_id_deterministic_across_materializations(self) -> None:
        world, _, result = confirmed_result()
        infra, _ = make_infra(world)
        first = materialize(result, infra)
        second = materialize(result, infra)
        self.assertTrue(first.accepted)
        self.assertTrue(second.accepted)
        self.assertEqual(first.finding_id, second.finding_id)

    def test_no_live_execution_enabled(self) -> None:
        from ai.execution import browser_executor as be
        from ai.execution import http_executor as he
        from ai.execution import nuclei_executor as ne

        self.assertFalse(he.LIVE_TRAFFIC_ENABLED)
        self.assertFalse(ne.LIVE_NUCLEI)
        self.assertFalse(be.LIVE_BROWSER)


if __name__ == "__main__":
    unittest.main()
