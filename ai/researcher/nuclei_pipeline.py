from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ai.collectors.nuclei_template import NucleiTemplateParser
from ai.correlator.nuclei_decision import NucleiDecisionEngine
from ai.correlator.nuclei_generator import NucleiTemplateGenerator
from ai.correlator.nuclei_validator import NucleiSemanticValidator
from ai.correlator.watch_targets import WatchAssetSelector
from ai.researcher.nuclei_runner import NucleiRunner
from ai.schemas.finding import NucleiFinding
from ai.schemas.research import ResearchResult


class NucleiPipeline:
    """
    End-to-end Nuclei preparation pipeline.

    ResearchResult
        ↓
    DetectionSpec
        ↓
    Decision
        ↓
    Generate
        ↓
    Semantic validation
        ↓
    nuclei -validate
        ↓
    Watch target selection
        ↓
    Scope policy
        ↓
    Dry-run
        ↓
    Finding normalization

    Live scanning is not performed by this class.
    """

    def __init__(
        self,
        output_dir: str | Path = (
            "ai_data/nuclei/generated"
        ),
        result_dir: str | Path = (
            "ai_data/nuclei/results"
        ),
        finding_dir: str | Path = (
            "ai_data/nuclei/findings"
        ),
    ):
        self.output_dir = Path(output_dir)
        self.result_dir = Path(result_dir)
        self.finding_dir = Path(finding_dir)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.result_dir.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.finding_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.parser = NucleiTemplateParser()
        self.decision_engine = NucleiDecisionEngine()
        self.generator = NucleiTemplateGenerator()
        self.validator = NucleiSemanticValidator()
        self.target_selector = WatchAssetSelector()
        self.runner = NucleiRunner()

    def _validate_with_nuclei(
        self,
        template_path: Path,
    ) -> tuple[bool, str]:
        try:
            process = subprocess.run(
                [
                    "nuclei",
                    "-validate",
                    "-t",
                    str(template_path),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return False, "nuclei executable not found"
        except subprocess.TimeoutExpired:
            return False, "nuclei validation timed out"

        output = (
            process.stdout
            + "\n"
            + process.stderr
        ).strip()

        success = (
            process.returncode == 0
            and "All templates validated successfully"
            in output
        )

        return success, output

    def prepare_for_watch(
        self,
        *,
        cve,
        research: ResearchResult,
        source_template: str | Path,
        technology_index,
        name: str,
        severity: str = "high",
        description: str = "",
        tags: list[str] | None = None,
    ) -> dict:

        cve_id = cve.title
        source_path = Path(source_template)

        if not source_path.exists():
            raise FileNotFoundError(
                f"Source template not found: {source_path}"
            )

        result = {
            "cve_id": cve_id,
            "decision": None,
            "decision_confidence": 0.0,
            "generated": False,
            "semantic_valid": False,
            "nuclei_valid": False,
            "template_path": None,
            "candidate_count": 0,
            "target_count": 0,
            "targets": [],
            "run_results": [],
            "findings": [],
            "errors": [],
            "warnings": [],
        }

        # --------------------------------------------------
        # DetectionSpec
        # --------------------------------------------------

        try:
            source_content = source_path.read_text(
                encoding="utf-8"
            )

            detection = self.parser.parse(
                content=source_content,
                cve_id=cve_id,
            )
        except Exception as exc:
            result["errors"].append(
                f"DetectionSpec error: "
                f"{type(exc).__name__}: {exc}"
            )
            return result

        # --------------------------------------------------
        # Decision
        # --------------------------------------------------

        try:
            decision = self.decision_engine.decide(
                cve=cve,
                research=research,
                detection=detection,
            )
        except Exception as exc:
            result["errors"].append(
                f"Decision error: "
                f"{type(exc).__name__}: {exc}"
            )
            return result

        result["decision"] = decision.decision
        result["decision_confidence"] = decision.confidence

        if decision.decision != "GOOD_CANDIDATE":
            result["warnings"].append(
                "Pipeline stopped before generation: "
                f"decision={decision.decision}"
            )
            return result

        # --------------------------------------------------
        # Generate
        # --------------------------------------------------

        template_path = (
            self.output_dir
            / f"{cve_id}.yaml"
        )

        try:
            generated_content = self.generator.generate(
                detection,
                name=name,
                author="watch-ai",
                severity=severity,
                description=description,
                tags=tags,
            )

            template_path.write_text(
                generated_content,
                encoding="utf-8",
            )

            result["generated"] = True
            result["template_path"] = str(
                template_path
            )
        except Exception as exc:
            result["errors"].append(
                f"Generation error: "
                f"{type(exc).__name__}: {exc}"
            )
            return result

        # --------------------------------------------------
        # Semantic validation
        # --------------------------------------------------

        try:
            semantic = self.validator.validate(
                detection,
                generated_content,
            )
        except Exception as exc:
            result["errors"].append(
                f"Semantic validation error: "
                f"{type(exc).__name__}: {exc}"
            )
            return result

        result["semantic_valid"] = semantic.valid
        result["errors"].extend(semantic.errors)
        result["warnings"].extend(semantic.warnings)

        if not semantic.valid:
            return result

        # --------------------------------------------------
        # Nuclei validation
        # --------------------------------------------------

        nuclei_valid, nuclei_output = (
            self._validate_with_nuclei(
                template_path
            )
        )

        result["nuclei_valid"] = nuclei_valid
        result["nuclei_validation_output"] = nuclei_output

        if not nuclei_valid:
            result["errors"].append(
                "nuclei -validate failed"
            )
            return result

        # --------------------------------------------------
        # Watch target selection
        # --------------------------------------------------

        try:
            selection = self.target_selector.select(
                cve=cve,
                technology_index=technology_index,
            )

            selection_dict = self.target_selector.to_dict(
                selection
            )

            result["candidate_count"] = (
                selection.candidate_count
            )
            result["target_count"] = len(
                selection.targets
            )
            result["targets"] = (
                selection_dict["targets"]
            )
            result["excluded"] = (
                selection_dict["excluded"]
            )
        except Exception as exc:
            result["errors"].append(
                f"Target selection error: "
                f"{type(exc).__name__}: {exc}"
            )
            return result

        # --------------------------------------------------
        # Dry-run
        # --------------------------------------------------

        try:
            run_results = self.runner.dry_run(
                selection=selection,
                template_path=template_path,
            )

            result["run_results"] = [
                {
                    "target": item.target,
                    "program": item.program,
                    "status": item.status,
                    "command": item.command,
                    "output": item.output,
                    "error": item.error,
                }
                for item in run_results
            ]

        except Exception as exc:
            result["errors"].append(
                f"Nuclei dry-run error: "
                f"{type(exc).__name__}: {exc}"
            )
            return result

        # --------------------------------------------------
        # Finding normalization
        #
        # Dry-run findings are informational only.
        # matched remains false because Nuclei was not run.
        # --------------------------------------------------

        findings = self.runner.to_findings(
            cve_id=cve_id,
            template_id=cve_id,
            severity=severity,
            selection=selection,
            results=run_results,
        )

        result["findings"] = [
            finding.model_dump()
            for finding in findings
        ]

        findings_path = self.save_findings(
            findings=findings,
            cve_id=cve_id,
        )

        result["findings_path"] = str(
            findings_path
        )
        
        return result

    def save_result(
        self,
        result: dict,
        output_path: str | Path | None = None,
    ) -> Path:

        if output_path is None:
            output_path = (
                self.result_dir
                / f"{result['cve_id']}.json"
            )

        path = Path(output_path)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return path

    def save_findings(
        self,
        findings: list[dict | NucleiFinding],
        cve_id: str,
    ) -> Path:

        normalized = []

        for item in findings:
            if isinstance(
                item,
                NucleiFinding,
            ):
                normalized.append(
                    item.model_dump()
                )
            else:
                normalized.append(item)

        path = (
            self.finding_dir
            / f"{cve_id}.json"
        )

        path.write_text(
            json.dumps(
                normalized,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return path