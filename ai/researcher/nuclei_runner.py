from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from ai.correlator.watch_targets import WatchTargetSelection
from ai.schemas.finding import NucleiFinding


@dataclass
class NucleiRunResult:
    target: str
    program: str
    status: str
    command: list[str]
    output: str = ""
    error: str = ""


class NucleiRunner:
    """
    Controlled Nuclei runner.

    Live execution requires BOTH:
        1. scope_status == READY_FOR_SCAN
        2. target came from the Watch selector and has a
           non-empty program.

    Default is dry-run.
    """

    def __init__(
        self,
        nuclei_binary: str = "nuclei",
        timeout: int = 120,
    ):
        self.nuclei_binary = nuclei_binary
        self.timeout = timeout

    def build_command(
        self,
        template_path: str | Path,
        target: str,
    ) -> list[str]:

        return [
            self.nuclei_binary,
            "-t",
            str(template_path),
            "-u",
            target,
            "-no-color",
        ]

    def _is_live_eligible(
        self,
        target,
    ) -> tuple[bool, str]:

        if target.scope_status != "READY_FOR_SCAN":
            return (
                False,
                "scope_status is not READY_FOR_SCAN",
            )

        if not target.target:
            return (
                False,
                "target is empty",
            )

        if not target.program:
            return (
                False,
                "program is missing",
            )

        return True, ""

    def dry_run(
        self,
        selection: WatchTargetSelection,
        template_path: str | Path,
    ) -> list[NucleiRunResult]:

        results = []

        for target in selection.targets:

            command = self.build_command(
                template_path=template_path,
                target=target.target,
            )

            eligible, reason = (
                self._is_live_eligible(
                    target
                )
            )

            if not eligible:
                status = (
                    "DRY_RUN_ONLY"
                    if target.scope_status
                    != "EXCLUDE"
                    else "EXCLUDED"
                )

                results.append(
                    NucleiRunResult(
                        target=target.target,
                        program=target.program,
                        status=status,
                        command=command,
                        error=(
                            f"{reason}; "
                            "command was not executed."
                        ),
                    )
                )
                continue

            results.append(
                NucleiRunResult(
                    target=target.target,
                    program=target.program,
                    status="READY_DRY_RUN",
                    command=command,
                )
            )

        return results

    def run(
        self,
        selection: WatchTargetSelection,
        template_path: str | Path,
        *,
        execute: bool = False,
    ) -> list[NucleiRunResult]:

        results = []

        template_path = Path(
            template_path
        )

        if not template_path.exists():
            raise FileNotFoundError(
                f"Template not found: {template_path}"
            )

        for target in selection.targets:

            command = self.build_command(
                template_path=template_path,
                target=target.target,
            )

            eligible, reason = (
                self._is_live_eligible(
                    target
                )
            )

            # ----------------------------------------------
            # Hard scope guard
            # ----------------------------------------------

            if not eligible:
                results.append(
                    NucleiRunResult(
                        target=target.target,
                        program=target.program,
                        status="BLOCKED",
                        command=command,
                        error=(
                            f"{reason}; "
                            "live execution blocked."
                        ),
                    )
                )
                continue

            # ----------------------------------------------
            # Safe default
            # ----------------------------------------------

            if not execute:
                results.append(
                    NucleiRunResult(
                        target=target.target,
                        program=target.program,
                        status="DRY_RUN",
                        command=command,
                    )
                )
                continue

            # ----------------------------------------------
            # Live execution
            # ----------------------------------------------

            try:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )

                results.append(
                    NucleiRunResult(
                        target=target.target,
                        program=target.program,
                        status=(
                            "COMPLETED"
                            if process.returncode == 0
                            else "FAILED"
                        ),
                        command=command,
                        output=(
                            process.stdout or ""
                        ),
                        error=(
                            process.stderr or ""
                        ),
                    )
                )

            except subprocess.TimeoutExpired as exc:
                results.append(
                    NucleiRunResult(
                        target=target.target,
                        program=target.program,
                        status="TIMEOUT",
                        command=command,
                        error=str(exc),
                    )
                )

            except FileNotFoundError as exc:
                results.append(
                    NucleiRunResult(
                        target=target.target,
                        program=target.program,
                        status="ERROR",
                        command=command,
                        error=(
                            "Nuclei executable not found: "
                            f"{exc}"
                        ),
                    )
                )
        return results
    def to_findings(
        self,
        *,
        cve_id: str,
        template_id: str,
        severity: str,
        selection: WatchTargetSelection,
        results: list[NucleiRunResult],
    ) -> list[NucleiFinding]:

        targets_by_name = {
            target.target: target
            for target in selection.targets
        }

        findings = []

        for result in results:

            target = targets_by_name.get(
                result.target
            )

            if target is None:
                continue

            matched = (
                result.status == "COMPLETED"
                and bool(result.output.strip())
            )

            evidence = []

            if matched:
                evidence.append(
                    "Nuclei produced output for the target."
                )

            if result.error:
                evidence.append(
                    result.error
                )

            findings.append(
                NucleiFinding(
                    cve_id=cve_id,
                    target=result.target,
                    program=result.program,
                    template_id=template_id,
                    severity=severity,
                    matched=matched,
                    scope_status=(
                        target.scope_status
                    ),
                    presence_status=(
                        target.presence_status
                    ),
                    version_status=(
                        target.version_status
                    ),
                    evidence=evidence,
                    raw_output=result.output,
                    error=(
                        result.error
                        or None
                    ),
                )
            )

        return findings