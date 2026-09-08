"""Bounded Nuclei launcher with environment/resource gates (Phase 5K-live B6).

The ONLY module permitted to create Nuclei processes. It never does so
today: ``LIVE_LAUNCH_ENABLED`` is frozen ``False`` and the production
network sandbox is not provisioned, so every launch path ends fail-closed
(``SANDBOX_UNAVAILABLE`` / ``LIVE_LAUNCH_DISABLED``). What this module
*does* enforce structurally — each gate unit-tested offline with
injected fakes — is the complete pre-launch boundary the future
activation must pass:

- B6-E process environment: ``require_clean_launch_environment``
  reuses ``egress_guard.check_environment`` (proxy/PAC/WPAD-shaped
  variables fail closed on presence, even empty) plus a closed
  denylist of resolver/CA-shaping variables. The child receives ONLY
  the explicitly constructed allowlisted environment
  (``build_nuclei_environment`` tuples); process-environment values
  are never forwarded.
- B6-A runtime pin: server-controlled binary presence
  (``check_nuclei_binary``) + exact pinned-release verification of
  captured ``-version`` output (``require_pinned_nuclei_version`` —
  pure, server-side pin, caller cannot choose).
- B6-B/F argv discipline: ``assert_frozen_argv_supported`` (flag
  contract) + ``assert_single_target_argv`` (exactly one ``-u`` target
  and one ``-t`` template; redirect/retry/concurrency bounds present
  with exact values; redirect-enabling flags absent).
- B6-F resource enforcement: ``run_bounded_process`` spawns with
  ``shell=False`` only (string commands rejected), kills on
  wall-clock expiry (``SUBPROCESS_TIMEOUT``), enforces stdout/stderr
  caps (``SUBPROCESS_OUTPUT_LIMIT``), and applies rlimit ceilings
  (address space, CPU, process count, file descriptors, file size)
  where the platform supports them — everything actually applied is
  recorded in ``AppliedLimits`` (never claimed when unavailable).
- B6-F sandbox gate: ``require_production_sandbox`` admits only a
  provisioned production network boundary; the B3 spec mode that
  exists today (``dry-run-blocked``) is refused with
  ``SANDBOX_UNAVAILABLE``. No namespace, filter, or cgroup is claimed.

No sockets, no DNS, no HTTP client, no proxy input exists in this
module (``pinned_peer`` owns the dial path). No caller-controlled
executable, flag, target, or environment value can enter: every input
is type-gated against the genuine 5F spec records.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ai.execution import egress_guard
from ai.execution.b3_boundary import acquire_sandbox
from ai.execution.nuclei_executor import (
    ExecutorError,
    NucleiExecutionSpec,
    argv_digest_for,
    assert_frozen_argv_supported,
    require_pinned_nuclei_version,
)

try:  # POSIX-only resource ceilings (recorded when unavailable).
    import resource as _resource
except ImportError:  # pragma: no cover - non-POSIX platform
    _resource = None  # type: ignore[assignment]

__all__ = [
    "LIVE_LAUNCH_ENABLED",
    "LAUNCHER_ERROR_CODES",
    "LauncherError",
    "FORBIDDEN_LAUNCH_ENV_VARS",
    "AppliedLimits",
    "BoundedProcessResult",
    "require_clean_launch_environment",
    "check_nuclei_binary",
    "read_nuclei_version_output",
    "assert_single_target_argv",
    "require_production_sandbox",
    "run_bounded_process",
    "launch_nuclei_bounded",
]

#: Master live-launch switch. Frozen ``False`` for Phase 5K-live B6.
#: Literal constant: no configuration, constructor argument, artifact
#: value, CLI flag, database value, or caller input can change it.
LIVE_LAUNCH_ENABLED = False

#: Closed launcher-failure vocabulary (secret-free, bounded details).
LAUNCHER_ERROR_CODES = frozenset(
    {
        "BINARY_MISSING",
        "VERSION_UNKNOWN",
        "VERSION_MISMATCH",
        "PROXY_DETECTED",
        "FORBIDDEN_ENVIRONMENT",
        "ARGV_REJECTED",
        "SANDBOX_UNAVAILABLE",
        "SUBPROCESS_TIMEOUT",
        "SUBPROCESS_OUTPUT_LIMIT",
        "SUBPROCESS_KILLED",
        "LAUNCH_FAILED",
        "LIVE_LAUNCH_DISABLED",
    }
)


class LauncherError(ValueError):
    """Bounded, secret-free launcher failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in LAUNCHER_ERROR_CODES:
            raise ValueError(f"unknown launcher code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("launcher error detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


#: Exact-case resolver/CA-shaping variables that must never be set in
#: the launcher process environment. Rationale per entry:
#: HOSTALIASES / LOCALDOMAIN / RES_OPTIONS alter libc resolver
#: behavior; GODEBUG selects the Go resolver path (netdns) among
#: other runtime knobs; SSL_CERT_FILE / SSL_CERT_DIR /
#: NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE replace
#: TLS trust roots. Presence alone (any value, including empty)
#: fails closed. Proxy/PAC/WPAD shapes are covered separately by
#: ``egress_guard.check_environment`` (case-insensitive, pattern
#: based); this list covers what that guard does not claim.
FORBIDDEN_LAUNCH_ENV_VARS = frozenset(
    {
        "HOSTALIASES",
        "LOCALDOMAIN",
        "RES_OPTIONS",
        "GODEBUG",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
)

#: Minimal probe environment: PATH only. The version probe never
#: inherits proxy, resolver, CA, or caller variables.
_PROBE_ENV = {"PATH": "/usr/bin:/bin"}

#: Default version-probe deadline (seconds).
_VERSION_PROBE_TIMEOUT = 30.0


def require_clean_launch_environment(
    snapshot: Mapping[str, str] | None = None,
) -> None:
    """Fail closed on proxy-shaped or resolver/CA-shaping variables.

    ``None`` snapshots the live process environment read-only (never
    mutated). ``egress_guard.check_environment`` owns proxy/PAC/WPAD
    detection (``PROXY_DETECTED``); the closed denylist above owns
    resolver/CA shapers (``FORBIDDEN_ENVIRONMENT``). No override
    parameter exists by design.
    """

    if snapshot is None:
        env = dict(os.environ)
    elif isinstance(snapshot, Mapping):
        env = dict(snapshot)
    else:
        raise LauncherError("FORBIDDEN_ENVIRONMENT", "environment untyped")
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise LauncherError(
                "FORBIDDEN_ENVIRONMENT", "environment entry untyped"
            )
    try:
        egress_guard.check_environment(env)
    except egress_guard.EgressGuardError as exc:
        raise LauncherError("PROXY_DETECTED", "proxy-shaped environment") from exc
    for key in env:
        if key in FORBIDDEN_LAUNCH_ENV_VARS:
            raise LauncherError(
                "FORBIDDEN_ENVIRONMENT",
                f"forbidden launch variable: {key}",
            )
    return None


def check_nuclei_binary(binary_path: object) -> str:
    """Require the server-controlled binary to exist and be executable."""

    if not isinstance(binary_path, str) or not binary_path:
        raise LauncherError("BINARY_MISSING", "binary path rejected")
    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        raise LauncherError("BINARY_MISSING", "nuclei binary unavailable")
    return binary_path


def read_nuclei_version_output(
    binary_path: str,
    *,
    timeout_seconds: float = _VERSION_PROBE_TIMEOUT,
    process_factory: Callable[..., Any] | None = None,
) -> str:
    """Capture ``nuclei -disable-update-check -version`` output.

    Offline probe (no target, no scan): update checks are disabled on
    the probe command line itself and the probe inherits only
    ``_PROBE_ENV`` (no proxy/resolver/CA/caller variables). Any
    failure — missing output, timeout, spawn error — fails closed
    with ``VERSION_UNKNOWN``. ``process_factory`` is injectable for
    offline tests (defaults to ``subprocess.run``).
    """

    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 0 < timeout_seconds <= 300
    ):
        raise LauncherError("VERSION_UNKNOWN", "probe timeout rejected")
    factory = process_factory or subprocess.run
    try:
        completed = factory(
            [binary_path, "-disable-update-check", "-version"],
            capture_output=True,
            text=True,
            timeout=float(timeout_seconds),
            env=dict(_PROBE_ENV),
        )
    except Exception as exc:
        raise LauncherError(
            "VERSION_UNKNOWN", "nuclei version probe failed"
        ) from exc
    output = getattr(completed, "stdout", None)
    if not isinstance(output, str) or not output.strip():
        raise LauncherError("VERSION_UNKNOWN", "nuclei version empty")
    return output


def assert_single_target_argv(argv: object) -> tuple[str, ...]:
    """Require exactly one target + one template on a supported argv.

    Reuses ``assert_frozen_argv_supported`` for the pinned-release
    flag contract, then enforces singularity: exactly one ``-u``
    (http/https URL) and one ``-t`` (scratch-confined path). A second
    target, a second template, or any deviation is ``ARGV_REJECTED``:
    retries (``-retries 0``), redirects (``-disable-redirects``), and
    concurrency (``-concurrency 1``/``-bulk-size 1``) therefore cannot
    smuggle a second request or a second destination.
    """

    try:
        tokens = assert_frozen_argv_supported(argv)
    except ExecutorError as exc:
        raise LauncherError("ARGV_REJECTED", "argv flag contract failed") from exc
    if tokens.count("-u") != 1 or tokens.count("-t") != 1:
        raise LauncherError("ARGV_REJECTED", "argv target not singular")
    try:
        target = tokens[tokens.index("-u") + 1]
        template = tokens[tokens.index("-t") + 1]
    except IndexError as exc:
        raise LauncherError("ARGV_REJECTED", "argv operand missing") from exc
    if not target.startswith(("http://", "https://")):
        raise LauncherError("ARGV_REJECTED", "argv target rejected")
    if not template.startswith("/srv/watch/scratch/nuclei/"):
        raise LauncherError("ARGV_REJECTED", "argv template rejected")
    return tokens


@dataclass(frozen=True)
class AppliedLimits:
    """Honest accounting of rlimit ceilings applied to the child.

    ``applied`` names the ceilings the platform accepted;
    ``unavailable`` names those the platform refused or lacks. Only
    ``applied`` entries may be claimed as enforced.
    """

    applied: tuple[str, ...] = ()
    unavailable: tuple[str, ...] = ()


@dataclass(frozen=True)
class BoundedProcessResult:
    """Outcome of one bounded child execution (accounting, no verdict)."""

    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    killed: bool
    applied_limits: AppliedLimits


def _rlimit_preexec(
    *, memory_bytes: int, cpu_seconds: int, proc_limit: int, fd_limit: int,
    file_size_bytes: int,
) -> tuple[Any, AppliedLimits]:
    """Build the child-side rlimit closure (POSIX; honest accounting)."""

    if _resource is None:
        return None, AppliedLimits(
            applied=(),
            unavailable=("memory", "cpu", "proc", "fd", "file"),
        )
    goals = (
        ("memory", _resource.RLIMIT_AS, memory_bytes),
        ("cpu", _resource.RLIMIT_CPU, cpu_seconds),
        ("proc", _resource.RLIMIT_NPROC, proc_limit),
        ("fd", _resource.RLIMIT_NOFILE, fd_limit),
        ("file", _resource.RLIMIT_FSIZE, file_size_bytes),
    )
    clamped: list[tuple[str, int, int]] = []
    unavailable: list[str] = []
    for name, which, value in goals:
        try:
            hard = _resource.getrlimit(which)[1]
            ceiling = value if hard == _resource.RLIM_INFINITY else min(value, hard)
            clamped.append((name, which, ceiling))
        except (ValueError, OSError):
            unavailable.append(name)
    if not clamped:
        return None, AppliedLimits(applied=(), unavailable=tuple(u for u, _, _ in goals))

    def _apply() -> None:
        for _, which, ceiling in clamped:
            try:
                _resource.setrlimit(which, (ceiling, ceiling))
            except (ValueError, OSError):
                pass

    return _apply, AppliedLimits(
        applied=tuple(name for name, _, _ in clamped),
        unavailable=tuple(unavailable),
    )


def run_bounded_process(
    *,
    argv: tuple[str, ...] | list[str],
    env: tuple[tuple[str, str], ...],
    cwd: str,
    wall_seconds: int,
    stdout_cap_bytes: int,
    stderr_cap_bytes: int,
    memory_bytes: int,
    cpu_seconds: int,
    proc_limit: int,
    fd_limit: int,
    file_size_bytes: int,
    popen_factory: Callable[..., Any] | None = None,
) -> BoundedProcessResult:
    """Spawn one child with wall-clock, output, and rlimit bounds.

    ``shell=False`` always: ``argv`` must be a tuple/list of strings
    (a string command is rejected — no shell interpolation exists on
    this path). ``env`` is the explicit allowlist mapping (tuples, as
    built by ``build_nuclei_environment``); it is re-checked for
    proxy/forbidden shapes before spawn. On wall-clock expiry the
    child is killed and ``SUBPROCESS_TIMEOUT`` raised; over-cap
    streams raise ``SUBPROCESS_OUTPUT_LIMIT``. ``popen_factory`` is
    injectable for offline tests (defaults to ``subprocess.Popen``).
    """

    if isinstance(argv, str) or not isinstance(argv, (tuple, list)):
        raise LauncherError("ARGV_REJECTED", "argv must be a sequence")
    argv_list = list(argv)
    if not argv_list or any(not isinstance(t, str) or not t for t in argv_list):
        raise LauncherError("ARGV_REJECTED", "argv token rejected")
    if not isinstance(env, (tuple, list)) or any(
        not isinstance(pair, (tuple, list))
        or len(pair) != 2
        or not isinstance(pair[0], str)
        or not isinstance(pair[1], str)
        for pair in env
    ):
        raise LauncherError("FORBIDDEN_ENVIRONMENT", "child env rejected")
    if not isinstance(cwd, str) or not cwd:
        raise LauncherError("LAUNCH_FAILED", "child cwd rejected")
    for label, value in (
        ("wall", wall_seconds),
        ("stdout cap", stdout_cap_bytes),
        ("stderr cap", stderr_cap_bytes),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
        ):
            raise LauncherError("LAUNCH_FAILED", f"{label} rejected")
    require_clean_launch_environment(dict(env))
    preexec, applied = _rlimit_preexec(
        memory_bytes=memory_bytes,
        cpu_seconds=cpu_seconds,
        proc_limit=proc_limit,
        fd_limit=fd_limit,
        file_size_bytes=file_size_bytes,
    )
    factory = popen_factory or subprocess.Popen
    popen_kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "env": dict(env),
        "cwd": cwd,
    }
    if preexec is not None:
        popen_kwargs["preexec_fn"] = preexec
    try:
        proc = factory(argv_list, **popen_kwargs)
    except LauncherError:
        raise
    except Exception as exc:
        raise LauncherError("LAUNCH_FAILED", "process spawn failed") from exc
    try:
        stdout, stderr = proc.communicate(timeout=float(wall_seconds))
    except Exception as exc:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        raise LauncherError(
            "SUBPROCESS_TIMEOUT", "child wall deadline exceeded"
        ) from exc
    if not isinstance(stdout, (bytes, bytearray)) or not isinstance(
        stderr, (bytes, bytearray)
    ):
        raise LauncherError("LAUNCH_FAILED", "child streams untyped")
    stdout_b, stderr_b = bytes(stdout), bytes(stderr)
    if len(stdout_b) > stdout_cap_bytes or len(stderr_b) > stderr_cap_bytes:
        raise LauncherError(
            "SUBPROCESS_OUTPUT_LIMIT", "child output over cap"
        )
    code = proc.returncode
    exit_code = code if isinstance(code, int) else None
    killed = exit_code is not None and exit_code < 0
    return BoundedProcessResult(
        exit_code=exit_code,
        stdout=stdout_b,
        stderr=stderr_b,
        timed_out=False,
        killed=killed,
        applied_limits=applied,
    )


def require_production_sandbox(
    *,
    policy: object,
    execution_id: str,
    now: str,
    backend: object | None = None,
) -> Any:
    """Admit only a provisionable production network boundary.

    ``acquire_sandbox`` records the intended isolation. The http-probe
    shape is ``dry-run-blocked`` and is refused; the ``nuclei_scan``
    shape records a ``production-netns`` spec whose exact egress tuple
    set comes from the reviewed EgressPolicy. This gate then asks the
    materializer (``SystemNetnsBackend`` by default) whether the host
    can create a default-deny namespace, and refuses whenever it
    cannot (fails closed — no host-network fallback). Only the
    capability probe runs here; actual namespace materialization + the
    CREATE..TEARDOWN lifecycle happen inside
    ``ai.execution.netns_sandbox.run_nuclei_in_sandbox`` at the B8
    activation point, after the master switch. On THIS host the probe
    cannot create namespaces (no CAP_SYS_ADMIN), so every live path
    stays ``SANDBOX_UNAVAILABLE`` deterministically.
    """

    if policy is None:
        raise LauncherError(
            "SANDBOX_UNAVAILABLE", "no egress policy presented"
        )
    try:
        spec = acquire_sandbox(
            policy=policy, execution_id=execution_id, now=now
        )
    except Exception as exc:
        raise LauncherError(
            "SANDBOX_UNAVAILABLE", "sandbox acquisition failed"
        ) from exc
    if getattr(spec, "mode", "") != "production-netns":
        raise LauncherError(
            "SANDBOX_UNAVAILABLE", "production boundary not provisioned"
        )
    from ai.execution.netns_sandbox import SystemNetnsBackend

    materializer = backend if backend is not None else SystemNetnsBackend()
    try:
        caps = materializer.capabilities()
    except Exception as exc:
        raise LauncherError(
            "SANDBOX_UNAVAILABLE", "capability probe failed"
        ) from exc
    if not getattr(caps, "can_create_netns", False):
        raise LauncherError(
            "SANDBOX_UNAVAILABLE", "production sandbox not provisionable"
        )
    return spec


def launch_nuclei_bounded(
    *,
    spec: NucleiExecutionSpec,
    env_snapshot: Mapping[str, str] | None = None,
    version_output: str | None = None,
    version_reader: Callable[[], str] | None = None,
    now_iso: Callable[[], str] | None = None,
    process_factory: Callable[..., Any] | None = None,
    egress_policy: object | None = None,
    backend: object | None = None,
) -> BoundedProcessResult:
    """Full pre-launch gate chain for one closed Nuclei spec.

    Order: clean process environment → server binary presence →
    pinned-release version proof → frozen-argv contract +
    single-target assertion → spec digest coherence → production
    sandbox (refuses today) → master ``LIVE_LAUNCH_ENABLED`` switch
    (frozen ``False``). The child is spawned only past every gate;
    today no call can get past the sandbox/switch gates, so live
    egress stays DISABLED structurally. ``egress_policy`` (the
    reviewed nuclei_scan EgressPolicy) and ``backend`` (namespace
    materializer) are the B8 activation inputs; until B8 the sandbox
    gate consumes them and still refuses.
    """

    if not isinstance(spec, NucleiExecutionSpec):
        raise LauncherError("ARGV_REJECTED", "launch accepts only 5F spec")
    # 1. process environment (proxy/resolver/CA shapers fail closed).
    require_clean_launch_environment(env_snapshot)
    # 2. server-controlled binary presence.
    check_nuclei_binary(spec.argv[0] if spec.argv else "")
    # 3. pinned-release proof (server-side pin; caller cannot choose).
    if version_output is None:
        if version_reader is not None:
            try:
                version_output = version_reader()
            except LauncherError:
                raise
            except Exception as exc:
                raise LauncherError(
                    "VERSION_UNKNOWN", "version reader failed"
                ) from exc
        else:
            version_output = read_nuclei_version_output(spec.argv[0])
    try:
        require_pinned_nuclei_version(version_output)
    except ExecutorError as exc:
        if "not pinned" in exc.detail:
            raise LauncherError(
                "VERSION_MISMATCH", "nuclei version not pinned"
            ) from exc
        raise LauncherError(
            "VERSION_UNKNOWN", "nuclei version indeterminable"
        ) from exc
    # 4. frozen argv + single target/template.
    assert_single_target_argv(spec.argv)
    # 5. spec digest coherence (argv the executor built, nothing else).
    if argv_digest_for(tuple(spec.argv)) != spec.argv_digest:
        raise LauncherError("ARGV_REJECTED", "spec argv digest mismatch")
    # 6. production sandbox (refuses: not provisioned until B8).
    now = now_iso() if now_iso is not None else ""
    require_production_sandbox(
        policy=egress_policy,
        execution_id=spec.execution_id,
        now=now or "held",
        backend=backend,
    )
    # 7. master switch (frozen False; unreachable past gate 6 today).
    if LIVE_LAUNCH_ENABLED is not True:
        raise LauncherError("LIVE_LAUNCH_DISABLED", "live launch disabled")
    raise LauncherError("LIVE_LAUNCH_DISABLED", "live launch disabled")  # pragma: no cover
