# utils/common.py
import os
import subprocess
import tempfile
import random
import string
from datetime import datetime
import ipaddress

# Module-level PATH for Watch subprocesses (non-interactive shells under
# systemd do not source ~/.zshrc, so tool directories must be explicit).
#
# systemd compatibility: the production units run as User=root with
#   PATH=/opt/watch/venv/bin:/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin
# so this list must work with exactly that PATH. In particular it must NOT
# depend on any interactive user's home directory (e.g. /home/pouya_behnia/go/bin
# is NOT on the systemd PATH); the current user's ~/go/bin is picked up
# dynamically via $HOME so developer shells keep working without hardcoding
# any username into the codebase.
def _build_watch_tool_path():
    parts = ["/opt/watch/venv/bin"]
    home = os.environ.get("HOME")
    if home:
        parts.append(os.path.join(home, "go", "bin"))
    parts += [
        "/root/go/bin",
        "/usr/local/go/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ]
    seen = set()
    ordered = []
    for p in parts:
        if p and p not in seen:
            seen.add(p)
            ordered.append(p)
    return ":".join(ordered)


WATCH_TOOL_PATH = _build_watch_tool_path()


class ToolError(RuntimeError):
    """Raised when a required external tool is missing or fails.

    Fail-fast signal for the scheduled pipeline: a missing/failing required
    binary must abort the affected job with a non-zero exit status, never be
    interpreted as an empty ("0 results") outcome.
    """


class ToolTimeout(ToolError):
    """A required external tool exceeded its time budget.

    Separate from a generic ToolError so callers can distinguish a hang from a
    hard failure. It is still a ToolError, so existing fail-fast handling keeps
    working unchanged.
    """


# Upper bound for one NS/DNS shell command (a per-domain bulk `dnsx` call over
# the collected subdomains, or a single-label wildcard probe). The bulk call is
# rate-limited to ~30 DNS requests/second, so the largest realistic domains need
# many minutes; 1 hour leaves headroom for those while still bounding a hung
# resolver or tool instead of blocking the pipeline forever. Adjust here (one
# constant) if the resolver rate limit or typical domain size changes.
NS_COMMAND_TIMEOUT = 3600


def tool_env(extra=None):
    """Environment for Watch subprocesses with the canonical tool PATH first."""
    env = dict(os.environ)
    if extra:
        env.update(extra)
    base_path = env.get("PATH")
    env["PATH"] = WATCH_TOOL_PATH + ":" + base_path if base_path else WATCH_TOOL_PATH
    return env


def find_tool(name):
    """Resolve a required binary via the canonical tool PATH (or None)."""
    import shutil
    env_path = os.environ.get("PATH")
    search_path = WATCH_TOOL_PATH + ":" + env_path if env_path else WATCH_TOOL_PATH
    return shutil.which(name, path=search_path)


def require_tool(name):
    """Return the resolved path of a required binary or raise ToolError.

    The error names the exact missing command so systemd logs and Telegram
    failure notifications identify the broken tooling immediately.
    """
    resolved = find_tool(name)
    if not resolved:
        raise ToolError(
            f"required tool not found: {name} "
            f"(searched PATH={WATCH_TOOL_PATH})"
        )
    return resolved


def require_tools(names):
    """Preflight: fail fast when any required binary is unavailable."""
    return [require_tool(name) for name in names]

# Shared color codes
class colors:
    GRAY = "\033[90m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

# Shared time formatter
def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Common zsh runner (non-shell)
def run_command_in_zsh_common(command):
    try:
        env = os.environ.copy()
        env["PATH"] = WATCH_TOOL_PATH + ":" + env["PATH"] if env.get("PATH") else WATCH_TOOL_PATH
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"{colors.YELLOW}[{current_time()}] Error: {result.stderr.strip()}{colors.RESET}")
            return []
        return result.stdout.splitlines()
    except Exception as exc:
        print(f"{colors.RED}[{current_time()}] Exception: {exc}{colors.RESET}")
        return []

def run_command_in_zsh_http(command):
    try:
        env = os.environ.copy()
        env["PATH"] = WATCH_TOOL_PATH + ":" + env["PATH"] if env.get("PATH") else WATCH_TOOL_PATH
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"[{current_time()}] Error executing command: {result.stderr}")
            return False
        return result.stdout
    except Exception as e:
        print(f"[{current_time()}] Exception in run_command_in_zsh: {e}")
        return []
    
# NS zsh runner (shell=True)
def _bounded_tail(text, limit=500):
    """Return a single bounded tail of diagnostic text (never unbounded)."""
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return "..." + text[-limit:]


def run_command_in_zsh_ns(command):
    """Run an NS/DNS shell command; raise on failure instead of returning [].

    Preserves the original successful behavior and the existing zsh/shell
    command shape. The only change is failure handling: a non-zero exit now
    raises ToolError and a hang raises ToolTimeout, so a broken dnsx can never
    be mistaken for a successful "0 results" DNS run.
    """
    env = os.environ.copy()
    env["PATH"] = WATCH_TOOL_PATH + ":" + env["PATH"] if env.get("PATH") else WATCH_TOOL_PATH
    try:
        proc = subprocess.run(
            command,
            shell=True,
            executable="/bin/zsh",
            capture_output=True,
            text=True,
            env=env,
            timeout=NS_COMMAND_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeout(
            f"command timed out after {NS_COMMAND_TIMEOUT}s: "
            f"{_bounded_tail(command, 200)}"
        ) from exc
    except OSError as exc:
        raise ToolError(
            f"command execution failed: {_bounded_tail(command, 200)}: {exc}"
        ) from exc

    if proc.returncode != 0:
        detail = (
            f"command failed (exit {proc.returncode}): "
            f"{_bounded_tail(command, 200)}"
        )
        if proc.stderr:
            detail += f" | stderr: {_bounded_tail(proc.stderr)}"
        if proc.stdout:
            detail += f" | stdout: {_bounded_tail(proc.stdout)}"
        raise ToolError(detail)

    if proc.stderr:
        print(f"{colors.YELLOW}[{current_time()}] stderr: {proc.stderr.strip()}{colors.RESET}")
    return [line for line in proc.stdout.splitlines() if line.strip()]

# Backward compatibility
run_command_in_zsh = run_command_in_zsh_common

def create_temp_file(lines):
    """Write list of strings to a temp file and return path."""
    fd, path = tempfile.mkstemp(text=True)
    with open(fd, "w") as f:
        for line in lines:
            f.write(f"{line}\n")
    return path

def normalize_ips(value):
    """Normalize dnsx 'a' field into a list of IP strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [ip for ip in value if ip]
    if isinstance(value, str):
        return [value] if value else []
    return []

def random_label(length=10):
    """Generate random subdomain label."""
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def is_private_ip(ip):
    """Check if IP is private/internal."""
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        return False

def _ip_in_cidrs(ip, cidrs):
    """Return True if IP belongs to any CIDR from list."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        return False
    except ValueError:
        return False

def detect_cdn(ips):
    """
    Detect provider label from IP list.
    Priority:
      1) Internal
      2) Cloudflare
      3) Cloudfront
      4) Fastly
      5) Akamai
      6) Normal
    """
    ip_list = normalize_ips(ips)

    if any(is_private_ip(ip) for ip in ip_list):
        return "Internal"

    if any(_ip_in_cidrs(ip, CLOUDFLARE_CIDRS) for ip in ip_list):
        return "Cloudflare"

    if any(_ip_in_cidrs(ip, CLOUDFRONT_CIDRS) for ip in ip_list):
        return "Cloudfront"

    if any(_ip_in_cidrs(ip, FASTLY_CIDRS) for ip in ip_list):
        return "Fastly"

    if any(_ip_in_cidrs(ip, AKAMAI_CIDRS) for ip in ip_list):
        return "Akamai"

    return "Normal"

CLOUDFLARE_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# AWS global ranges include CloudFront edges as well (broad heuristic)
# Note: Keeping minimal common ranges for practical detection.
CLOUDFRONT_CIDRS = [
    "13.32.0.0/15",
    "13.54.63.128/26",
    "13.59.250.0/26",
    "13.113.196.64/26",
    "13.124.199.0/24",
    "13.228.69.0/24",
    "13.233.177.192/26",
    "13.249.0.0/16",
    "13.249.128.0/17",
    "18.64.0.0/14",
    "18.160.0.0/15",
    "18.164.0.0/15",
    "18.172.0.0/15",
    "52.46.0.0/18",
    "52.82.128.0/19",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "54.239.128.0/18",
    "54.239.192.0/19",
    "99.84.0.0/16",
    "130.176.0.0/17",
    "143.204.0.0/16",
    "204.246.164.0/22",
    "204.246.168.0/22",
    "205.251.192.0/19",
    "205.251.249.0/24",
    "205.251.250.0/23",
    "205.251.252.0/23",
    "216.137.32.0/19",
]

# Fastly published ranges (commonly used)
FASTLY_CIDRS = [
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.64.0/18",
    "140.248.128.0/17",
    "146.75.0.0/16",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
]

# Akamai uses many ranges and frequent changes; this is heuristic coverage
AKAMAI_CIDRS = [
    "23.0.0.0/12",
    "23.32.0.0/11",
    "23.192.0.0/11",
    "23.64.0.0/14",
    "23.72.0.0/13",
    "23.200.0.0/13",
    "23.208.0.0/12",
    "96.6.0.0/15",
    "96.16.0.0/15",
    "104.64.0.0/10",
    "184.24.0.0/13",
]