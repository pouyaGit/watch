# utils/common.py
import subprocess
import tempfile
import random
import string
from datetime import datetime
import ipaddress

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
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{colors.YELLOW}[{current_time()}] Error: {result.stderr.strip()}{colors.RESET}")
            return []
        return result.stdout.splitlines()
    except Exception as exc:
        print(f"{colors.RED}[{current_time()}] Exception: {exc}{colors.RESET}")
        return []

def run_command_in_zsh_http(command):
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[{current_time()}] Error executing command: {result.stderr}")
            return False
        return result.stdout
    except Exception as e:
        print(f"[{current_time()}] Exception in run_command_in_zsh: {e}")
        return []
    
# NS zsh runner (shell=True)
def run_command_in_zsh_ns(command):
    proc = subprocess.run(
        command,
        shell=True,
        executable="/bin/zsh",
        capture_output=True,
        text=True
    )
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