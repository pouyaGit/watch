import os
import json
import ipaddress
from utils.common import (
    colors,
    current_time,
    run_command_in_zsh_ns,
    random_label,
    normalize_ips,
    create_temp_file,
)

def is_private_ip(ip):
    """Check if IP is private/internal."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def has_private_ip(ips):
    """Check if any IP in set is private."""
    return any(is_private_ip(ip) for ip in ips)

class WildcardDetector:
    """Multi-level wildcard detector using DNS A records only."""
    def __init__(self, domain):
        self.domain = domain.strip(".")
        self.wildcard_answers_cache = {}
        self.level_answers_normal_cache = set()

    def _build_levels(self, host):
        """Build wildcard levels for a given host."""
        if not host:
            return []

        host = host.strip(".")
        if not host.endswith(self.domain):
            return []

        if host == self.domain:
            return []

        sub_part = host[: -(len(self.domain))].rstrip(".")
        if not sub_part:
            return []

        labels = sub_part.split(".")
        levels = [f"*.{self.domain}"]
        for i in range(len(labels) - 1, -1, -1):
            suffix = ".".join(labels[i:])
            levels.append(f"*.{suffix}.{self.domain}")
        return levels

    def _resolve_level_ips(self, level):
        """Resolve a random label for a wildcard level and return A record IPs."""
        random_sub = level.replace("*", random_label(12), 1)
        temp_file_path = create_temp_file([random_sub])
        ips_set = set()

        try:
            cmd = (
                f"dnsx -l {temp_file_path} -silent -a -resp -json -t 10 -rl 30 "
                "-r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
            )
            results = run_command_in_zsh_ns(cmd)

            for line in results:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ips = normalize_ips(obj.get("a"))
                if ips:
                    ips_set.update(ips)

        except Exception as e:
            print(f"{colors.RED}[{current_time()}] wildcard error: {e}{colors.RESET}")

        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except Exception:
                    pass

        return ips_set

    def is_wildcard(self, host, ips, preserve_private=True):
        """
        Check if host result should be filtered as wildcard.
        """
        if not host or not ips:
            return False

        ips_set = set(ips)
        levels = self._build_levels(host)
        if not levels:
            return False

        for level in levels:
            if level in self.level_answers_normal_cache:
                continue

            cached_ips = self.wildcard_answers_cache.get(level)
            if cached_ips is None:
                resolved_ips = self._resolve_level_ips(level)
                if resolved_ips:
                    self.wildcard_answers_cache[level] = resolved_ips
                    cached_ips = resolved_ips
                else:
                    self.level_answers_normal_cache.add(level)
                    continue

            if ips_set.issubset(cached_ips):
                if preserve_private and has_private_ip(ips_set):
                    return False
                return True

        return False

def get_wildcard_ips(domain, num_tests=3):
    """
    Detect wildcard IPs for a domain by testing random subdomains.
    Returns a set of wildcard IPs (may be empty).
    """
    wildcard_ips = set()

    for _ in range(num_tests):
        random_sub = f"{random_label(12)}.{domain}"
        temp_file_path = create_temp_file([random_sub])

        try:
            cmd = (
                f"dnsx -l {temp_file_path} -silent -a -resp -json -t 10 -rl 30 "
                "-r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
            )
            results = run_command_in_zsh_ns(cmd)

            if not results:
                continue

            for line in results:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    ips = normalize_ips(obj.get("a"))
                    if ips:
                        wildcard_ips.update(ips)
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            print(f"{colors.RED}[{current_time()}] wildcard error: {e}{colors.RESET}")

        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except Exception:
                    pass

    if wildcard_ips:
        print(f"{colors.YELLOW}[{current_time()}] wildcard IPs for {domain}: {', '.join(sorted(wildcard_ips))}{colors.RESET}")
    else:
        print(f"{colors.GREEN}[{current_time()}] no wildcard IPs detected for {domain}{colors.RESET}")

    return wildcard_ips

def is_wildcard_result(ips, wildcard_ips, preserve_private=True):
    """
    Return True if result should be filtered as wildcard.
    """
    if not wildcard_ips or not ips:
        return False

    is_wildcard = set(ips).issubset(wildcard_ips)

    if is_wildcard and preserve_private and has_private_ip(ips):
        return False

    return is_wildcard
