#!/usr/bin/env python3
"""Set the dashboard password hash (argon2id). The plaintext is never stored.

  python scripts/set_dashboard_password.py          print DASHBOARD_PASS_HASH=<hash>
  python scripts/set_dashboard_password.py --write  also update DASHBOARD_PASS_HASH in .env
"""
import argparse
import getpass
import os
import sys
import tempfile

from argon2 import PasswordHasher

ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
KEY = "DASHBOARD_PASS_HASH"
MIN_LENGTH = 8


def prompt_password():
    first = getpass.getpass("New dashboard password: ")
    if len(first) < MIN_LENGTH:
        sys.exit(f"Password must be at least {MIN_LENGTH} characters.")
    if getpass.getpass("Repeat password: ") != first:
        sys.exit("Passwords do not match.")
    return first


def update_env(path, new_line):
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
        mode = os.stat(path).st_mode & 0o777
    except FileNotFoundError:
        lines, mode = [], 0o600

    out, replaced = [], False
    for line in lines:
        if "=" in line and line.split("=", 1)[0].strip() == KEY:
            if not replaced:
                out.append(new_line + "\n")
                replaced = True
            continue
        out.append(line)
    if not replaced:
        if out and not out[-1].endswith("\n"):
            out[-1] += "\n"
        out.append(new_line + "\n")

    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.writelines(out)
    os.chmod(tmp_path, mode)
    os.replace(tmp_path, path)


def main():
    parser = argparse.ArgumentParser(description="Set the dashboard login password hash")
    parser.add_argument("--write", action="store_true", help=f"update {KEY} in {ENV_PATH}")
    args = parser.parse_args()

    password = prompt_password()
    line = f"{KEY}={PasswordHasher().hash(password)}"
    print(line)

    if args.write:
        update_env(ENV_PATH, line)
        print(f"Updated {KEY} in {ENV_PATH}. Restart the dashboard service to apply.", file=sys.stderr)


if __name__ == "__main__":
    main()
