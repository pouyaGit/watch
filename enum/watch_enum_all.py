#!/usr/bin/env python3
import sys, os, subprocess, psycopg2, re, datetime, requests, random, time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'database')))
from db import *
from config import config

def run_command_in_zsh(command):
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error occurred:", result.stderr)
            return False
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as exc:
        print("Status : FAIL", exc.returncode, exc.output)



if __name__ == "__main__":
    programs = Programs.objects.all();
    for program in programs:
        print(f"[*] [{current_time()}] Enumerating for program: {program.program_name}")
        scopes = program.scopes

        for scope in scopes:
            print(f"    [*] [{current_time()}] Scope: Enumerating {scope}")
            enum_path = config().get("WATCH_DIR") + "enum/"
            run_command_in_zsh(f"python {enum_path}/watch_crtsh.py {scope}")
            run_command_in_zsh(f"python {enum_path}/watch_subfinder.py {scope}")
            run_command_in_zsh(f"python {enum_path}/watch_abuseipdb.py {scope}")
            run_command_in_zsh(f"python {enum_path}/watch_wayback.py {scope}")
       