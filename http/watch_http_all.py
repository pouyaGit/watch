#!/usr/bin/env python3
import sys,os,json,tempfile
from datetime import datetime
import subprocess
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import *
from config import config
from utils.common import (
    colors,
    current_time,
    run_command_in_zsh_http,
)

def httpx(subdomains_array, domain):
    for subdomain in subdomains_array:
        command = (
            f"echo {subdomain} | {config().get('HTTPX_BIN')} "
            "-silent -json -favicon -fhr -tech-detect -irh -include-chain "
            "-timeout 5 -retries 3 -threads 5 -rate-limit 4 -ports 443 -extract-fqdn "
            "-H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0' "
            f"-H 'Referer: https://{subdomain}'"
        )

        print(f"{colors.GRAY}Executing HTTPx: {command}{colors.RESET}")
        results = run_command_in_zsh_http(command)
        
        if results != '':
            json_obj = json.loads(results)
            upsert_http({
                "subdomain": subdomain,
                "scope": domain,
                "ips": json_obj.get("a", ''),
                "tech": json_obj.get("tech", []),
                "title": json_obj.get("title", ''),
                "status_code": json_obj.get("status_code", ''),
                "headers": json_obj.get("header", {}),
                "url": json_obj.get("url", ''),
                "final_url": json_obj.get("final_url", ''),
                "favicon": json_obj.get("favicon", ''),
            })
    
    return True

if __name__ == "__main__":
    programs = Programs.objects().all()

    for program in programs:
        for scope in program.scopes:
            domain = scope
            obj_lives = LiveSubdomains.objects(scope=domain)
            if obj_lives:
                print(f"[{current_time()}] running HTTPx module for '{domain}'")
                
                httpx([obj_live.subdomain for obj_live in obj_lives], domain)
            
            else:
                print(f"[{current_time()}] domain '{domain}' does not exist in watchtower")