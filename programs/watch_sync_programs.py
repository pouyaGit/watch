#!/usr/bin/env python3

import os, json, sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'database')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db import upsert_program, delete_program_and_related, Programs
from config import config

def scan_directory_for_json_files(directory):
    found_programs = set()

    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            file_path = os.path.join(directory, filename)
            print(f"Processing file: {file_path}")

            with open(file_path, 'r') as file:
                try:
                    data = json.load(file)
                    program_name = data.get('program_name')
                    if not program_name:
                        print(f"[WARN] program_name missing in {file_path}")
                        continue

                    found_programs.add(program_name)
                    upsert_program(
                        program_name,
                        data.get('scopes'),
                        data.get('ooscopes'),
                        {}
                    )
                    print()
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON file {file_path}: {e}")
                    print()

    return found_programs

def delete_missing_programs(found_programs):
    # تمام برنامه‌های موجود در دیتابیس
    db_programs = {p.program_name for p in Programs.objects.only("program_name")}

    # برنامه‌هایی که دیگر فایل ندارند
    missing = db_programs - found_programs

    for program_name in missing:
        delete_program_and_related(program_name)

if __name__ == "__main__":
    directory_to_scan = config().get("WATCH_DIR") + "programs/"
    found_programs = scan_directory_for_json_files(directory_to_scan)
    delete_missing_programs(found_programs)
