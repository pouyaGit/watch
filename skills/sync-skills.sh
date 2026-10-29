#!/usr/bin/env bash
# Re-copy local Hermes skills from the live (curator-managed) dir into this repo.
# Snapshot only -- edit skills live in ~/.hermes/skills, then run this to version them.
set -euo pipefail
SRC="${HERMES_SKILLS:-/root/.hermes/skills}"
DST="$(cd "$(dirname "$0")" && pwd)"
BUILTINS=" hermes-agent codebase-inspection dogfood blocked-page-recovery "

# wipe previously-synced skill dirs (keep README.md + this script), then re-copy
find "$DST" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +

n=0
while IFS= read -r f; do
  d=$(dirname "$f"); name=$(basename "$d"); rel=${d#"$SRC"/}
  case "$BUILTINS" in *" $name "*) continue ;; esac
  mkdir -p "$DST/$rel"
  cp -a "$d/." "$DST/$rel/"
  n=$((n+1))
done < <(find "$SRC" -name SKILL.md -not -path "*/.archive/*")

echo "synced $n skill dirs from $SRC -> $DST"
