#!/bin/bash

cd /opt/watch
source venv/bin/activate 2>/dev/null || true

OUT_DIR="/opt/watch/crawl/output"
mkdir -p "$OUT_DIR"
DATE=$(date +%Y%m%d_%H%M%S)

# اگر آرگومان دادی، فقط همون برنامه/دامنه
FILTER="$1"

echo "[+] Getting HTTP targets from Watch..."

if [ -n "$FILTER" ]; then
  curl -s "http://127.0.0.1:5000/api/http/all?raw=1" | grep -E '^https?://' | grep -i "$FILTER" | sort -u > "$OUT_DIR/targets_$DATE.txt"
else
  curl -s "http://127.0.0.1:5000/api/http/all?raw=1" | grep -E '^https?://' | sort -u > "$OUT_DIR/targets_$DATE.txt"
fi

TARGETS="$OUT_DIR/targets_$DATE.txt"
COUNT=$(wc -l < "$TARGETS" 2>/dev/null || echo 0)

echo "[+] Found $COUNT targets"

if [ "$COUNT" -eq 0 ]; then
  echo "[-] No targets found. Exiting."
  exit 1
fi

# نمایش چند نمونه
echo "[+] Sample targets:"
head -5 "$TARGETS"

# 1. Gospider
if command -v gospider >/dev/null 2>&1; then
  echo "[+] Running Gospider..."
  gospider -S "$TARGETS" -d 3 -c 6 --sitemap --robots -a -o "$OUT_DIR/gospider_$DATE" 2>/dev/null
else
  echo "[-] gospider not installed"
fi

# 2. Katana
if command -v katana >/dev/null 2>&1; then
  echo "[+] Running Katana..."
  katana -list "$TARGETS" -d 3 -jc -kf all -silent -o "$OUT_DIR/katana_$DATE.txt" 2>/dev/null
else
  echo "[-] katana not installed"
fi

# 3. Historical robots
echo "[+] Extracting historical robots..."
cat "$TARGETS" | sed 's|https\?://||' | cut -d/ -f1 | sort -u | while read domain; do
  curl -s --max-time 8 "https://web.archive.org/web/timemap/link/$domain/robots.txt" 2>/dev/null
done | grep -Eo 'https?://[^"<> ]+' | sort -u > "$OUT_DIR/historical_robots_$DATE.txt"

echo "[+] Done. Results in $OUT_DIR"
ls -lah "$OUT_DIR" | tail -10
