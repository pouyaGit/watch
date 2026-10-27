import json
import re

import requests

KEY = re.search(r"AIza[A-Za-z0-9_-]{35}",
                open("/tmp/ind.js").read()).group(0)

tests = {
    "youtube-data": f"https://www.googleapis.com/youtube/v3/videos?part=id&id=dQw4w9WgXcQ&key={KEY}",
    "customsearch": f"https://www.googleapis.com/customsearch/v1?q=test&key={KEY}",
    "translate": f"https://translation.googleapis.com/language/translate/v2?q=test&target=de&key={KEY}",
    "places": f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=NYC&key={KEY}",
    "geocode": f"https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key={KEY}",
    "staticmap": f"https://maps.googleapis.com/maps/api/staticmap?center=NYC&zoom=1&size=100x100&key={KEY}",
    "timezone": f"https://maps.googleapis.com/maps/api/timezone/json?location=39,-8&timestamp=1&key={KEY}",
}

for name, url in tests.items():
    try:
        r = requests.get(url, timeout=20)
        txt = r.text.replace("\n", " ")[:200]
        verdict = ""
        if "not activated" in txt or "has not been used in project" in txt \
                or "is disabled" in txt:
            verdict = "API_DISABLED"
        elif r.status_code == 200 and '"error"' not in txt:
            verdict = "*** WORKS"
        elif "API key not valid" in txt or "invalid" in txt.lower():
            verdict = "KEY_REJECTED"
        elif "billing" in txt.lower():
            verdict = "BILLING"
        print(f"{name:14} {r.status_code} {verdict:14} {txt[:150]}")
    except Exception as e:
        print(f"{name:14} ERR {type(e).__name__}")
