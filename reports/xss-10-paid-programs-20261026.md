# 10 paid-program hunt — final report

Date: 2026-10-26
Engagement: 10 bounty:true programs across HackerOne/Bugcrowd/YesWeHack/Intigriti
Selected from projectdiscovery/public-bugbounty-programs (530 bounty:true entries)

## Targets (10)
1. Acronis (HackerOne) — acronis.com, 5nine.com, devicelock.com, acronis.work
2. Airbnb (HackerOne) — byairbnb.com, luckey.app, withairbnb.com, airbnbcitizen.com, luckey.fr
3. Algolia (HackerOne) — algolianet.com, algolia.com, algolia.net
4. Asana (Bugcrowd) — asana.com, asana.plus, asana.biz
5. Binance (Bugcrowd) — binance.com, binance.org, binance.co.ug, binance.je, binance.sg
6. Cisco Meraki (Bugcrowd) — ikarem.io, meraki.com, network-auth.com, cisco.com
7. BlaBlaCar (YesWeHack) — blablacar.fr/de/co.uk/in/es ...
8. Dailymotion (YesWeHack) — dailymotion.com, dmcdn.net, dailymotionadvertising.com, dm.gg, dmxleo.com
9. Doctolib (YesWeHack) — doctolib.fr/de/it/com/net
10. SBB — Swiss Federal Railways (Intigriti) — sbb.ch, sbbmobile.ch, swisspass.ch, elvetino.ch, sbbcargo.com

## Method
- Scope checked against programs/*.json before any request.
- Browser-driven DOM XSS (Chromium, hook proven at document-start: alert + innerHTML +
  document.write + insertAdjacentHTML, validated on a control page).
- Reflected-XSS sweep with unique canary, baseline control, raw-vs-encoded classification.
- Sink instrumentation, not just alert().
- No sequential ID enumeration, no credential guessing.

## Results
- Acronis / Algolia / Asana / Binance / Cisco Meraki / BlaBlaCar / Doctolib / SBB:
  either Cloudflare-blocked or no reachable search/reflection surface from this IP.
- Dailymotion: the query IS reflected into <title> and the page body, but as
  HTML-escaped text ("&gt;&lt;svg onload=alert(40931)&gt;"). The browser does not
  execute it; no sink writes the canary; no live element carries an onload attr.
  This is a correct encoding, not an XSS.
- No XSS executed on any of the 10 programs.

## Conclusion
No reportable XSS found. The honest blockers are the same as on the previous
engagement: Cloudflare on most hosts, and no account/write surface reachable
from this IP for stored XSS. Dailymotion is the one program worth revisiting
with an account session and a proxy, because it does reflect the query verbatim
into the document title — a real reflection surface that is currently correctly
escaped.
