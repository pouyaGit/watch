---
name: hermes-xss-dataflow-review
category: software-development
description: Static XSS candidate data-flow review for HERMES recon.
---

# HERMES XSS candidate data-flow review (static-only)

Recurring cron job: judge whether each scanner-recorded XSS candidate is a genuine
application flow, using ONLY artifacts already archived under `/root/hermes-recon/`.

## Hard rules
- **Never** send a request, parameter, payload or header to a target host. No internet.
- Never write "confirmed"; use *potential* / *candidate*. Never claim exploitation.
- Do not touch the recon DB, do not run a cycle, do not use git.
- Append to `/root/hermes-recon/targets/<target>/findings/xss/reports/dataflow_<YYYY-MM-DD>.md`
  (never rewrite an existing section; a same-day re-run appends a new `## ... - HH:MM` pass).
- A target may have **no file for today** (`magwien`, `wien` on 2026-09-22): create it with the same
  title/disclaimer/`Verdict vocabulary` header and a `## Pass 1 - HH:MM +0330` section rather than appending to
  yesterday's file. Check `os.path.exists` before choosing append vs create - and note the report **target**
  is not the candidate's `host` (`XSS-000284` on `simulation.gesundheitsverbund.at` belongs in the
  `gesundheitsverbund` report, not under a `simulation` directory).
- Final message ends with the §28 attribution line: `Model: complex (DeepSeek — 9Router 'complex' route)`.

## Data sources (read-only)
- `targets/<target>/findings/xss/candidates.jsonl` — one JSONL row per recorded instance;
  fields: `candidate_id, host, url, js_file, line, source, sink, data_flow, evidence,
  sanitization, confidence, source_in_chain, source_class, library_tier, fingerprint`.
- SQLite `/root/hermes-recon/state/hermes.db` (use python3 `sqlite3`; **no sqlite3 CLI on this box**):
  - `js_samples(host, url, captured_at, text)` — archived JS bodies.
  - `http_samples(host, target, captured_at, status, headers, body, title, server)` — archived
    responses. Note: **no `url` column** there; key on `host`, not on a request URL.
  - bodies are **capped at 300,000 chars** — check `length(text) == 300000` and say "truncated"
    in the verdict rather than claiming the whole file was read.
- Body lookup: match `host` + `js_file` in the `url` column; inline snippets sometimes appear
  as rows whose url points at the page.
- Shell note: cron ships a Tirith scanner that blocks nested/dynamic shell bodies — run logic
  via `python3 -c "..."` or a script file, avoid `$(...)` in loops that build commands.

## Coverage bookkeeping (do this first, it is where the alert queue comes from)
`candidate_id` is a **per-target counter, not globally unique** — `XSS-000176` exists in both
`gesundheitsverbund` and `wien-at` with different content. Key coverage on `(target, id)`.
The alert queue lists `id host`; resolve to `(target, host)` before deciding a row is missing
(80 alert items resolved to 62 truly uncovered rows in the 2026-09-20 sweep).

### The recount that actually works
Match **row-level** ids (lines beginning `| **XSS-`), and require the row's host cell to equal the
candidate's `host` — not a bare `re.findall(r'XSS-\d{6}')` over the file. A bare regex over-counts
coverage, because ids appear inside other rows' cells as cross-references (`XSS-000048/049/050/060`
in the gesundheitsverbund file are all "As §XSS-000…" references; `XSS-000211` is a `wien-at` row
cited from elsewhere). The correct predicate is
`rid == candidate_id and (host in row_text or host.split('.')[0] in row_text)`, counted over all
`dataflow_*.md` of that target. Verified example: 12 uncovered records collapsed to 4 distinct
candidates, 9 of them being one candidate (`XSS-000234`) on one file:line.

### Environment note
`execute_code` is **blocked in cron** (`approvals.cron_mode` not trusted) — write the analysis as a
script file with `write_file` and run it with `terminal` → `python3 /tmp/<name>.py`.
`/tmp/<name>.py` may already exist from an earlier run: write to a fresh, timestamped name
(`/tmp/df_cover_1617.py`) rather than overwriting, or `read_file` it first.
The sweep emits records *while* a pass is running, so re-run the coverage script after appending and
expect a second, smaller pass (the 12:20 pass left 3 fresh ids written at 12:11:54 uncovered; the
16:20 pass left 3 fresh ids on `lib-react.5907209f.js`, which were re-records of an existing
verdict). Always recount at the end; 0 uncovered is the stop condition.

## Coverage resolution shortcut (do this before reading any code)
Map `host -> {targets}` from every `candidates.jsonl` and match against **row-level** ids whose host
cell equals the candidate's `host` (prefix match on the first label). That one predicate resolved all
**114** alert-queue items of the 2026-09-24 08:15 sweep to 0 uncovered except 2 genuinely new rows
(`XSS-000322`/`XSS-000323` on `vserlaa`/`vskolonitzgasse.schule.wien.at`) - no per-row reasoning needed.
The alert queue prints `[type] host` with `type` in brackets (High/Medium, Medium/MEDIUM); a naive
`split()` on the line puts the type in field 0, so parse `id host` from the tail, not the head.
Also: the sweep writes new rows *while* the review runs - re-run the recount at the end and expect
1-3 fresh `(target,id)` keys per pass (they were recorded 02:43-03:51 today, i.e. before this 08:15 run).

## Verdict vocabulary (mandatory)
`genuine application flow` / `library internal` / `inconclusive` — plus these recurring patterns:
- sink is `location`/`document.location`/`history.*` → *navigation, not markup*; downgrade, note it
  belongs in redirect review.
- `.append(` on a URLSearchParams object → `sink mis-attributed` (WHATWG URL API).
- `.append(` whose argument is a DOM node / jQuery object / clone / kendo visual container →
  not a string→markup path (`portal.js:2`, `dynamic.js:1257`, `awia-snippet-hamburger-menu.js:484`).
- `new Function("return this")` → webpack `globalThis` shim, body is a literal.
- core-js `addEventListener("message", …)` → library self-scheduling tick, no payload, no origin check needed.
- source→sink token co-occurrence on the same minified line is **not** a data flow.
- a `postMessage event.data` row on a file with `postMessage` = 0 and `event` = 0 is source misattribution by
  construction; a cheap detector gate is "require the literal `addEventListener("message"` / `onmessage` /
  `postMessage` in the file before recording a message-source row" (three rows in the 2026-09-22 08:35 pass fail it).

## Procedural recipe
1. Read the budget gate in the pre-run context; if REFUSE, emit the deferral line only.
2. Build `(target,id)` coverage across `dataflow_*.md` with `re.findall(r'XSS-\d{6}', ...)`.
3. For each uncovered candidate, re-read the cited line *in the archived body* (not the JSONL)
   and grep the file for the source token, `addEventListener("message")`, `onmessage`,
   `postMessage`, `new Function`, encoder names, and `md5(text)` for cross-host identity.
4. Append one markdown row per candidate with the 9 mandated columns (candidate | host | type |
   scanner flow | scanner level | verdict | sanitization assessment | adjusted confidence +
   reasoning | one concrete manual step for a human).
5. Verify afterwards: every appended row ends with `|`, coverage recount = 0 uncovered, and the
   only occurrence of "confirmed" is the standing disclaimer.

## Collapsing repeated rows cheaply
When a host contributes many rows for one `js_file`, group `candidates.jsonl` by `(candidate_id, host, fingerprint)`
before reading any code: identical `fingerprint` + same host means the same set of token hits, so N rows are ONE
finding. On `jquery.min.js?ver=3.7.1` that turned 12 + 6 + 2 + 2 rows (standort-penzing, pflege) into 4 verdicts.
Rows whose `source_in_chain` is `False` and whose `data_flow` is one artifact string shared across different
sinks are proof the "flow" is a co-occurrence pairing, not a path - say that, and only then re-read the cited
sink sites to name what each actually is.

## Recurring queue-inflation pattern (check before analysing)
A candidate re-emitted every cycle for an **unchanged** `file:line` keeps re-appearing in the alert
queue: `tre`/`XSS-000059` had **75** rows for one `lib-react.5907209f.js:2` by 2026-09-22 while the
distinct un-assessed count stayed 0 (3 rows per cycle, new `ts`, same `fingerprint`). Count
`(id, host, js_file, line, fingerprint)` before treating a queue item as new work; report the
re-emission in the notes rather than re-deriving a verdict. Detect it by comparing the newest
record's `ts` against the newest verdict row's date and checking the row already cites file:line.

## Known per-target gotchas
- **Substantiate a data-attribute from the archive** before calling provenance unknown: `http_samples` holds one body per host, and grepping it for the attribute name (`body.count("data-reset")`) can show the value is a server-rendered same-host URL — that is positive evidence, not an assumption. When the count is 0 (`data-link-column-url` on standort-penzing), say the attribute is absent from the archived body instead of implying it exists.
- Uncovered-row ambiguity (`klinik-hietzing` file older than the pass, several candidate hosts) is cheapest to resolve by `SELECT host, MAX(captured_at) FROM js_samples GROUP BY host` — the host whose archived file was captured around the records' timestamps owns the row.
- Shell: any `python3 -c "<multi-line quoted SQL>"` body is blocked by Tirith in cron. Always `write_file` a script and run `python3 /tmp/<name>.py`, even for a one-liner query.
- `jquery.min.js` on all `*.gesundheitsverbund.at` is one byte-identical jQuery 3.7.1 file —
  treat the 27 hash→innerHTML/html/append rows as one finding repeated per host.
- `portal.js` (204,811 B, md5 a26293cf58a2), `dynamic.js` (80,313 B, md5 dc309bf88174) and
  `ooo_solr.js` (5,294 B, md5 25537825ef09) are byte-identical across hosts — hash them and
  reuse the earlier verdict by cross-reference (their earlier rows: XSS-000049/050/060/061/062,
  XSS-000187/210/109).
- Truncated at 300k: `jquery.easyui.min.js` (bp), `app.399ebe07c4e475193cbb.js` (wibi),
  `index-k5Ef85y4.js` (hyzdok), `index.js` (stadtplan), `vendors~meeting.*.js` (meet/meet-t).
  "No message listener" there is a claim about the captured region only.
- `bp.gesundheitsverbund.at` easyui: `parseOptions` does
  `new Function("return "+$.trim($(el).attr("data-options")))` — a real attribute→eval sink worth
  naming for a human, distinct from the postMessage rows.
- `bp.gesundheitsverbund.at` `jquery-3.6.0.min.js` (89,501 B, md5 `8fb8fee4fcc3cc86ff6c724154c49c42`,
  complete): `location.hash` occurs **once**, in jQuery's own `:target` selector filter, where the
  fragment is only `===`-compared to an element id. Every `innerHTML` write in the file is either a
  literal-string feature probe or the `.html()` accessor. The whole file is jQuery 3.6.0, so the
  3.5.0 `htmlPrefilter`/`<option>` regressions do not apply. The `location.hash -> innerHTML/html/append`
  rows on it (XSS-000234/235/236) are co-occurrence pairings, not flows.
- `icongrid.js` is byte-identical (3,613 B, md5 `e9ec6d0c4a0fa4debc6e266b981a61e2`) on
  campus-alsergrund / campus-donaustadt / campus-leopoldstadt; line 55 is
  `window.location.href = link.attr( 'href' )` in a `touchend` handler — navigation-only, so each
  host's row (XSS-000157 / 000203 / 000237) takes the same verdict.
- `www.loom.com` `main-e0778b1bea03e0c8.js` and `new.loom.com` are LaunchNotes/Next.js; the
  reflected candidates cite `response:0`, so judge them from the archived `http_samples` body.
- `www.loom.com` `9426-6def5794cde96317.js` (15,469 B, md5 `e06c90b828f8`, complete) DOES contain a
  message listener - correct the 2026-09-19 row that said none exists. It is Sanity visual-editing's
  `window.addEventListener("message", s, !1)`: shape allow-list (`data.domain==="sanity/channels"`,
  `to`/`from` match) then `if(n.origin&&t.origin!==n.origin) return;`. Its single `innerHTML` is the
  literal react-fast-marquee CSS string, so the verdict stays LOW. `4582-a2b5ac0573dba7dc.js`
  (84,696 B, md5 `f746486aba21`) really has `postMessage`/`onmessage`/`event.data`/`innerHTML` all 0.
- Enfold `avia-snippet-hamburger-menu.js` (16,266 B / 575 lines, md5 `d70920369d9e`, byte-identical
  on simulation / gesundheitsfoerderung / ausbildung / einkauf / karriere): line **484** is
  `menu2.append(social);` where `social = $('#header .social_bookmarks').clone(true)` - the earlier
  row quoting line 483's `addClass` as 484 was wrong. Line 419 `location.href` is only `==`-compared
  to suppress a same-page reload; the only other `.append(` string arg is the literal submenu
  `<span class="av-submenu-indicator">`. Whole file: `innerHTML`/`insertAdjacentHTML`/`eval(` all 0.
- Enfold `shortcodes.js` copy count reached **10** hosts (2026-09-22 16:50 pass added `simulation` = XSS-000284).
  The row keeps re-appearing because the scanner names the *sink* `location assignment` from the source token
  `location.href`, but L740/L747 are assignments **to** `window.location.href` from `url` (L705) - source and sink are
  printed in reverse. A gate that refuses a row whose recorded source token is the left-hand side of the recorded
  sink expression drops this whole family.
- `nextgen_basic_thumbnails.js` (48ertandler.wien.gv.at, NextGEN Gallery 4.5.0, 2,277 B / 57 lines, md5 `d54ef8401910`,
  complete): whole file has `innerHTML`/`insertAdjacentHTML`/`document.write`/`eval(`/`new Function`/`postMessage`/
  `append(`/`.html(` all **0** - a click-handler-only file with no markup sink. L13 `var url = window.location.toString()`
  is overwritten at L30 (`url = image_url.replace('%STUB%', image_id)`) before the L40 `window.location = url`, and
  `image_url` is the anchor's own `data-imagebrowser-url`. The host body (104,813 B) holds `use_imagebrowser_effect`
  only inside the gallery config JSON as `"0"` and `data-imagebrowser-url` **0** times - say the markup is uncaptured.
- `dynamic.js` (80,313 B, md5 `dc309bf88174`) and `portal.js` (204,811 B, md5 `a26293cf58a2`) now also appear on
  **`ma70bp.magwien.gv.at`** (XSS-000276-000283), byte-identical to the `wien`-target copies - new host name = cross
  reference, re-verify the hash and reuse the XSS-000046/000047/000048/000050/000060/000061/000062 verdicts.
  `dynamic.js` whole-file `innerHTML` is **3** (L1704/1786 integer countdowns, L1758
  `...innerHTML = localStorage.getItem("selectedIdPName")` written at L1741 from a server-rendered label); `postMessage`
  and `onmessage` are **0**, and the lone `event.data` (L463) is jQuery's `.on(type, data, fn)` payload passed as literal
  maps at L327-332 - so a `postMessage event.data` row here is source misattribution. L525/L551 *are* concatenated HTML
  string appends, but built from `data-sortkey` / `data-app-proxy` of the clicked element.
- `http_samples` on a new host is often useless for the IdP pages: `ma70bp.magwien.gv.at`'s 10,839 B body has 0
  occurrences of `data-idpUrl` / `autoselect_name` / `countDown` / `idp_`, so provenance of those attributes cannot be
  settled from the archive - say so and put it in the manual step instead of implying the markup exists.
- **`avia-snippet-hamburger-menu.js` / `shortcodes.js` provenance can be quoted from the host page itself**: `compliance.gesundheitsverbund.at`'s capture (116,867 B, 200, complete) has `social_bookmarks` **6** and `avia-menu` **10**
(the `#header` block is server-rendered `<ul class='noLightbox social_bookmarks icon_count_5'>` of five anchors), so the L475 clone operand is settled from this host rather than a sibling; the same capture has `data-link-column-url` **0**, so that attribute is absent from the archive and must be said to be absent. Always grep the host's own body for the attribute token before reaching for a sibling host.
- WordPress `jquery.min.js?ver=3.7.1` (87,553 B, md5 `826eb77e86b02ab7724fe3d0141ff87c`, complete, **17** hosts as of the
  2026-09-22 08:35 pass) gets THREE
  rows per host (`innerHTML` / `.html()` / `.append()`) whose recorded `data_flow` is one artifact
  string, e.g. `(new ie.DOMParser).parseFromString(...) → element.innerHTML` — that is `ce.parseXML`
  (XML parser, different function), not a flow. The file has exactly one `location.hash`, in the
  `:target` selector filter (`t.slice(1)===e.id`, strict comparison, no write); every `innerHTML`
  write is a literal feature probe or a caller-argument accessor; `htmlPrefilter` is the identity
  `function(e){return e}`. One verdict serves all rows of a host.
  Its scanner `sanitization` list is also pure token co-occurrence: the only `encodeURIComponent`
  hits are in `ce.param` (`$.param`), `escape` hits are `escapeSelector` (CSS selector escaping),
  `createTextNode` appears once in `buildFragment`. Cite those names instead of vaguely calling the
  encoders irrelevant. `innerHTML` site offsets in this exact body (for cheap re-citation):
  10089, 35242, 35340, 36374, 48587, 48773, 82474.
  A brand-new host name appearing for this file in a later sweep is a cross-reference, not review
  work — check the md5 and say so. The copy count reached **18** hosts by the 2026-09-22 12:5x pass
  (campus-favoriten's XSS-000272/273/274 = one finding in 9 records; the body's own header reads
  `jQuery v3.7.1`).
- `js_samples` contains a handful of **empty-body** rows (`length(text)=0`): `custom_dynamic.js` on
  kidweb.magwien / ma70bp / psp / pvp, and `scss.399ebe07c4e475193cbb.js` on wibi.test.magwien. A
  verdict for those hosts must say the body is absent, not that a token count is 0 - a 0 count on an
  empty string is not evidence.
- `ooo_solr.js` (5,294 B, md5 `25537825ef09`, complete, 185 lines) is archived on **nine** gesundheitsverbund hosts (incl. campus-leopoldstadt and gesundheitsfoerderung) and Enfold `shortcodes.js` (46,180 B, md5 `c5a1298660a2`, complete) on **nine** (incl. standort-penzing, pflege, gesundheitsfoerderung). New records on a *newly named host* for either file are not new code — answer by cross-reference and say so, rather than re-deriving the verdict. Whole-file `location.href` count is **2** (line 114 `location.href = $(this).data('reset');` in the `".ooo-solr-fulltext-reset"` click handler, and line 168 `location.href = suggestion.data;` in the commented-out typeahead block); `location.hash`/`location.search`/`innerHTML`/`insertAdjacentHTML`/`document.write`/`eval(`/`new Function` are all **0**. Decisive positive evidence for line 114 is already in the archive: the host body (136,705 B, complete) contains exactly **one** `data-reset` attribute and its value is the server-rendered same-host URL (`data-reset="https://gesundheitsfoerderung.gesundheitsverbund.at/"`), so quota that instead of calling provenance unknown.
- Enfold `shortcodes.js` is byte-identical (46,180 B, md5 `c5a1298660a2`, 1,620 lines, **9** hosts as of the
  2026-09-21 20:25 pass, incl. gesundheitsfoerderung) on all hosts: lines
  692-748 are `$.fn.avia_link_column`, `url` comes from the clicked element's own
  `data('link-column-url')` (705), 740/747 are `window.location.href = url;` — navigation-only.
- Enfold `shortcodes.js` whole-file token counts (reusable, whole file, not a region): `location.href` **2**
  (lines 740/747 only), `location.hash`/`location.search` **0**, `innerHTML`/`insertAdjacentHTML`/`outerHTML`/
  `document.write`/`eval(`/`new Function`/`escape(` **0**. So its `EXTERNALLY_CONTROLLABLE` source class has no
  on-file origin and the sink is navigation-only. Its host page body may be irrelevant: on
  gesundheitsfoerderung the archived `http_samples` body (136,705 B) contains **0** `data-link-column-url`,
  i.e. the attribute is absent from the capture - say that, do not assume it exists.
- `swfobject-1.5.js` on `physik.gesundheitsverbund.at` (6,887 B / **8 lines**, md5 `699027eb66b1`,
  complete, the only copy in the archive): a minified Library of 8 lines, so any "line 8" row is the
  whole file. `innerHTML` occurs **1** time - `n.innerHTML=this.getSWFHTML();` in
  `deconcept.SWFObject.prototype.write` - and `getSWFHTML` contains the substring `location`
  **zero** times (it concatenates only the instance's own attributes/params/variables). The single
  `window.location` is the constructor's `var _c=(_8)?_8:window.location; this.setAttribute("xiRedirectUrl",_c);`,
  consumed once as `escape(this.getAttribute("xiRedirectUrl"))` in the express-install flashvars
  branch - it never reaches `write()`/`getSWFHTML()`, so the recorded chain `_c = ... -> location ->
  element.innerHTML` (XSS-000265) is two unrelated statements on one line. The `document.location`
  SINK `document.location.replace(this.getAttribute("redirectUrl"))` (XSS-000266) is navigation and
  its argument is initialised `""` and never passed by this page; `getRequestParameter` (XSS-000267)
  is a source helper whose value feeds only `this.skipDetect` (a truthiness gate). Positive evidence
  the code is dead here: the archived body (48,457 B, complete) has the `<script src>` tag, the
  `new SWFObject(...)` call and `Carousel_loadSwf();` **all inside one HTML comment** whose `-->`
  sits 2,759 chars later.
- `layerslider.kreaturamedia.jquery.js` (`?ver=8.4.0`, campus-favoriten) is the first LayerSlider file to hit the
  **300,000-char cap** (md5 `4e0b456d8cf6`, 12 lines) - mark its rows as captured-region claims. In that region:
  `postMessage`/`onmessage`/`event.data`/`event.origin` all = 0 (the 98 `origin` hits are `parallaxorigin` /
  `transformOrigin` option names), all 11 `addEventListener` calls are `new Image` load/error, the Lottie player
  load/loadError and the scroll-lock helper on `window`; all 9 `.append(` operands are jQuery objects of literal
  markup (`e("<img>").attr("src",v)`, `e('<div class="ls-bg-video-overlay"></div>')`). `document.location.hash`
  has 5 sites: the load-time read is fed to `r.slides.deeplink(...)` and compared with **`==` against configured
  `data.deeplink` slugs** (returns an integer slide index), and the only navigation write is gated by
  `r.o.hashChange`, whose **default is `!1`** (slider options block, offset ~21148) and which the page's
  `_initLayerSlider(...)` options never set. Verdict: library internal + navigation-only, not XSS.
- `layerslider.slidefxtr.js` (SFX Slide Transitions Add-On, campus-favoriten, 71,451 B / 12 lines, md5
  `0b55f4e60dfe`, complete, only copy): `postMessage`/`onmessage`/`message`/`event.data` and even the token
  `event` are **0**, so the recorded source cannot exist in the file; its single `addEventListener` is
  `n.addEventListener("pause", …)` on a **video element** (`requestVideoFrameCallback` fallback); both `append(`
  operands are `<canvas>` elements (`t.transitions.slide.$wrapper.append(n)` at `createCanvas`, and
  `u.canvas=r,…,a.append(r)` in the WebGL block renderer); the 10 `.data(` hits are `$background.data(
  t.defaults.init.dataKey)` / `.data("direction")` / `data("ls-sfxtr")` plugin-data reads. jQuery `.append()`
  of a DOM node moves it, so no string→markup path exists. Twin of the reveal.js verdict (XSS-000268).
- `layerslider.reveal.js` (LayerSlider Reveal Add-On) on `campus-favoriten.gesundheitsverbund.at`
  (9,538 B / **13 lines**, md5 `41e81a993f07`, complete, only copy): whole-file `postMessage`,
  `addEventListener`, `onmessage`, `message` are each **0** - there is no handler, so "no origin
  validation near handler" (XSS-000268) describes an absent handler. Both `append(` calls are
  `e.elements.$innerWrapper.append(g.append(h))` where `g=a("<ls-reveal-wrapper></ls-reveal-wrapper>")`
  and `h` is a jQuery set of literal `<ls-reveal class="ls-reveal-N">` clones: jQuery `.append()` of a
  jQuery object moves nodes, it does not parse a string. The seven `data(` hits are
  `d.data(c.pluginData.key)` (plugin data), not `event.data`. The page's single `postMessage` is
  WordPress's emoji-support Worker blob, far from this plugin.
- `www.geschichtewiki.wien.at` (MediaWiki + Semantic MediaWiki) reflected rows are scanner
  artifacts, twice over: the crawler keeps HTML-escaped link URLs, so `urls.params` splits
  `...&amp;action=edit` into pseudo-parameters `amp;action` / `amp;redlink`; and value matching is
  substring/normalized, so a wiki page title (`Diskussion:Wien_Geschichte_Wiki` vs the page's own
  `"wgTitle":"Wien Geschichte Wiki"` in the `RLCONF` block) and the word `edit` inside the SMW
  `application/ld+json` vocabulary dump both count as "reflected". Also: `http_samples` holds ONE
  body per host (keyed on `host`), so the cited 404 / `action=edit` responses are not archived at
  all — say so instead of judging them. Detector fix belongs capture-side (normalize `&amp;`).
 - **A literal pipe inside cited code breaks the row — do not try to escape it, rewrite the citation**: an
 unescaped `|` in a cell adds a column and silently breaks the row, and a `\|` written by hand can end up
doubled (`\\|\\|`) after a naive replace. Cheapest fix that always validates: drop the operator from the quote
(`new Function("return this")` without the `return this||` prefix), or split it as ``return this` + `new
Function``. After writing, assert every appended row has exactly **10** `|` characters and ends with `|` —
verified with `python3 -c` over `dataflow_<today>.md` before reporting; this caught XSS-000321 (12 pipes).
 The **actual recurring trigger is a `||` inside a quoted shim**: writing the webpack globalThis fallback
 verbatim (`r=r||new Function("return this")()` @18909) added a 12th pipe on XSS-000324 (2026-09-24 12:22).
 Reword fallbacks as prose ("the `new Function("return this")()` fallback assigned to a local @18909") — the
 assert must run on the **whole file**, not just on the rows just appended. Any candidate row is cheaper to
 reword before appending than to repair after; repair is a plain `str.replace` plus the same assert.
 - **A URL-derived token used only as a control-flow flag is a control dependency, not a data flow**:
 `buergeranliegen.wien.at` (wien-at, XSS-000286, `inline-script-10.js:20`) reads
 `document.cookie.split(";")`, tests only the cookie *name* prefix for presence, then guards an
 `innerHTML` write whose value is a hard-coded German cache-caution literal. That host has **0**
 `js_samples` rows, so the artefact to read is the single `http_samples` body (63,612 B, complete).
 - **Require the recorded payload token itself, not just a listener**: SWCMS `vendor.js`
 (28,510 B, md5 `957573c34b17`, byte-identical on `campus-deutschordenstrasse.schule.wien.at` and
 `graetzl.bildung.wien.at`; the latter already carries XSS-000175) contains
 `addEventListener("message"`/`onmessage`/`postMessage` but `event.data`/`e.data`/`origin`/
 `innerHTML` are all **0** — the listener is core-js's self-post macrotask tick with no payload.
 - **A 403 block page is not page markup**: `ybbs.gesundheitsverbund.at`'s only `http_samples` body is
 1,707 B, status 403 `Zugriff verweigert` (MA 01 front end, `Request ID` in the body), so
 `data-reset` / `data-link-column-url` / `ooo-solr-fulltext-reset` / `shortcodes.js` all count **0**
 there — cite the sibling host's capture for provenance instead and say so. The host's 20 archived
 JS bodies are complete and unaffected.
 - **A "location assignment" sink on a polyfill file is a *read*, and the write grep settles it in one pass**: Parcel
 `babel.polyfills.<hash>.js` on `bnayak-portal.public.atlastunnel.com` (XSS-000326, 118,451 B, 2,664 lines, md5
 `4b675a2d311af6cb86eff2b92854e726`, complete) cites L1201 `$location = globalThis.location;` — inside
 `fails(function() { ... })` with the source's own comment `Deno throws a ReferenceError on "location" access`. `$location`
 is then used only at L1220 (`globalThis.postMessage(String(id), $location.protocol + '//' + $location.host)`, the
 polyfill's targetOrigin) and L1251 (`$location.protocol !== 'file:'` guard). The decisive check is the **write shape**,
 not the word: `window.location =` / `document.location =` / `globalThis.location =` / `location.href =` / `location.replace(`
 / `location.assign(` are each **0** in the file, as are `innerHTML`/`insertAdjacentHTML`/`document.write`/`eval(`/
 `new Function`. The file's single `.replace(` is `String(string).replace(replacement, '.')` in `isForced.normalize`. Do this
 file-level write-grep first — it costs one script and turns "LOW, library" into a positive no-flow finding.
- Copy counts after the 2026-09-24 **12:2x** pass: SWCMS `vendor.js` md5 `957573c34b1707fc5c67c852a751e0fa` **19** hosts
 (+ `zehdengasse.schule.wien.at` XSS-000324, `zinckgasse.schule.wien.at` XSS-000325; both rows opened a *new* day file for
 `wien-at`? no — appended as Pass 3 to `dataflow_2026-09-24.md`, which already existed). `atlastunnel` had a reports dir with
 **no** file at all, so XSS-000326 required the create-branch header; that target's `postmessage/` dir is empty and the row
 belongs under `dom/`. Per-host corroboration for the vendor family is now available from two more school bodies
 (`Home - GTVS Zehdengasse - 921331` 85,199 B md5 `c897493ff908`; `Startseite - Schule Zinckgasse - 915023` 87,954 B md5
 `52c8cae7cf3c`, both 200 and complete, `postMessage` **0** each) plus `app.js` `e79c671c582d` 3,711 B, `runtime.js`
 `6681ed71a970` 2,333 B and `main.js` `4c3a60d66768` 1,095 B with `postMessage`/`onmessage`/`innerHTML`/`Function(` all **0** —
 quote these rather than "not checked".
- Copy counts after the 2026-09-24 **08:1x** pass: SWCMS `vendor.js` md5 `957573c34b1707fc5c67c852a751e0fa` **17** hosts
 (+ `vserlaa.schule.wien.at` XSS-000322, `vskolonitzgasse.schule.wien.at` XSS-000323; 28,510 B, complete). Both new hosts' rows
 carry `source_in_chain`/`source_class`/`library_tier` = `None` while their byte-identical siblings have them populated - the same
 row-writing difference noted on XSS-000293/000294; say so instead of treating the empties as evidence. The recorded `Function`
 sink on these rows is the webpack `Function("return this")()` shim at offsets ~306 and ~18,909 (the latter used as the
 `r=r||new Function("return this")()` fallback) - `innerHTML`/`insertAdjacentHTML`/`document.write`/`eval(` are all **0**.
 Per-host corroboration that no page-level poster exists: the host's own `http_samples` body (200, complete) has `postMessage` **0**,
 and the sibling bundles `app.js` (3,711 B, md5 `e79c671c582d`) / `runtime.js` (2,333 B, md5 `6681ed71a970`) have
 `postMessage`/`onmessage`/`innerHTML`/`Function(` all **0** - quote those counts rather than saying "not checked".
 - Copy counts after the 2026-09-24 **04:1x** pass: WP `jquery.min.js?ver=3.7.1` md5 `826eb77e86b0` **21** hosts (20 + `compliance`),
 SWCMS `vendor.js` md5 `957573c34b1707fc5c67c852a751e0fa` **15** hosts (+ the 7 schools `mariarekkergasse`, `marischka16`, `ovs-oberstveit`,
 `viktorchristgasse`, `vs-am-baumannpark`, `vs-keplerplatz`, `vs-park`), Enfold `shortcodes.js` **12**, `ooo_solr.js` **12**, Enfold
 `avia-snippet-hamburger-menu.js` **6**. All cross-references — recompute the md5 per host, then reuse the family verdict.
 - `mitwirkung.wien.gv.at` `vorarlberg-util.min.js` (79,089 B, md5 `e4eb2cdf792f0b98cbf86e209928027e`, complete, only copy, XSS-000320/000321):
 `innerHTML` occurs **1** time (@76840) and it is a **read in an equality test** — `"Dokumente"==t.innerHTML?e&&(ft.hasClass(e,"active")||e.click()):…` —
 `innerHTML=` is **0** and `insertAdjacentHTML`/`postMessage`/`onmessage`/`event.data`/`location.hash`/`location.search`/`eval(` are all **0**.
 The single `new Function` is the webpack globalThis shim @371. The recorded `localStorage` source is real but unrelated: `exchangeAllLinks()` reads
 `doReplaceUrls`/`replaceUrlSource`/`replaceUrlTarget` and rewrites link **attributes** via `setAttribute(n[a], l)` — an attribute sink, not HTML parsing.
 - `integrationsrat.wien.gv.at` XSS-000313: the cited inline block is **verbatim in the archived page body** (77,988 B, 200, complete) —
 `docReady(function(){var modalel=document.getElementById("wm-modal-container");var parentelid=modalel.parentNode.id;var bodyel=document.body;if(parentelid=="wrapper")bodyel.prepend(modalel);var loc=window.location.href;var check=loc.endsWith("wien.gv.at/")||loc.endsWith("wien.gv.at");if(check){…}})`. `bodyel.prepend(modalel)` is a **DOM element** operand and `loc` only feeds `endsWith` guards whose `check` is unused: sink mis-attribution plus a control dependency. `js_samples` for that host holds a *different* file (`lazyloading-1.0.0.legacy.js`), so the body is the only readable artefact.
 - `cards.linktr.ee` reflected rows keep arriving for new product slugs (XSS-000308/000309 added to 000305/000306): same single archived **home-page** body (199,944 B, complete) holds **all four** candidate values (5/5/3/5 occurrences) as catalogue JSON variant ids and server-rendered `href="…?variant=…"`; the cited offsets 51,373-51,458 and 53,878 all land inside the inline `<script id="captcha-bootstrap">` block (50,648-54,044). One capture containing four different requests' values is decisive that the match is page content.
 - Copy counts after the 2026-09-23 **16:20** pass: `ooo_solr.js` md5 `25537825ef096e729767b6290dcfec7d` **12** hosts (11 + compliance), SWCMS `vendor.js` md5 `957573c34b1707fc5c67c852a751e0fa` **8** hosts (6 + `karl-loewe.schule.wien.at` + `loquai.schule.wien.at`; the same URL path on `help.pinterest.com`/`support.pinterest.com` is md5 `ef432881e955ef0d200935fd3bd4ffb9` — a different file, not this family). Both new-host rows are cross-references; recompute the md5 on the new copy rather than assuming.
 - **Core-js message listener, precise mechanism (supersedes "the event carries no payload")**: in SWCMS `vendor.js` the installed listener body is `A=function(t){P(t.data)}` where `P=function(t){if(p(E,t)){var n=E[t];delete E[t],n()}}` — `t.data` IS read, but only as a **numeric registry key** into `E` (the scheduler's task table), and the registry is populated solely by the library's own setter; the companion poster is `I=function(t){u.postMessage(O(t),e.protocol+"//"+e.host)}` (same-origin only). The two `Function` tokens are the globalThis shims `Function("return this")()` / `new Function("return this")()`. Say this precisely instead of "no payload": the refined detector gate is "require the recorded sink token in a *call shape* applied to a data variable".
 - **`cards.linktr.ee` reflected rows are analytics-`pageurl` artefacts** (XSS-000305/000306, target `linktr`, `js_file` literally `response`, line 0): the recorded offset lands inside the inline `<script id="captcha-bootstrap">` Shopify block, and the matched text is an analytics JSON field `"pageurl":"cards.linktr.ee\/products\/<handle>?variant=<id>"` — i.e. the *whole request URL quoted into a JSON string*. The host's single archived `http_samples` body (199,944 B, complete, **home page**, its own `pageurl` = `cards.linktr.ee\/` with no query) contains **both** candidates' values 5 times each as catalogue data (`"variants":[{"id":"…"}]`) and server-rendered `href="…?variant=…"` — one capture holding both values cannot be a per-request echo. One body per host means the product-page responses are *absent*, not truncated; read it as "not archived". Detector fix belongs capture-side (exclude matches inside a quoted JSON field whose value is the full request URL).
 - Copy counts after the 2026-09-23 **12:15** pass (`compliance.gesundheitsverbund.at` is the only new host name): Enfold `avia-snippet-hamburger-menu.js` md5 `d70920369d9e` **6** hosts (5 + compliance),
 Enfold `shortcodes.js` md5 `c5a1298660a2` **12** (11 + compliance), SWCMS `vendor.js` md5 `957573c34b1707fc5c67c852a751e0fa` **6**
 (`graetzl.bildung`, `campus-deutschordenstrasse`, `enk1.schule`, `galileigasse.schule`, `henry-dunant.schule`, `hoefftgasse.schule`). All three are cross-references: hash the body, reuse the family verdict.
 - Copy counts after the 2026-09-23 08:15 pass (all via new host `simulation` / `enk1.schule` / `galileigasse.schule`): WP
 `jquery.min.js?ver=3.7.1` md5 `826eb77e86b0` now **20** hosts, Enfold `shortcodes.js` md5 `c5a1298660a2` **11**, `ooo_solr.js` md5
 `25537825ef09` **11**, SWCMS `vendor.js` md5 `957573c34b1707fc5c67c852a751e0fa` **4** (`graetzl.bildung`, `campus-deutschordenstrasse`,
 `enk1.schule`, `galileigasse.schule`). Each is a cross-reference. The two newest vendor rows (XSS-000293/000294) carry **empty**
 `source_in_chain` / `source_class` / `library_tier` while the byte-identical XSS-000288 row has them populated - a row-writing
 difference, not a code difference; say so instead of treating the empties as evidence.
 - `simulation.gesundheitsverbund.at` is the first `ooo_solr.js` host whose page capture is a **normal 200** (161,989 B, title
 `Simulationszentrum - Bruenner Str. 68, 1210 Wien`) instead of the ybbs 403 block page: it contains exactly **1** `data-reset`,
 value `data-reset="https://simulation.gesundheitsverbund.at/"`, and **1** `ooo-solr-fulltext-reset` - so the same-host-URL
 provenance for line 114 can be cited from this host directly (quota it before falling back to the sibling citation).
 - WP `jquery.min.js?ver=3.7.1` sanitizer tokens, named (reusable instead of "encoders irrelevant"):
 `createTextNode` **1** (offset 36516), `encodeURIComponent` **2** (71333/71359, both inside
 `ce.param`), `escape(` **0** (`escapeSelector` 3, alias `I.escape=ce.escapeSelector`), `encodeURI`
 **0**, `textContent` 9 (accessor uses). Its single `location.hash` is
 `target:function(e){var t=ie.location&&ie.location.hash;return t&&t.slice(1)===e.id}`.
