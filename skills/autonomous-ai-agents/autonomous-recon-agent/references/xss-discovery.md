# XSS discovery module (static-first, non-exploitative)

Depth notes for the XSS layer described in SKILL.md. Candidate discovery only:
nothing is ever marked confirmed and no payload is ever sent.

## Hard boundary

Forbidden regardless of engagement rules: `<script>`, `alert()`/`prompt()`/
`confirm()`, `javascript:`, event-handler payloads, HTML/SVG injection payloads,
iframes, cookie/session theft, exfiltration, stored-payload submission, reflected
payload injection, crafted `postMessage` payloads, creating accounts to test.
When confirming would require a payload: record, report, require manual
verification, stop.

Allowed: public JavaScript, existing responses, naturally-occurring parameter
values, content hashes, existing page/asset inventory.

## Pipeline

```
http_recon (GET /)  -> extract same-host links (with query params),
                       same-host <script src>, inline <script> blocks, forms
        |                                   |
  urls table (params=<names>)        js_assets table (placeholder rows)
        |                                   |
  reflection_check job               js_recon job (content-hash gated)
   GET the URL exactly as             fetch JS -> hash -> source/sink/flow
   discovered; analyse reflection       analysis -> candidates
   of the values already in it
        \______________  xss_candidates table  ______________/
                        fingerprint dedup, confidence LOW/MEDIUM/HIGH
```

Third-party scripts (a CDN host loaded by an in-scope page) are recorded but
NEVER fetched or analysed — a third-party domain is not in scope because an
in-scope page loads it.

## Sources and sinks

Sources: `location`/`.search`/`.hash`/`.href`/`.pathname`/`.host`/`.origin`,
`document.URL`/`documentURI`/`referrer`, `window.name`, `document.cookie`,
`localStorage`, `sessionStorage`, `URLSearchParams`, `new URL()`, `postMessage
event.data`. Sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`document.write`/`writeln`, `eval`, `new Function`, `setTimeout(string)`,
`setInterval(string)`, `execScript`, location assignment, jQuery
`.html()`/`.append()`/`.prepend()`/`.after()`/`.before()`. Safe text sinks
(`textContent`, `innerText`) are NOT candidates and must produce nothing.

## Data-flow correlation (do not report every source or sink)

1. Strip comments and string literals first, preserving line structure so line
   numbers stay accurate (patterns inside strings are noise).
2. For each sink, take the enclosing statement only (bounded by `;`/braces/newline)
   and look for a source there — an over-wide window produces false "same
   statement" hits from earlier lines.
3. Otherwise walk backwards from the sink through assignments of the variables
   used nearby, at most a handful of hops, collecting a chain like
   `location.search -> URLSearchParams -> userInput -> render() -> element.innerHTML`.
4. Sanitizers anywhere in the chain or in the sink statement
   (`encodeURIComponent`, `escape`, `DOMPurify`, `textContent`, framework
   escaping, custom sanitizers) lower confidence — they do not erase the candidate.

## Confidence model

- HIGH: attacker-controlled source reaches a strong sink, no sanitization in the chain.
- MEDIUM: source and potential sink related, flow incomplete (or origin-checked `postMessage`).
- LOW: sanitizer/encoder in the chain, library-internal flow, or only indirect indicators.

Never emit a confirmed label. Every record carries source, sink, file, line,
data flow, sanitization state, confidence, evidence and
`manual_verification=REQUIRED`.

## Library-bundle guard (signal quality)

Cap at LOW (with a reason) when the file is a vendor/library bundle — filename
hints (`vendor`, `jquery`, `lodash`, `polyfill`, `bootstrap`, `react-dom`, ...)
or content signatures (`jQuery.fn.jquery`, `Sizzle`, `__core-js_shared__`, ...).
Without it, a bundled framework makes every scanned page look vulnerable.

## Reflection analysis (section 49 style)

Analyse only the parameter values already present in a discovered URL. Find the
value in the response, then classify the context: `<script>` block, `<style>`
block, event-handler attribute, URL attribute (`href`/`src`/`action`), other HTML
attribute, or body. If the value is absent but its HTML-escaped form is present,
record LOW with `ENCODED` — never upgrade an encoded reflection. Attribute and
body contexts are MEDIUM; nothing from this path is HIGH without execution
evidence, which requires a payload and is therefore out of scope.

## Other candidate classes

- `postMessage`: find the listener, see whether `event.data` reaches a sink,
  and report whether `event.origin` is validated in the handler (absent
  validation raises confidence; library bundles are capped LOW).
- Stored/UGC surfaces: passively detect form/input fields near comment/profile/
  message/feedback/review content and record a LOW surface-only candidate —
  nothing is submitted and no account is created.
- Template markers in attributes (`{{ }}`, `${ }`, `<% %>`, `#{ }`) → LOW.

## Fingerprint and evidence

Fingerprint = target | host | xss type | source | sink | JS file | normalised URL
(strip query and fragment, digits → N) so line shifts and cache-busting query
strings never duplicate a candidate. Evidence layout:
`targets/<t>/findings/xss/{candidates.jsonl,dom/,reflected/,stored/,postmessage/,reports/}`
with the per-candidate finding file in the matching subdirectory.

## Scheduler integration

Separate small budgets per job type (JS files analysed, URLs reflection-checked,
targets passively swept) and priority order: new JS → changed JS → new endpoint →
new parameter → source/sink analysis → correlation → finding. JS assets are
queued on discovery (placeholder row with an empty hash) and only fetched when
the stored hash differs from the analysed hash. A fetch that fails transiently is
retried next cycle; a permanent failure is marked so the queue cannot loop.

## Deterministic test matrix (no payload required)

`location.search → innerHTML`, `location.hash → innerHTML`,
`postMessage.data → innerHTML` (and the origin-validated variant),
`URLSearchParams → DOM sink`, source → sanitizer → sink (LOW), safe text sink
(no candidate), reflected value in an attribute (MEDIUM), reflected value
HTML-encoded (LOW), duplicate fingerprint stable, changed JS detected, and the
same flow HIGH in application code vs LOW in `vendor.js`. Assert both report
formats (finding text and the alert text) contain the manual-verification and
"exploitation NOT PERFORMED" wording.
