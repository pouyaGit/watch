# Third-party form toolkits as XSS surfaces

Depth for the case where a landing page ships a vendor form toolkit
(Eloqua, Marketo, Pardot, HubSpot, 6sense) that reads `location.search`
itself and writes it into the DOM. The server-side echo of the same
parameter is usually inert, so a body scanner reports "no reflection" on
a page that is actually exploitable.

The generalizable rules live in SKILL.md. This file is the worked
example, the field-by-field sink map, and the verification recipe.

---

## The chain

```
URL ?param=<payload>
  -> vendor "fill form from query string" script
     copies any parameter into the field of the same name,
     applying its OWN decoder
  -> vendor form script, on window.onload
     writes the field value into innerHTML
```

The server's own echo is irrelevant. It usually appears only in a
tracking pixel, double-percent-encoded, and never reaches a parser.

## Eloqua: the two scripts

### `elqQueryStringToFormField.js`

```js
var field = query[i].split("=");
...
$("input[name='" + field[0] + "'], select[name='" + field[0] + "']")
    .val(decode(field[1]));
```

Three consequences:

1. It matches on the `name` attribute, so ANY query parameter whose name
   matches a form field is copied in. Hidden inputs are reachable.
2. `decode()` is the vendor's own, not `decodeURIComponent`. It tests the
   FIRST hex digit with `parseInt(hex, 16) < 8`, so `%3C` -> `<`,
   `%3E` -> `>`, `%22` -> `"`, `%3D` -> `=`. A vendor decoder is not
   guaranteed to agree with the standard one on every byte.
3. `split("=")` takes `field[1]` only. A raw `=` in the value truncates
   it. A value that needs `=` (any `attr=value` payload) must carry it as
   `%3d` in the URL, which survives the split and is decoded afterwards.

### The form script (`elqForm_*.js`, ~50 KB, several copies)

`displayAllFields()` runs on `window.onload`:

```js
function displayAllFields() {
    if (getParameterByName('resetPage') == 1) {
        clearFieldValues();
        disableFields();
    } else {
        $("[name=emailAddress]").val($("#emailAddressFieldMerge").val());
        if (document.getElementById("field2").value != "") {
            ...
            document.getElementById("info").innerHTML =
                '...Welcome back, <b>' + $("[name=firstName]").val() + '</b>...';
            document.getElementById("welBack").innerHTML =
                document.getElementById("field2").value;
        } else {
            clearFieldValues();
        }
    }
}
```

## The sink map: every innerHTML write, and its source

Enumerate the writes, then classify each SOURCE. This is the analysis,
not a single grep hit.

| Write | Source | Attacker-controlled? |
|---|---|---|
| `info.innerHTML = '...<b>' + $("[name=firstName]").val() + '</b>...'` | form field | YES |
| `welBack.innerHTML = document.getElementById("field2").value` | form field | YES |
| `info.innerHTML = '...<b>' + fName + '</b>...'` (4 copies) | `GetElqContentPersonalizationValue('C_FirstName')` | NO - the function is not defined on the page, so `fName` is always `""`. Check `typeof window.GetElqContentPersonalizationValue` before believing it |
| `welBack.innerHTML = vistr_Email_Add` (4 copies) | server-side variable | NO |
| `stateProvLabel.innerHTML = TXTProvince` | script constant | NO |
| `<option>.innerHTML = arrayText[j]` | the option label list | NO |
| `zipPostalLabel.innerHTML` / `stateProvLabel.innerHTML` | constants | NO |

## The gate parameter is a sink too

The second write is the one that matters most:

```js
document.getElementById("welBack").innerHTML = document.getElementById("field2").value;
```

`field2` is the visible e-mail input, and its value comes from the HIDDEN
merge input `#emailAddressFieldMerge`, which the fill script populates
from the query string. So:

- `?emailAddressFieldMerge=<payload>` alone executes. No other parameter
  is needed. It is the shortest vector.
- `?firstName=<payload>` alone does NOT execute - it needs the merge field
  non-empty to survive `clearFieldValues()`.
- `?emailAddress=<payload>` does NOT execute. The visible field is cleared
  by `clearFieldValues()` before the merge field is copied into it. Only
  the merge field survives the reset.

**Generalize:** the field that gates a branch usually flows into an
element too. Test the gate parameter on its own.

## Field-by-field sink sweep

One payload per field, each field alone, no other parameter. This is what
tells you which parameter to report and which are non-sinks.

| Field | Fires? | Why |
|---|---|---|
| `emailAddressFieldMerge` | YES | copied into `field2`, written to `welBack.innerHTML` |
| `firstName` | only with the gate | needs `field2` non-empty to reach `info.innerHTML` |
| `emailAddress` | no | cleared by `clearFieldValues()` |
| `industryFieldMerge`, `productOfInterestFieldMerge`, `numOfServersFieldMerge`, `timeFrameToBuyFieldMerge`, `quoteFieldMerge`, `jobFunctionFieldMerge`, `jobLevelFieldMerge`, `resWebSecFieldMerge`, `webSecPlannedFieldMerge`, `companySizeFieldMerge`, `countryFieldMerge`, `stateFieldMerge` | no | value stays in a hidden input, or is copied into a `<select>`, which cannot execute script |
| `lastName`, `company`, `phone` | no | visible text inputs, never read into an HTML context |

**An HTML5 `type="email"` input does not block the payload.** Constraint
validation runs on form SUBMISSION, not on a programmatic `.val()` write.
The value reaches the sink unvalidated.

## Conditionally revealed fields

The form disables most fields until a country is chosen, and a hidden
`countryFieldMerge` does NOT reach the visible `<select>`: the value stays
in the hidden input, the select stays empty, and the branch never opens.

Setting the select through the UI and dispatching `change` DOES open it,
and the effect is measurable:

| | before | after |
|---|---|---|
| province row | `display: none` | visible |
| disabled `<select>` | 6 | 0 |
| disabled visible `<input>` | 6 (`firstName`, `lastName`, `company`, `city`, `address1`, `zipPostal`) | 0 |

**This opens no new sink.** The newly enabled inputs are plain text fields
that nothing reads into an HTML context. Report the effect AND the absence
of a new sink - "activating it enables the other fields but does not open
a new sink" is a bounded, useful claim.

## Character reach

Measure it, do not assume it. Send each dangerous character separately and
read the resulting `innerHTML`.

| Char | Reaches `innerHTML`? |
|---|---|
| `<` `>` `"` `'` `=` `/` space `:` `#` backtick `$` `{` | yes, raw |
| `&` | entity-encoded to `&amp;` - the only filtered one |
| newline | stripped |
| tab | kept |
| NUL | stripped |

## Which payload shapes actually fire

Inserted via `innerHTML`:

- `<img src=//no.such.host.invalid/x onerror=...>` FIRES. `src=""`
  resolves to the page URL, which loads fine, so `onerror` never runs -
  use a non-resolving host.
- Separate attributes with a SPACE. Using `/` as the separator yields
  `src=""` plus a separate `onerror` attribute: the handler is present
  but inert.
- `<details open ontoggle=...>` FIRES
- `<video src=x onerror=...>` FIRES
- `<audio src=x onerror=...>` FIRES
- `<marquee onstart=...>` FIRES
- `<svg onload=...>` does NOT fire - SVG inserted through the HTML parser
  does not take the SVG load path in Chromium
- `<script>` never executes (HTML spec)

## Proving execution without a network beacon

An `http://` beacon fired from an `https://` page is blocked as mixed
content, so a negative beacon result proves nothing. Prefer in-page
markers read back from the same session:

```js
document.title='XSSPROOF';document.body.setAttribute('data-xss','fired')
```

For same-origin read access, which is the strongest proof of privilege:

```js
fetch('/some-page').then(r=>r.text()).then(t=>document.title='LEN'+t.length)
```

## Proving `alert()` itself fires, not just "some JS ran"

A `document.title` marker proves code executed, but a reviewer asking "does
the alert actually pop up?" needs the alert call itself observed. Wrap
`alert` at document start and collect its arguments:

```js
window.__xssHits = [];
window.alert = function(v){ window.__xssHits.push(String(v)); return true; };
```

Then run three cases in the same session and compare the collected array:

| case | expected `__xssHits` |
|---|---|
| control, no payload | `[]` |
| payload calling `alert(origin)` | `['https://the.victim.origin']` |
| payload calling `alert('PWNED_BY_PAYLOAD')` | `['PWNED_BY_PAYLOAD']` |

The third case is what makes it conclusive: it shows the arguments came
from the payload, not from the page's own code. The origin case then
proves the alert fires in the VICTIM's origin, which is the impact claim.

**A payload that reaches the DOM but does not fire is still a finding**,
but the report must distinguish the two states. A payload whose attribute
separator is `/` yields `src=""` plus a separate `onerror` attribute: the
element and the handler are created, and the handler never runs. Say
"reaches the DOM, does not fire" for that shape and reserve "executes" for
the shapes you proved with the hook.

## Verification recipe

1. Fetch the page, list its `<input>` and `<select>` elements, and note
   every `name` that looks like a merge field (`*FieldMerge`).
2. Enumerate every `innerHTML` write in the vendor form script and classify
   each source. Fetch the script from ITS OWN host - it is served from a
   CDN, not the page's host.
3. Sweep: one payload per field, each alone, in a real browser. Record
   which fire.
4. Prove with a control (benign value, no payload) and an attack in the
   same session, then confirm the handler executed by reading an in-page
   marker back.
5. For the report, give the field/sink table, the sweep result, the
   character-reach table, and the blast radius over the sibling landing
   pages.

## Tooling pitfalls that cost turns here

- **`urllib.parse.urlencode` double-encodes an already-encoded payload.**
  `%3C` becomes `%253C` and the payload never decodes. Build the query by
  hand when the value is pre-encoded.
- **Never `%`-format a string containing a percent-encoded payload.**
  `"...%3C..." % v` raises `ValueError: unsupported format character`.
  Use concatenation or `.format()` / f-strings.
- **A function-local `import urllib.request` shadows the `urllib` name
  inside that function**, so a later `urllib.parse.unquote` raises
  `UnboundLocalError: cannot access local variable 'urllib'`. Import
  submodules at module level.
- **`pkill -f <pattern>` matches the shell running the pkill** when the
  pattern appears in the command line, so it kills its own shell (exit
  143 / SIGTERM). Use a marker that does not appear in the kill command,
  or kill by PID.
- **A scan whose filter excluded every candidate prints "0 hits"**, which
  reads as a clean result. Print the candidate count next to the hit
  count, and treat a 0-candidate run as broken rather than clean.
