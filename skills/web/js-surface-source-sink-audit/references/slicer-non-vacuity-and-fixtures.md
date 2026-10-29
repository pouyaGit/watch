# Slicer non-vacuity: the bugs that zero a pass, and the fixtures that catch them

## Why this file exists

A backward slicer that cannot fire still reports a number. That number looks
like a measurement and is not one, and it is the single most expensive thing
to get wrong in a bulk JS audit — it either hides real flows or invents fake
ones. Two bugs each did exactly that on real runs, and only the fixtures
caught them.

## Bug 1 — the argument extractor amputates the expression

```python
# WRONG
seg = text[pos:pos + limit]
if "=" in seg[:2]:       # sink regex already consumed "= "
    seg = seg[1:]        # so seg starts at the EXPRESSION
seg = seg.strip()        # and this slices off its first character
```

For `X.innerHTML = h`, a sink pattern like `.innerHTML\s*=\s*` consumes the
`= `, so the captured segment already begins at `h`. Slicing `[1:]` turns
`h;` into `;`, the argument no longer resolves to any identifier, and
**every assignment-style flow dies silently**. Only calls (`X.html(v)`) keep
working, which is what makes the output look plausible.

Correct form — strip a leading `=` only when one is genuinely still there:

```python
seg = text[pos:pos + limit]
if seg.lstrip().startswith("="):
    seg = seg.lstrip()[1:]
seg = seg.strip()
if not seg:
    return ""
```

## Bug 2 — the identifier regex demands two characters

```python
# WRONG - {1,40} means "one or more AFTER the first", i.e. minimum length 2
IDENT = re.compile(r"[A-Za-z_$][\w$]{1,40}")

# RIGHT
IDENT = re.compile(r"[A-Za-z_$][\w$]{0,40}")
```

Single-letter variables (`h`, `q`, `x`, `e`) are what ordinary code and every
minified bundle use. With `{1,40}` the extractor returns `[]` for them, so
`innerHTML = h` can never resolve its source. Verify directly:

```python
assert IDENT.findall("h") == ["h"]
```

## The symptom that identifies both

After a pass, look at the candidate distribution:

| healthy | broken |
|---|---|
| a meaningful share of `innerHTML =` and `.html(v)` rows | almost no assignment rows |
| sink mix spread across DOM sinks | dominated by `.append(` / `.html(` call-style sinks |
| candidates traceable to a source variable | candidates mostly framework DOM *building* |

Framework DOM building dominating the list is the tell: `$('<div>' + x + '</div>')`
is a CONSTRUCTOR, and if it has been registered as a SOURCE it manufactures
candidates wherever the built node is later appended. It invented 16 fake
candidates in one 8 KB file. **Never register a construction string as a
source** — it is sink-side.

## The fixture set to keep

Run these through the REAL `analyse()` (import the module, do not re-implement)
and require the expected outcome. Positives prove it can fire; negatives prove
it is not just matching everything.

| fixture | source | expect |
|---|---|---|
| `hash → innerHTML` direct | `var h=location.hash.substring(1); el.innerHTML=h;` | detect (`assigned`) |
| `search → .html()` | `var q=new URLSearchParams(location.search).get('q'); $('#o').html(q);` | detect |
| two hops | `var a=location.hash; var b=a.substring(1); el.innerHTML=b;` | detect (`chained`) |
| `postMessage → innerHTML` | `addEventListener("message",function(e){el.innerHTML=e.data;});` | detect (`direct`) |
| `eval(hash)` | `eval(location.hash.substring(1));` | detect (`direct`) |
| `cookie → document.write` | `document.write(document.cookie);` | detect (`direct`) |
| literal only | `el.innerHTML="<b>hi</b>";` | **silent** |
| tokens, no path | `var u=location.hash; console.log(u); el.innerHTML=stat(); function stat(){return "x";}` | **silent** |

A representative broken run: 2 of the first 4 failed. After the two fixes
above: 8 of 8 pass, and the candidate distribution reshaped completely
(`547 → 179` candidates, `jQuery.append` 507 → `location.assign` 70,
`direct` 220 → 22, `chained` 30 → 77).

## Keep the gate inside the verifier

Re-run the fixtures from the note's verifier, importing the analyzer module.
A slicer that regresses six months later must fail the note's own check rather
than quietly change what the note claims. The verifier exits non-zero on any
failure, and it also asserts the two specific fixes (the one-letter identifier
and the un-amputated argument) so neither can be reintroduced.
