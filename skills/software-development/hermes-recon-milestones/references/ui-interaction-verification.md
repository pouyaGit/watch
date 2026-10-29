# Verifying a UI milestone when the user says it is broken

Applies when a brief hands you real-device evidence (a screenshot, "tapping it
does nothing", "the fields are stacked wrong") for a surface you previously
certified as passing. The hard part is not fixing the bug; it is that your
earlier PASS is now suspect, and the instinct to defend it is exactly wrong.

## The trust rule

A milestone report that said PASS is a claim, not an inherited fact. When the
same subsystem fails twice, the earlier suite is part of the defect, not a
separate historical footnote. Re-open it and ask: **what was the old assertion
structurally incapable of seeing?**

## Probe by what the user reads, not by what the box encloses

The recurring false PASS comes from measuring a container when the content
inside it was missing. Every one of these passed while the page was visibly
broken:

| Assertion used | Why it cannot fail |
|---|---|
| route returns 200 / `href` present in markup | reachability says nothing about layout or interactivity |
| no horizontal overflow | an element with zero width does not overflow |
| `scrollWidth <= clientWidth` per cell | nothing rendered means nothing clipped |
| `getBoundingClientRect()` has sane values | a covered element still has a correct box |
| cell widths sum to the viewport | a full-width overlay can sit on top of every cell |

The user reads **painted pixels**. A label that was never painted, or a button
that cannot be hit, is invisible to all five assertions above.

## Drive the mechanism; never write the postcondition

The highest-value rule in this file. A test that *sets* the state it then
asserts cannot distinguish working code from broken code.

- Setting `location.hash` and asserting a `:target` panel opened proves you can
  assign a hash. It does not prove the button works. This exact substitution
  survived two consecutive milestones.
- `element.click()` is **not** a real click either — it bypasses hit-testing, so
  it proves a handler exists, not that the control is reachable. Use CDP
  `Input.dispatchMouseEvent` at the element's coordinates, then assert
  `document.elementFromPoint(x, y)` is that element or a descendant. That is the
  only probe separating *painted* from *tappable*, and *visible* from *painted
  over*.
- **Assert the pre-click state.** A suite checking only the postcondition passes
  against a panel that was already open. Closed → click → open.
- **Prove the navigation, not the link.** Dispatch the click and assert
  `location.pathname`. Serving pages over `file://` breaks this: a click on
  `/k` silently lands on `/` and still "passes" a href-only assertion. Serve the
  real router output over a loopback HTTP server and assert the path.

## CSS `attr()` naming a different attribute than the renderer emits

`content:attr(data-l)` against `<td data-label=…>` resolves to the **empty
string** — no error, no console warning, zero-width box. Every field renders
naked and every geometry probe stays clean.

- Match the names with `[\w-]+`, not `\w+`. `\w` stops at the hyphen, so a test
  written as `\w+` matches only `data` and can fail for the wrong reason.
- Assert the *painted* value: compare `getComputedStyle(td,'::before').content`
  against `td.getAttribute('data-label')`. Asserting `"data-label=" in html` is
  inert — the attribute can be present in markup and dead in the cascade.

## Two siblings with identical fixed geometry will collide

A disclosure control added as a *second* fixed bar will share the rect with the
primary bar (`bottom:0;left:0;right:0;z-index:9`) and paint over it. If its only
child is `flex:1`, that child spans the full width and covers every cell beneath.
The cell widths remain correct in the DOM, so width/overflow/route checks all
pass.

Detect it two ways: compare `getBoundingClientRect()` across siblings (identical
rects on fixed elements are a smell), and hit-test **every** cell of the survivor
— `elementFromPoint` at each cell centre is what actually sees the overlay. Then
assert the count (`querySelectorAll(...).length === 1`) so the duplicate cannot
return.

## A visually-hidden element is body text until you hide it

A `<caption>` or heading carrying the field names paints as a detached label
list at mobile widths until display is actually suppressed. Assert rendered
geometry — but assert **painted geometry, never `innerText`**, since a correctly
hidden caption is still in `innerText` and would report a false failure.

## Prove the suite is non-vacuous before you certify it

A responsive suite that cannot fail when the defect is reintroduced certifies a
broken page. Break the interaction in an offline copy and require a failure:

| Injected break | Must fail |
|---|---|
| hide the panel (`display:none`) | "panel becomes visible", link hittability, navigation |
| break the target (`href="#nope"`) | "click sets the fragment" and everything downstream |
| `pointer-events:none` on the panel | hittability, and navigation must not change path |
| overlay the primary controls (the real bug) | "cells not covered" and wrong-path navigation |

Restore from a saved copy and re-verify the restore afterwards. Each mode should
break a **different** edge of the chain; if one mode fails the whole suite, your
assertions are coupled rather than independent.

## A passing focused run does not establish ordering

A new suite can pass repeatedly and still fail inside the runner, where it runs
after other suites. `document.readyState === "complete"` is already true on the
page you are *leaving*, so a navigate-then-poll helper can read the **previous**
page and report a real field as empty. Plant a document-replacement sentinel and
wait until it is gone **and** `location.pathname` matches **and** readyState is
complete. Run any new suite in the real runner before certifying it.

Corollary: a non-zero exit with zero `FAIL` lines means the suite never ran
(port already in use, import error). Print the log tail — `grep FAIL` returning
nothing is not success.

## Retargeting a test is not weakening it

A layout fix invalidates assertions that encoded the **buggy** structure. When
one fails, check whether its literal preserved the defect before "fixing" it;
then replace it with the invariant it was protecting, one-for-one or better, and
disclose the retarget with the count of checks before and after. A retarget that
drops an assertion without a reason is a regression.

## Report a defect you could not reproduce as an open item

When your environment cannot reproduce the user's observation:

- list **which** observations reproduced and which did not, concretely;
- fix and hard-test the defect your tooling demonstrably could not see;
- do **not** claim to have reproduced the symptom you were handed, and do not
  let the prior PASS stand unchallenged because the new state looks fine.

"Fixed a real measured defect" and "reproduced the reported symptom" are
different sentences. A milestone can be PASS with the second one absent only if
the report says so in Limitations.
