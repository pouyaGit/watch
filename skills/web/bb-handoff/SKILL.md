---
name: bb-handoff
description: "bb-handoff — Manual-Test Task Crafting. Companion to the handoff agent. These are the rules for writing tasks the human will actually execute."
---

# bb-handoff — Manual-Test Task Crafting

Companion to the handoff agent. These are the rules for writing tasks the human will
actually execute.

## Good task
```
TASK: Confirm stored XSS renders on console.verda.com SSH keys page
WHY:  finding f_014 (candidate, confidence 0.7) — headless agent can place the payload
      but cannot verify browser execution
DO:   1) log in at https://console.verda.com (acct1 creds in target.md)
      2) open Settings -> SSH Keys (or /ssh-keys)
      3) the key named <img src=x onerror=alert(document.domain)> should pop an alert
REPLY: DONE: alert fired with console.verda.com  |  FAIL: no alert / page blocked
EVIDENCE: screenshot of the alert; or console output
```

## When NOT to make a manual task
- Evidence can be fully gathered non-intrusively → verifier confirms directly.
- The check is out-of-scope → don't ask.
- The human already validated it in a prior session → reuse the confirmation.

## Anti-patterns
- Vague steps ("check if XSS works"). → Name the exact page, element, payload, expected result.
- Asking the human to do something the agent can do (e.g. "run curl"). → Only browser/
  intrusive/2nd-account steps reach the human.
- Over-long tasks. → Break into ≤5 steps.

## Answer handling
- Accept: `DONE` + the specific evidence requested.
- Reject: unverifiable claims, screenshots of non-conclusive states → ask once, then refute.
