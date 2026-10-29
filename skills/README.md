# Hermes skills — version-controlled copies

These are **copies** of the Hermes agent's local skills (the live set lives at
`~/.hermes/skills/<category>/<name>/SKILL.md`). They are kept here so our skills
are backed up and version-controlled alongside the Watch project.

## Why copies, not symlinks

`~/.hermes/skills` is **actively managed by the Hermes curator** (`.curator_ledger.jsonl`,
`.curator_state`, `_installed-*.json` manifest, bundles). Moving the skill dirs out and
symlinking them back risks breaking skill discovery / curator sync. So this directory is a
**snapshot** for backup + diffing, not the live source. Edit skills live in `~/.hermes/skills`
(so the curator and Hermes see the change), then re-sync here.

Builtin skills (hermes-agent, codebase-inspection, dogfood, blocked-page-recovery) are
excluded — they ship with Hermes core, not ours.

## Re-sync after editing live skills

```bash
/opt/watch/skills/sync-skills.sh
git -C /opt/watch add skills && git -C /opt/watch commit -m "skills: sync from ~/.hermes/skills"
```

## Our own skills (authored for this setup)

- `web/hunt-csp-bypass` — reflected/stored injection vs CSP decision tree + bypass primitives.
- `dell-login-playwright` — Dell.com vault login behind Akamai (CAPTCHA/MFA).
- `recon/watch-hunt` — Watch → verify → report loop (see also /opt/watch/HUNT_GUIDE.md).
- `hermes-recon-*`, `hermes-*` — operational skills for this server's recon pipeline.

The external bug-bounty libraries (murrtada / shuvonsec `hunt-*`, `bb-*`) are mirrored here
too for completeness; their upstream source is `/root/skills-src/`.
