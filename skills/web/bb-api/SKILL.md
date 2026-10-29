---
name: bb-api
description: "bb-api — API & GraphQL Testing Reference. Companion to `bb-ops/playbooks/{graphql,websocket}.yaml` + api-analyzer role. Load in api-analyzer tasks."
---

# bb-api — API & GraphQL Testing Reference

Companion to `bb-ops/playbooks/{graphql,websocket}.yaml` + api-analyzer role.
Load in api-analyzer tasks.

## GraphQL
```
# introspection
{"query":"{ __schema { types { name fields { name } } } }"}
# batched aliases (DoS / abuse)
query { a:user(id:1){email} b:user(id:2){email} ... z:user(id:26){email} }
# nested query depth abuse
{"query":"{ users { posts { comments { replies { ... } } } } }"}
```
- Tools: `graphql-cop -t https://HOST/graphql`, `graphql-map`.
- Authz on fields/mutations: query a `{ user(id: OTHER) }` mutation on another's object.

## WebSocket
- Auth handshake required? Origin validated? Message-level authz (e.g. subscribe to other users' streams by id)?

## Mass assignment
- Send extra fields in JSON bodies: `{"role":"admin"}`, `{"isPaid":true}`, `{"admin":true}`,
  `{"price":0}`, `{"verified":true}` — check if they persist on the created record.

## Prototype pollution
- `{"__proto__":{"isAdmin":true}}`, `{"constructor":{"prototype":{"isAdmin":true}}}`
  in JSON bodies; check reflected behavior.

## Params / transport
- HTTP verb tampering (POST->GET), JSON/XML content-type smuggling, duplicate params
  (first vs last wins), array params `?id=1&id=2`.

## Output
- Evidence: HTTP pair; GraphQL findings include the exact query+variables+response.
- Introspection alone = info unless it leaks sensitive fields. Never self-confirm.
