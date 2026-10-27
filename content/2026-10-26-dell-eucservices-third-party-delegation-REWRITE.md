# `eucservices.dell.com` is delegated to a third-party GoDaddy hosting account that Dell does not own, serving a Parallels Plesk panel under a non-Dell certificate

| | |
|---|---|
| **Program** | dell |
| **Scope** | `dell.com` — in scope (`eucservices.dell.com`) |
| **Class** | Loss of namespace control — a `dell.com` name delegated to a third-party-controlled hosting account (DNS misconfiguration / dangling delegation) |
| **Severity** | P4 (see rationale in §5; a P3 case is argued, conditional on the ACME vector) |
| **Authentication** | None required to reach any of the exposed surfaces |
| **Date verified** | 2026-10-26 |
| **CVSS 3.1 (est.)** | 5.4 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |

---

## 1. Summary

`eucservices.dell.com` is a hostname in Dell's namespace, but it does **not** point
at Dell infrastructure. It is a CNAME to `eucservices.net` — a domain that, by every
available registration and DNS signal, is **not owned or operated by Dell**: it is
registered at GoDaddy behind a privacy proxy, runs on GoDaddy nameservers, and is
served from a GoDaddy shared-hosting IP. That account serves a live **Parallels Plesk
Obsidian 18.0.81** control panel under a **GoDaddy shared-hosting wildcard certificate
that does not match the Dell hostname**, and Certificate Transparency shows **no
certificate has ever been issued for `eucservices.dell.com`**.

The core problem is governance, not a single exploit: **Dell has delegated a name in
its own namespace to a hosting account it does not control.** Whoever controls that
account controls what `eucservices.dell.com` serves, and — via the ACME HTTP-01 path
described in §4 — can potentially obtain a publicly-trusted TLS certificate for the
Dell name itself.

This is explicitly **not** reported as a subdomain takeover: the target domain is
registered, paid through 2028, and registrar-locked, so it cannot be claimed by an
external party (see §6).

---

## 2. Evidence — the delegation and the service

### 2.1 The delegation leaves Dell's namespace

```
eucservices.dell.com   CNAME  eucservices.net
eucservices.net        A      107.180.36.179
eucservices.net        NS     ns77.domaincontrol.com, ns78.domaincontrol.com
eucservices.net        SOA    ns77.domaincontrol.com. dns.jomax.net. ...
```

### 2.2 The target is served from GoDaddy shared hosting

```
dig -x 107.180.36.179   ->  179.36.180.107.host.secureserver.net
whois 107.180.36.179    ->  OrgName: GoDaddy.com, LLC  (NetName GO-DADDY-COM-LLC)
```

### 2.3 The certificate served is a GoDaddy wildcard, not Dell's

```
TLS handshake to eucservices.dell.com:8443
  subject  CN = *.shr.prod.iad2.secureserver.net
  issuer   C = US, O = GoDaddy.com, CN = GoDaddy TLS Intermediate CA DV - R1v1
  SAN      DNS:*.shr.prod.iad2.secureserver.net, DNS:shr.prod.iad2.secureserver.net
```

A browser reaching the Dell hostname over HTTPS is shown a certificate for an
unrelated `secureserver.net` name, so the Dell-branded URL raises a TLS warning.

### 2.4 No Dell certificate has ever existed for the hostname

```
crt.sh      q=eucservices.dell.com            -> [] (and intermittently 502; retry)
certspotter domain=eucservices.dell.com       -> []
```

Two independent CT sources agree: the name was never onboarded into any TLS
management, Dell's or otherwise.

### 2.5 The service presented

```
GET https://eucservices.dell.com:8443/login_up.php
-> 200, ~98,700 bytes
   <title>Plesk Obsidian 18.0.81</title>
   Server: Microsoft-IIS/10.0 ; X-Powered-By: ASP.NET

port 80   GET /  -> 200  "Default Parallels Plesk Panel Page"
port 21   banner -> "220 Microsoft FTP Service"
Port state: 80 open, 443 open, 8443 open, 21 open; 22 and 8880 closed.
```

Scope note on how to read the panel: three requests differing only in the `Host`
header (`eucservices.dell.com`, the certificate vendor name, and an invented name)
all return a byte-identical Plesk landing page; `Host: eucservices.net` behaves
differently (`301 -> https://eucservices.net/`). So a vhost exists for the registered
domain `eucservices.net`, and the Dell name falls through to the default landing page.
This report does **not** claim a Dell-configured control surface is exposed — it claims
the Dell name is delegated to third-party infrastructure.

---

## 3. Evidence — `eucservices.net` is not a Dell asset

This is the finding's load-bearing claim, so it is established against Dell's own
known registration pattern rather than asserted. Dell registers its non-`dell.com`
utility domains through its corporate registrar on Dell nameservers; `eucservices.net`
matches the opposite, consumer-GoDaddy pattern on every axis:

| Signal | `eucservices.net` | Dell's real pattern (`dell.com`, `dellscp.com`) |
|---|---|---|
| Registrar | **GoDaddy.com, LLC** | **SafeNames Ltd.** |
| Nameservers | **domaincontrol.com** / `dns.jomax.net` (GoDaddy) | **NS\*.DELL.COM** |
| Registrant | **Domains By Proxy, LLC** (privacy proxy) | real org, no proxy |
| Hosting | GoDaddy shared IP (`host.secureserver.net`) | Dell-operated infrastructure |
| MX / SPF / TXT | **none present** | present (corporate mail + SPF) |
| Created | 2021-02-23, GoDaddy | 2014, SafeNames |
| CT for the dell name | **never issued** | — |

A domain Dell operated would be on SafeNames and `NS*.DELL.COM`, not behind a GoDaddy
privacy proxy with no SPF and no mail. The distinguishing signal is **who controls the
registration and DNS**, not the domain suffix.

**Residual uncertainty, stated honestly:** the privacy proxy hides the legal
registrant, so it cannot be proven at 100% that Dell did not register this domain
through GoDaddy. Every operational signal above argues against it, but a triager with
internal records can confirm ownership definitively — and that confirmation is the
single question this report asks Dell to answer.

---

## 4. Impact

Because `eucservices.net` is controlled by a party other than Dell (§3), and
`eucservices.dell.com` CNAMEs into that party's webroot, the consequences are:

* **Loss of namespace control / trust degradation (established).** A `dell.com` URL
  resolves to a third-party GoDaddy shared-hosting account serving a management panel
  and a stock Plesk page, under a certificate Dell did not issue. Any user following a
  link to this hostname lands on infrastructure Dell does not administer and is shown a
  mismatched certificate on a `dell.com` address.

* **Valid TLS for the Dell name is obtainable by the account holder (conditional,
  not executed).** ACME HTTP-01 validation proves domain control by serving a token at
  `http://<name>/.well-known/acme-challenge/<token>`. Because `eucservices.dell.com`
  resolves (via the CNAME) to the third party's webroot, whoever controls that account
  can satisfy an HTTP-01 challenge for `eucservices.dell.com` and be issued a
  publicly-trusted certificate (e.g. Let's Encrypt) for the **Dell** name. They could
  then serve arbitrary content at `https://eucservices.dell.com/` with a valid padlock
  and no TLS warning — removing the only user-visible deterrent that exists today.
  **This vector was not exercised** (issuing a certificate and serving content would be
  intrusive and is out of scope); it is described as a capability that follows from the
  delegation, for Dell to weigh.

### What is NOT claimed (kept from the verified report, because it bounds severity)

* **This is not a subdomain takeover.** `eucservices.net` is registered, paid until
  2028, and registrar-locked (`clientTransferProhibited`, `clientDeleteProhibited`,
  `clientUpdateProhibited`, `clientRenewProhibited`). It cannot be claimed by an
  external attacker. The attack surface in §4 requires control of the existing account,
  not re-registration.
* **No Dell-configured vhost / control surface is claimed exposed.** The Dell name
  receives the default Plesk landing page; the configured vhost is for `eucservices.net`.
* **No login was attempted, no FTP session opened beyond reading the pre-auth banner,
  and no CVE was exercised** against Plesk Obsidian 18.0.81 (version read from the page).
* **The phishing-via-mismatched-cert angle from an earlier draft is withdrawn** on its
  own: today the TLS warning is a deterrent, not a lever. The ACME vector in §4 is the
  path that would remove that deterrent, and it is stated conditionally.

---

## 5. Severity rationale

**P4, with a conditional P3 argument.** P4 because the established, non-conditional
impact is loss of namespace control plus certificate mismatch on a `dell.com` name —
real, but with no demonstrated attacker-controllable takeover (the domain is locked)
and no reachable Dell data or credential. The case rises toward **P3** if the ACME
HTTP-01 vector in §4 is accepted: a third party being able to mint a valid
publicly-trusted certificate for a `dell.com` hostname and serve content under it is a
meaningful integrity/trust impact. It does **not** reach P2/takeover, because the
underlying domain cannot be claimed by an external party.

---

## 6. Reproduction

```bash
H=eucservices.dell.com

# 1. the delegation leaves Dell's namespace
dig +short $H CNAME                 # -> eucservices.net.
dig +short eucservices.net NS       # -> ns77/ns78.domaincontrol.com (GoDaddy)
dig +short eucservices.net A        # -> 107.180.36.179

# 2. the target is third-party GoDaddy hosting, not Dell
dig -x 107.180.36.179               # -> *.host.secureserver.net
whois eucservices.net | grep -iE 'registrar:|registrant org|name server|creation'
#   Registrar: GoDaddy.com, LLC
#   Registrant Organization: Domains By Proxy, LLC
#   Name Server: NS77/NS78.DOMAINCONTROL.COM
#   Creation Date: 2021-02-23
# contrast with Dell's own pattern:
whois dellscp.com | grep -iE 'registrar:|name server'   # SafeNames Ltd. / NS*.DELL.COM

# 3. no Dell certificate has ever been issued for the hostname
curl -s 'https://crt.sh/json?q=eucservices.dell.com'                                   # -> []
curl -s 'https://api.certspotter.com/v1/issuances?domain=eucservices.dell.com&include_subdomains=false'  # -> []

# 4. the certificate actually served is a GoDaddy wildcard
echo | openssl s_client -connect $H:8443 -servername $H 2>/dev/null \
  | openssl x509 -noout -subject -issuer
#   subject=CN = *.shr.prod.iad2.secureserver.net
#   issuer = GoDaddy TLS Intermediate CA DV - R1v1

# 5. the panel and the stock page
curl -sk https://$H:8443/login_up.php | grep -o 'Plesk Obsidian [0-9.]*'
curl -s  http://$H/ | grep -o 'Default Parallels Plesk Panel Page'
```

---

## 7. Suggested fix

1. **Confirm ownership of `eucservices.net`.** This is the one question only Dell can
   answer and it decides everything below.
2. **If Dell does not own it:** remove the `eucservices.dell.com` CNAME from Dell's DNS
   immediately — a `dell.com` name must not resolve into a hosting account Dell does not
   control.
3. **If Dell does own/use it:** stop serving it from a GoDaddy shared-hosting account,
   bind a Dell-managed certificate for the `dell.com` name, and ensure the panel (8443)
   and FTP (21) are not internet-reachable.
4. **Sweep for the same shape:** any record in the Dell namespace whose CNAME target is
   a registrable domain not controlled by Dell (same registrar/NS/privacy-proxy
   fingerprint as above). This is the generalizable class, not just this one host.
