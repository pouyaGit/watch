# Open-redirect confirmation — redirect param set to `https://google.com`

- Generated: 2026-10-26 16:33:07 +0330
- Candidates tested: **2861** endpoints (from redirect-params-4platforms-20261026.md)
- Method: original archived URL re-requested with every redirect-style parameter rewritten to `https://google.com`, one GET, no follow, 15s timeout, then compared against the untouched baseline response
- Exact-host match on `Location` (a `*.google.com` subdomain does not count — only `google.com` itself)

## Result: 0 confirmed open redirect(s)

**No endpoint redirected to the supplied canary host.** Every candidate either ignored the parameter, validated and refused the value, or did not redirect at all. Nothing here is reportable as an open redirect yet.

### Breakdown

-   687  unreachable (dead host / TLS / refused)
-   442  no redirect with either value
-   473  redirects, unchanged by our value
-   960  blocked at the edge (403/404/406/429 — WAF or bot filter, not a verdict on the param)
-   257  param consumed, value refused (4xx)
-    16  param consumed, IdP error page
-    26  other / inconclusive

Note: 960 endpoints answered with the same 4xx to both the untouched URL and the canary URL (mostly 403/406/429 from an edge WAF or bot filter, 404 for dead paths). Those were **not** validated as safe — they are blocked from this IP without a browser session, and are simply untested.

## Where the parameter is consumed but the value was refused (257)

These endpoints read the redirect parameter and rejected our external host with a 4xx. That is the correct behaviour and also the exact place a `redirect_uri` whitelist bypass (subdomain, `@`, backslash, `%2f%2f`, path traversal, open redirect on an allowed host) would be attempted — one program at a time, inside its scope.

### bugcrowd / Okta — 82
program: https://bugcrowd.com/okta

https://acadian-asset.oktapreview.com/oauth2/v1/authorize?client_id=0oan8jccytVdz9rE30h7&redirect_uri=https%3A%2F%2Fpmtools.integration.acadian.am%2Foauth2%2Fidpresponse&response_type=code&scope=openid&state=clnxtcDDRi%2FrrflOGgKvPNYUV%2F2YekdOiN2DFnBGWz%2BIIxCyvTd1MX0xNy5E0eP4MfyEuyXHKsKy97aHVyz5GlQJATOuzTZ2J8n14%2FKgRt8AcZatFcuo7Gg0nbz1HDHuGnzwg6P6Pddpu5ifJ7k924pbLhsZ03Kq%2BFIb3mdJFsc9rehoY1Z2IBw02NqcPR9NCKUoVqk%3D
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://1password3.oktapreview.com/oauth2/v1/authorize?client_id=0oai0ljq6k67BzMWL1d7&redirect_uri=https%3A%2F%2Fns-manager.play.agilebits.net%2Foauth2%2Fcallback&response_type=code&scope=openid+email+profile+groups&state=JFspBje_1YlJGy0B09W809o0JYlnZQmxy8Ec_umBhsc%3A%2F&approval_prompt=force
  baseline: 302 -> ns-manager.play.agilebits.net
  canary  : 400 -> (none)
https://8451.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2F8451-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=PCmUg9qCawG-Cff_3vBih0_yC8pijmIt&nonce=mwtgrZmMJzURY4oplpKuNTR2yB-_Vuzi&code_challenge=1a1R8R9iGzMqjFYdLG3RJ1XJbEj-b3hQWWNUlmsUWB0&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://advantagesolutions.oktapreview.com/oauth2/v1/authorize?client_id=0oa1tfo8nym18or1L0h8&nonce=638635329984283352.NTM4NTEwNzAtOTc5MS00YTcxLWJlZDQtMDg5ODA0Y2EwNjg1ZTc4NTQ1ZjYtN2VhOC00MDg4LWE5NTMtMDRkNmYxNGQyNDhk&redirect_uri=https%3A%2F%2Fqa-retail-im.advantagesolutions.net%2Fauthorization-code%2Fcallback&response_mode=form_post&response_type=id_token+token&scope=openid+profile+offline_access&state=OpenIdConnect.AuthenticationProperties%3DewgxlNCPSENUsJryQrVWFiE8FJb0Iama3EoW_UzAYY6d8upm9XGpPU505gJ6F8JAHAKcuo7i2vwS87TJryuOhzwQrOcMxWUqnVyBxdFKMBbKZ916wQw64hyy5icdJL19-qGwAGUn3BNHTlzowL1zjJfj2exCUWZszR-g5pF3B35qofTNa4t4_AAPN6hbmFNJYOPtI3TH5wlyaVo6ldhNDc6Fz1dlhxbQ1JB_OXstGwIkNqJofTiz6F7s7CsABIN_Ae_v4CzzU2qQCnRIGmq2uv3e7FoGwxj9J2Pb7Ftbovk&x-client-SKU=ID_NET451&x-client-ver=5.2.1.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://afge.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa1x766ayeAgCahA0h8&redirect_uri=https%3A%2F%2Ftest-nvacfeed.afge.org%2Fauthorization-code%2Fcallback&response_type=code&scope=openid%20profile%20email%20NVACFeedback&code_challenge=HCMNaeIOxGSaOHHTzGOhlBtq_kGsHaBkGR9GNDTEigU&code_challenge_method=S256&response_mode=form_post&nonce=638751906885883450.ZmUxNmUzNmYtZDUwZS00ZDJlLTljMzEtMWExNmYwNTQ3MDhiZWRkN2U0NTMtOWY4Yy00MzZkLWJkM2QtYzE2ZmRiMzk0NmRi&state=CfDJ8GMnov8voZhNn1z_4ixbhCk4Gs3LmKgzNnsCeVLkRrwey_Xs1X3pZ-o6A_KNNMg3xg6T7XkiI-d8-ZzHLJwNnVhZD-ZQwawJ4bbJ-HN35dP77Gkd76eKM__DbCfeWT8F4ecgGKNRKnJGraPrFNd2xA-6fnWkxD-cQpUL09e_rfnmIWmnWU5arzqgPmDWpIDM4W9COULihu9dx4pYD_Ecbszk2_t8qghazBH2HdHBFz5CNz32fojWjue1it0j_Q4vUvZeAABcq5BOsewVn4OgdHparc1YptQv9kZRwctBrMPEtRor3wJwgsXamdyxqsGOtAyMLOJkX8kiwOGUnz2Urnj0IZbnnTX9Os38CC9sE1minO5sQuxIyxbIzWQkUIMbA038fVSbCZv45X-oq09IiBis8GTwysW1kgFbRKhO_A65&x-client-SKU=ID_NET8_0&x-client-ver=7.1.2.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://aon-ext.oktapreview.com/oauth2/ausftf21ftCAwtRRJ1d7/v1/authorize?state=asdfsfdsfsdjldfjgdfj&scope=openid+profile+email&client_id=0oafte8rnsLi26PlA1d7&redirect_uri=https%3A%2F%2Fstaging-acrash.aon.co.uk%2FCheckLogon.asp&response_type=code
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://assurant.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa1nq4p2vzy5gzH00h8&redirect_uri=https://uat-wh.canada.dls-test.com/oidc/callback&response_type=code&scope=openid%20profile%20email%20AD.groups&state=GYo58Z
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://atge.oktapreview.com/oauth2/default/v1/authorize?client_id=0oawoveisrkxaCchF0h7&redirect_uri=https%3A%2F%2Fpsc.qa2.chamberlain.edu%2Fauthorization-code%2Fcallback&response_type=code&scope=openid%20profile%20email&state=OpenIdConnect.AuthenticationProperties%3DaBxpwb9fiFALqjM1lIUOxHmBrLBI32D28S4zpLgLkWWyaErX1a4QaDZKj_WhSI_Q7fUmazabNyJhp5jxD5w78vQBSTfLlBNSrf2q2PplZsuxnd-dBYkaai3TY0HNnW-KEWZKWv5gczmqXM7HaaXsVw_VT_587z3wb2WYs13mzuxFCOLh3pmkHhsLKPhIfVccOtYQzi35Zpb8kifujRYEVg&response_mode=form_post&nonce=637858778631211554.MjA4OGI3NzItMGU1My00NzhiLWE4Y2MtODgwZDk1YzFlNWU4MGFmOGVkOWUtMDJiYy00ZTMyLTljOTYtNzU1NjBhOGMzOWRm&x-client-SKU=ID_NET451&x-client-ver=5.3.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://asa-dev.oktapreview.com/oauth2/v1/authorize?client_id=0oa1yqg3xnbrkqRZS0h8&redirect_uri=https%3A%2F%2Finfra.dev-test.sudo.wtf%2Fp%2Flogin%2Foidc_callback&response_type=code&scope=openid+email+profile&state=eyJuZXh0IjoiLyIsInNlc3Npb25faWQiOiIzNTk5Y2NmNy0yZTI3LTQ3M2QtODdlNi0zOGVjNTQ2YmU1ZTkiLCJvcmdfbmFtZSI6ImxlZ2FjeSJ9
  baseline: 302 -> asa-dev.oktapreview.com
  canary  : 400 -> (none)
https://aptive.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa8w1s4soV0Elsnb1d7&redirect_uri=https%3A%2F%2Fbytebase.ops.aptivetech.com%2Foauth2%2Fidpresponse&response_type=code&scope=openid&state=0HlaCxTXYTadqpzimc%2FEKgCj0m3fm7vpjw0IrRmFNANXM9xf9tuClcUDeOYEz7V1FenO7yRqBO%2BYj7G%2Fo0%2BsYeiJCz7tG2kjVpw%2FZ2Cg5jb6fGkhTzMCO3usP1YY64BZg4B6IsqF8W4RXUfk%2BIk8Ud4EQe1z%2FxWPXx67JwITXu37MrGTnHU1yhMAYy7wN3aWX%2FrwBqdw8VZEv2Zylb%2F9Ps6eTtz%2BDDZQ2JSS8uVV2XxWzM6jMepL
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://bugcrowd-pam-2766.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2Fbugcrowd-pam-2766-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=J6s1oWn0F9LPCNCl1DFadyEqNaudfrjA&nonce=0nyBTCunqUlB6gvkcz_g3qyn5jWfJ3S8&code_challenge=tEB3VOus5jaxvTyyBB4OadEvk858mePlie2m-qTZvIU&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://canva.oktapreview.com/oauth2/v1/authorize?client_id=0oazgs8q5okbQvO4D0h7&redirect_uri=https%3A%2F%2Fcanva-internal-preview.cloudflareaccess.com%2Fcdn-cgi%2Faccess%2Fcallback&response_type=code&scope=openid+groups+profile+email&state=0d16a1ef1000a634443d4b156375955482ed6aea5fd9c4ada376cebd868418bc.JTdCJTIyaWF0JTIyJTNBMTcyNjAxMDY0MSUyQyUyMmF1dGhEb21haW4lMjIlM0ElMjJjYW52YS1pbnRlcm5hbC1wcmV2aWV3LmNsb3VkZmxhcmVhY2Nlc3MuY29tJTIyJTJDJTIyaG9zdG5hbWUlMjIlM0ElMjJoaWdod2F5LmNhbnZhLWludGVybmFsLXByZXZpZXcuY29tJTIyJTJDJTIycmVkaXJlY3RVUkwlMjIlM0ElMjIlMkYlMjIlMkMlMjJhdWQlMjIlM0ElMjI4NGI5Nzk5Y2MzMWVhOGE4ZWU5YWJhMDJhNjA4ZmQ1NGI1Zjk2Zjg4NmM4YWQzNzBkZDk0Y2I4NjYzZmIzOTY1JTIyJTJDJTIyaXNTYW1lU2l0ZU5vbmVDb21wYXRpYmxlJTIyJTNBdHJ1ZSUyQyUyMmlzSURQVGVzdCUyMiUzQWZhbHNlJTJDJTIyaXNSZWZyZXNoJTIyJTNBZmFsc2UlMkMlMjJub25jZSUyMiUzQSUyMm5FaXdlWVM1NDFwZ3pIMlJzJTIyJTJDJTIyaWRwSWQlMjIlM0ElMjJhNWRjMTM1My1kNWFmLTRjNjctYjgyNi1iOGY3MmY4NjIzMmUlMjIlMkMlMjJzZXJ2aWNlX3Rva2VuX2lkJTIyJTNBJTIyJTIyJTJDJTIyc2VydmljZV90b2tlbl9zdGF0dXMlMjIlM0FmYWxzZSUyQyUyMmF1dGhfc3RhdHVzJTIyJTNBJTIyTk9ORSUyMiUyQyUyMmlzX3dhcnAlMjIlM0FmYWxzZSUyQyUyMmlzX2dhdGV3YXklMjIlM0FmYWxzZSUyQyUyMm10bHNfYXV0aCUyMiUzQSU3QiUyMmNlcnRfaXNzdWVyX3NraSUyMiUzQSUyMiUyMiUyQyUyMmNlcnRfcHJlc2VudGVkJTIyJTNBZmFsc2UlMkMlMjJjZXJ0X3NlcmlhbCUyMiUzQSUyMiUyMiUyQyUyMmNlcnRfaXNzdWVyX2RuJTIyJTNBJTIyJTIyJTJDJTIyYXV0aF9zdGF0dXMlMjIlM0ElMjJOT05FJTIyJTdEJTJDJTIyYXBwU2Vzc2lvbkhhc2glMjIlM0ElMjJlNTA4Mjc3NDFjMDZiNGM0NTE5ZWQyZmVhZDBhYjg4MzA1ZDU3ZjYzZWMxZTA0YmVjMzgwYjA1MTJmMmI5YzI0JTIyJTdE
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://cfahome.oktapreview.com/oauth2/ausc6e4sj2fnPnQ670h7/v1/authorize?state=140077b4f3c645cbad4dd22b5f4c4c90%3A%3A%2F&client_id=0oarvesnt9HOhmsGq0h7&redirect_uri=https%3A%2F%2Fss.grc.cfadevelop.com%2Foidc%2Fcallback&scope=openid+profile&response_type=code&nonce=596b0d23abfa4677891c6654e952a387
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://cfahome.oktapreview.com/oauth2/auscjsakz3PaAP82K0h7/v1/authorize?client_id=0oaz79jmw91oqcGZK0h7&nonce=638628699538253193.YzZmNzUxNWItMDAzOS00ZjFkLTkxNGYtZTVjMmFlNGUzY2MzYTUyMjQ2YTktZTQxYS00MDJjLWFiZjUtZWY1ZmU5NTM4ZTVm&redirect_uri=https%3A%2F%2Ftest.portal.cfahome.com%2Fauthorization-code%2Fcallback&response_mode=form_post&response_type=code&scope=openid+profile+episerver%3Aread&state=CfDJ8J-SbHTs1khHgF4gk-iNxy3ZIn-6vVVeplH8tTtsXABmlaOgMOadGQ5tDNJAgwU14lfANiQWG_LCYh4QTs1oTJnHj4EAA243n2nAndUIpUPkgxHmb9noI-McAfoyoQv3Lfiesvry1j18owG8eMChJWltZGtZlcHeJzRD-tEjYsZmFIach6u7GE1o1j5txS7drRWGDbr1kGo0vNLGTM10ctlkiRK1SerUt6b4ANZUn5-QCyNKz7tM84-DYIBL-JmzjkD6QQVFMnUiZutasom6orob1flihKXCNSSZ_Zk0SKI3n6EUTVhxdZmMdCBUJnoPJFnzBjOcGSKie9TLJ0HNJjM&x-client-SKU=ID_NET6_0&x-client-ver=6.33.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://condenast-hub.oktapreview.com/oauth2/aus10s2nzylxugjkK0h8/v1/authorize?client_id=0oa105v6230WfLda50h8&nonce=_a49foXF5lLgP6XFA1q827xc1CLui25YLdOOHDsCqKo&redirect_uri=https%3A%2F%2Fcnaffiliate-staging.condenast.co.uk%3A443%2F_codexch&response_type=code&scope=openid+profile+email+offline_access&state=0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://condenast-hub.oktapreview.com/oauth2/v1/authorize?scope=openid+email&code_challenge=K5VnBzzyRh53ygq_Hv5SBvOIIv7bhoydnqR4e_XuL30&code_challenge_method=S256&state=DuDF4lKxu7gNRqs_lmKudhB8tkU4ppCDy7Pr7-eVzIo&client_id=0oa21il6lyfwmQWAE0h8&response_type=code&redirect_uri=https%3A%2F%2Fstg-techradar.conde.digital%2Foauth2%2Fidpresponse
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://corpengdatabricks.oktapreview.com/oauth2/default/v1/authorize?redirect_uri=http%3A%2F%2Fpasswordrecovery.dev.corpengdatabricks.com%2Fcallback&scope=openid&state=kQH2BDUrSjnEIqJWIAzeYmM0v5TQqA4eihObaVIGOJ1_2XqhiDqGLBYjxT-aJb6O7Afreb3Gk9rxkSNkMi7QqQ&code_challenge=3XviHt8e-rcTBSWjGvHPa_toC-Y-BhAtkUY5IBPuKXQ&code_challenge_method=S256&response_type=code&client_id=0oa1tpndi3b8yaU4V0h8
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://collegeboard-oie.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2Fcollegeboard-oie-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=gQz5qaH_kFSICdiF-fXSzFswq693NHU-&nonce=iEi-Xsng7miU5btfX2Kgb73y8-CtSD5k&code_challenge=LHGUnmwaDt8077BAsN1qtfuUZl_QQSgC2HmBoSiNc3U&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://das.oktapreview.com/oauth2/v1/authorize?client_id=0oalvnnqre8BXfEfd0h7&redirect_uri=https%3A%2F%2Fregister-stg.omnicomgroup.com%2Fauth%2Fokta%2Fcallback&response_type=code&scope=openid+profile+email&state=778bae5fb9a28a4ba4a089ba48fca8e39143f9e77f9a8014
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://covetrus.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2Fcovetrus-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=TxVQ2-GpPlD5pNPLyD_Ex59Letfq2Zd0&nonce=uP_F5ei-shmfwJYe23aQXstG9WzvY_qe&code_challenge=IVbH9ZLA3YdhpfVpBdUOtaQ7Vt5_3drRyKaOh-V3UTc&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://cwbfg.oktapreview.com/oauth2/aus27cgkd1lSHvZBg0h8/v1/authorize?nonce=638675783106458047.N2E3NGU5NTYtNWNlMC00NjEzLWE4ZDItYTEyNGZkZDA3Y2E0ZDdjODcwZTUtOGVjZS00MGIzLWI4ZDItZWEwMzNiYzQxZDkz&client_id=0oa27cg6rr1wpL75i0h8&response_type=code&x-client-ver=7.1.2.0&scope=openid+profile+email&state=CfDJ8CnKr60fNaJEgPMGL6SQxAEZe-0cREikurugQzY7GuVqji3wu_5PPj7Pq7VLlW3whP7qd-9qZthUbetA25PJmMPtTBBJXCtBSaaEu6T6iAUz0VBY_wkM9hdPVOIGG0pamMAQ6_bSVnaO2EWj1n16-R9R3ceNZch12DfQtQ8_Pzxh1G4nvX03zxceH4Btot5MK0vw6Y7C5LKcQ2eTD5y-aBvwIgMypIo4Cv70nCZ1dPmIxUO_KAHpFQwVQHbrE9fz2PnhbSN7sp3o0MeVXq5GchGKiJArFBjaIQfxyNwpaijItBY9B4OMctFfcqNcOND2uAbgIqHSi7YFoiZVvp4cmk2ALw8qfMOYoZI&redirect_uri=https%3A%2F%2Fcwb-test-admin.taina.tech%2Fsignin-oidc&code_challenge_method=S256&x-client-SKU=ID_NET8_0&response_mode=form_post&code_challenge=g1abVaKhOyjfnuac_106S1WsbnzmHInKd-Z9ELYbjqY
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://demo-incode.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2Fdemo-incode-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=Pw15Q9VgAweIc71CsNXtx2PSQUFOe5ly&nonce=6EFVwiJ5vTUJx1DMEiAlcO0RHyEF8AqM&code_challenge=VhkMzSTAqBmpXf41BqmbZfspAKj_GeDKA2osCN3HzKo&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://demo-nvi-lab-wic-preview.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2Fdemo-nvi-lab-wic-preview-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=yHX0u4mbED_6Vu6AabWkDvN03f1MKGf9&nonce=gBkXzKsFvxAY-z2CW-SXo6IkeMM1pdRa&code_challenge=zeakNdlPn9a0Oiv_K8HaIe2Esy_Ir9Z9-i6arojqwIk&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://dev-1234.oktapreview.com/login/login.htm?fromURI=%2Fprivacy
  baseline: 200 -> (none)
  canary  : 429 -> (none)
https://dev-179482.oktapreview.com/oauth2/ausbhdf5qd99WQtws0h7/v1/authorize?client_id=0oabh87bqgR5SeK5Y0h7&redirect_uri=https://portal.csxsystems.com/authorization-code/callback&response_type=code&scope=profile%20email%20openid&state=d4RKiN
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://dev-745903.oktapreview.com/oauth2/aus1flfrimksCr9n40h8/v1/authorize?client_id=0oa1bwm2rrkQKjrp50h8&nonce=hWS8TNbPJmp4Ax0hdKa6QbopeHUpofgd&redirect_uri=https%3A%2F%2Flogin.prg.iain.cl%2Foauth2%2Fokta%2Fauthorization-code-callback&response_type=code&scope=openid+email+profile+groups&state=7728ba08-d835-4584-bc4e-cf97e7d73ee1
  baseline: 302 -> dev-745903.oktapreview.com
  canary  : 400 -> (none)
https://devaicpa.oktapreview.com/oauth2/default/v1/authorize?state=Qphozt68CktHJmpDWQDOgugrO%2B5S0ho%2F7QMV2h6prWZVgjmUzMIRy5qUdqfaav2khvpBz7Akxl6VnZEBdySBW%2Bonts6uKv7sDCwOHlrKRmzzfwRsUz6IuFgfZwlHy4OYTJdzL%2BSHxDFKuygoocGv0Lo0JmHaBf%2BA%2BtDur20Cq9qdsxGujWUvziaocMpLojWgasTyacq3lsuEPmJ1AMI45K5Br%2By%2BzZsxgqoWvPnATqW8K53%2FeA%3D%3D&client_id=0oark0q2zci2Z0taC0h7&redirect_uri=https%3A%2F%2Fsit.test-aicpa.org%2Foauth2%2Fidpresponse&response_type=code&scope=openid+profile
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://edcasteu.oktapreview.com/oauth2/v1/authorize?client_id=dxniVPZY9427%21&idp=0oauh7n47NPzDzTrj0x6&nonce=YsG76jo&redirect_uri=https%3A%2F%2Ftrautomationv3mum.futureskillsprime.in%2Fauth%2Flxp_oauth%2Fcallback&response_mode=query&response_type=code&scope=openid+email+profile+offline_access&state=74c081ed47263e9529ebe28f9089566aa54289cf99fae48b
  baseline: 302 -> www.facebook.com
  canary  : 400 -> (none)
https://directemployers.oktapreview.com/oauth2/default/v1/authorize?client_id=0oara0hd2fvyamqlr0h7&nonce=BBCLQru23Vu8trKunfmwAKjpTXvkd33I&redirect_uri=https%3A%2F%2Fqc.de.works%2Foidc%2Fcallback%2F&response_type=code&scope=openid+email&state=bUdhCRK96JvWmYrpcfHKSXKSt6D05Hyd
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://economist.oktapreview.com/oauth2/v1/authorize?response_type=code&scope=openid&state=fmmwI6F1%2FHmITp8bNRZlqYgq9uBfMORu%2Bw93uZKYcZRCrEzaVrCJ9OsrG962G28qu8Sb6uj%2Bqqm0IlFicbcC%2Bdli327FYLURhIbXdW7LNDY58mA5pdsJkezYm8j28IxJTVml2B9OFW0Wj0QnjSrXub6ke7o%2Bgf3NwOB28wmzJVIS3twwsDAc0eaCk8LFfs57eO%2FfHvEcFduobKNe1QRsWXcgePstM0jWuNn94YlHixf%2FJ0tuiA%3D%3D&client_id=0oa9e7o4cgvnCd2hL0x7&redirect_uri=https%3A%2F%2Fairflow.dev.mldp.economist.com%2Foauth2%2Fidpresponse
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://engieapppreview.oktapreview.com/oauth2/v1/authorize?response_type=code&scope=openid+email+profile&nonce=3e131b95887f71639c38b93874685960807731dfd7059434ac2804a447949b1d&state=%2F&client_id=0oa98as4ex2xEm3uq0x7&redirect_uri=https%3A%2F%2Flbe-digital-documentation.int.mylaborelec.com%2F_callback
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://engieapppreview.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa9v5fkypKnzsydW0x7&redirect_uri=https%3A%2F%2Fcontroleconso-ppr.fraicheurdeparis.fr%2Flogin%2Fokta%2Fcallback&scope=openid+profile+email&response_type=code&state=fKV3AACHA3YMMimPu1Db6mPFDkewMs5EOu3NsMkp
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://ecolabext.oktapreview.com/login/login.htm?fromURI=%2Fapp%2Ftemplate_wsfed%2Fexksdqqck5VCIKFaJ0h7%2Fsso%2Fwsfed%2Fpassive%3Fwa%3Dwsignin1.0%26wct%3D2024-09-13T02%253A32%253A48Z%26wctx%3Drm%253D0%2526id%253Dpassive%2526ru%253D%25252f%26wtrealm%3Durn%253A%2Bstg-bi-ecosure
  baseline: 200 -> (none)
  canary  : 429 -> (none)
https://esri-qa.oktapreview.com/login/login.htm?fromURI=%2Fapp%2Fesridev_globaltrainingdev_1%2Fexkhnkmsz1HFGfxzN0h7%2Fsso%2Fsaml%3FSAMLRequest%3DnVNLb%252BIwEP4rke%252FkQVO6WISKBXWL1O1GwPbQS2WcASwcO%252FU4hPbXr2NgxaHlwCnSzOeZ7zEZ3O9LGezAoNAqI0kYk%252FvhAFkpKzqq7UbN4L0GtIGDKaS%252BkZHaKKoZCqSKlYDUcjof%252FX6i3TCmldFWcy1JMJ1k5G1ZLFOW8l6x6t3yu5skuU05CV5OC90LB0SsYarQMmVdKU76nbjf6d4s4pQmfdrthemP9JUE%252BXH0T6EKodaXeSwPIKSPi0Xeyf%252FMFyQYIYKxbvFYK6xLMHMwO8Hh7%252BwpIxtrKxpFa1uFgEaEXJdRqzfiBzAJJs4IoZj1zFs4OnyL7byzUG8tqwzsBDT%252BKasq3ytg97aWesmkNUwoR6mtJBHstxu1LfEzeXz4tdp%252FPsebuwhR%252B53kkAH1zpgz8y9rZid9ZHhU0zSNZ%252BYpfbVyEJ0tOiX%252F7CZPJ7mWgn9ck%252FyDNiWz36OTMPEVUXRWHkqhZEKOisIAostJSt2MDTALGbGmBhKdqB3vEQp%252FnS5HC%252FurrnOsy4oZgW2WsGfcnjw%252FHzyWztIZrK5J4CKMU96OduXcfRptiva4gTthC8MUVtrYYzRf8Rkeet%252FY8b97%252FgcP%252FwE%253D
  baseline: 200 -> (none)
  canary  : 429 -> (none)
https://ethias-dev.oktapreview.com/oauth2/v1/authorize?code_challenge_method=S256&code_challenge=3E8KybrDvaajOvsaaTPmT_SMXYbS3zMd0NS1qCuFKsI&scope=openid&response_type=code&state=HXlX5NctRPBKqBOayim8TQ4hcYxJFZet&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&response_mode=query&nonce=_QEN0adVS8CQcNld1Cxc5xPK6uCmGgN4&redirect_uri=https%3A%2F%2Fethias-dev-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://gartner.oktapreview.com/oauth2/v1/authorize?client_id=0oas09hmh4CUN1dJi0h7&nonce=638617964144153284.YmY0ZWU0OTAtYzFiNy00M2M1LWIxMGUtOTY2MjE5OTQyNDNmMmFkZmUxZmQtY2MwYy00NTAxLThlODItMWYyMmMxMzJmMDRm&redirect_uri=https%3A%2F%2Fmidaspv.gartner.com%2Fauthorization-code%2Fcallback&response_type=code&scope=openid+profile&state=OpenIdConnect.AuthenticationProperties%3D5jabrh3ewUziw_oYcHqWH6LI5bBn2gvGDOknMRD0LEw89mkv_fSw6AI9MfhwVNuIqyzLXB8SYKxYrICJYnBfoX1ANoarrCJyhZ_eUsE0kNzKOeM3fuQgBGnTlEj41MdazFtZDHTzYDCF7NpZpwMMY_ZSHzW5zCM8bCYa3x1XWfp3SHcRmULEBoGpQSzVmOqgE8sijId-nxvUdI3323TYRn53iZrADa4rGrA-hsM0fkSGzRVDr5bkDOMIh5tUmhyJewgbL8qEEZ_DN2nK4TPNrA&x-client-SKU=ID_NET461&x-client-ver=6.8.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://gcdev.oktapreview.com/oauth2/default/v1/authorize?response_type=code&scope=openid%20email&client_id=0oa118wv1vsBfsAuh0h8&state=SVMlXGs-r3vTob5jPrcOWi8jPCE&redirect_uri=https%3A%2F%2Fdev.gc-hybridsolutions.com%2Fprotected%2Foidc%2Fredirect_uri&nonce=8XOECkHDlV7t4FD6DCZcZSV-Vxo7cy0qAf1CpBUHXcM
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://gcqc.oktapreview.com/oauth2/aus14y4x3hwgy7SgJ0h8/v1/authorize?response_type=code&scope=openid%20email&client_id=0oa14y3v4soCtOtWC0h8&state=i22_Y_6epzrWVPS56xtTh4n7ZcU&redirect_uri=https%3A%2F%2Fqa.gc-hybridsolutions.com%2Fprotected%2Foidc%2Fredirect_uri&nonce=kGxLXDvvptDdqF44St1HguyV7GV8T5cELEffEEYRXA4&response_mode=form_post
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://gr.oktapreview.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=XexZQTlqHA3URpen8_HcruZuVSy9QoWG4Fe_6RTTM9Q&code_challenge_method=S256&nonce=73NpsvMqyFJs9IBLKw3wAq5nyLHvOOdIVClPTs2k2XUoUPbHiyFrNY2Nu6drS40n&redirect_uri=https%3A%2F%2Fgr.oktapreview.com%2Fenduser%2Fcallback&response_type=code&state=AxyfAYdpLVwS2UpKThIYQHt0jYkuuU4wDYsM2lC8dYA3eih45hRhAwFzEWYyyfR4&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage%20okta.myAccount.sessions.manage
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://gr.oktapreview.com/oauth2/aus1sds3hsfNA2X4t0h8/v1/authorize?client_id=0oa1tfv5il16vdXcv0h8&nonce=612726ca-dd57-46f1-9044-231a2b1717fe&state=2ac73741-8e55-4e66-84d4-e3f127016503&scope=openid+offline_access+profile&response_type=code&redirect_uri=https%3A%2F%2Fswan.gr-dev.com%2Foauth%2Fcb
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hashicorp.oktapreview.com/oauth2/default/v1/authorize?response_type=code&scope=openid+profile&state=nxMFbYemM2aHqg88fZ8qrg6ajQHj8ka%2BobP6r9LBfTIy1ef%2Bf7WW15rqAeywBBTvedJHfHI01RTv0%2BrwFXyh8KSoHmg%2BE0k3kW%2BzhqNexOYN6XVbuTA0t8NQQxT%2FzTpzoKBQFLpz%2FjCCdDah4N8IVt0yXRUjxskHkjvo904qr6xR6oMRMe6KiJ2AuUSCiOYTGkpH0FLYWkfs%2BdYWQS9%2FvkDQ%2BlUR0nvVIsYLKR9H0H%2FUrNhBiA%3D%3D&client_id=0oa1h5qegr5NWupIR0h8&redirect_uri=https%3A%2F%2Fhashipaper-dev.hashicorp.services%2Foauth2%2Fidpresponse
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hashicorp.oktapreview.com/oauth2/v1/authorize?client_id=0oa13q93bw0IRGIhX0h8&redirect_uri=https%3A%2F%2Fhashilinks.dev.secops.hashicorp.services%2Foauth2%2Fidpresponse&response_type=code&scope=openid+profile&state=ZwJunZBlZnCbpO2uUfqjTz6fvf0j5Ufd%2BaGjbQixti36QBgFVgGanmEJUYqYOMaDMw%2FJG8oBreHAEiOnSdxC1vG0yrZXTJnJEiQN6DM0Crep5H3OoOQ1060Ba7cm2ANy4THcZSdf1lAgYEcFaN7q2uZvmeV8wUWr5VZwxrj5GtZJXkKdATAi2vygCT%2BXJs5Thg%2F6gA4LNhsJc%2BU2fBZKRi8%2FCEb%2BXxk8QjlZyd0P3qJ8iJvRqA%3D%3D
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hc-internal-dev.oktapreview.com/oauth2/ausc9vmug09Pn11Py1d7/v1/authorize?client_id=0oac9v9o3sOkoeRFe1d7&redirect_uri=https%3A%2F%2Fapi-dev.healthcatalyst.net%2Fconfig%2Flogin%2Fcallback&scope=openid+email+profile+offline_access&state=4QxKvx0bBTZ6u1Prz2tS4RIQI5Z4X0J1vyi2uVWsmRBYZqr3eeyE49Tgn3CjGXJU4QJEJzD1H49nckbl6vM8QQ&code_challenge=r5A6fMYp8QY3YNfS27oDrgP5Apxvxe8nN2vhL9I2GQY&code_challenge_method=S256&response_type=code&response_mode=query
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hc-internal-dev.oktapreview.com/oauth2/aus9wk59yxM9emUKA1d6/v1/authorize?response_type=code&client_id=0oa2gfxs15yrDSPZy1d7&state=cmNEUWptQWpFZkIyN0hVRWNfM3d3c2E1Tnp5ZFpVb2lXQ3dOQzNnRlZsZVJZ%3B%252Fpopulation%252F1%252Fdefine%253Fgrain%253DGMDatabricksPatient&redirect_uri=https%3A%2F%2Fcds-dev-cus-pop-app-test.azurewebsites.net%2Fauth&scope=openid+profile+offline_access&code_challenge=B0YLcUmh6mNoNkdgJYanUMOdKRhNeq-5OOi8q4UP8mQ&code_challenge_method=S256&nonce=cmNEUWptQWpFZkIyN0hVRWNfM3d3c2E1Tnp5ZFpVb2lXQ3dOQzNnRlZsZVJZ
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hc-internal-dev.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2Fhc-internal-dev-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=B4S0sPwzMwR3Dumn5rPxHgj8DhdOAJEC&nonce=0B6FXAcAv7Qr6dFh3A-8Tak0O318akrd&code_challenge=R5_7b3YEOUwtSX_BzAOd-P9rHHHNQ_YF3SX3tUxXFOE&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hc-internal-hub.oktapreview.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=kOTYyPQXQOZDUlY0b-Y8ogbseNmACqMJVicZpcdcmGM&code_challenge_method=S256&nonce=J8jWPLbL3sQc5TlWeEkhodLxCyNxseRQTpps1ePYFGwkpi0k17RfkJLfCG9WLwSW&redirect_uri=https%3A%2F%2Fhc-internal-hub.oktapreview.com%2Fenduser%2Fcallback&response_type=code&state=NOGBJnrCW7CHes2Y5utKNq5EIAV9BG2ku4ndTbb8pC20VijrKuqZE4LgZgcSSAhk&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage%20okta.myAccount.sessions.manage
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://ic-consult-kit.oktapreview.com/oauth2/v1/authorize?response_type=code&response_mode=query&client_id=okta.b58d5b75-07d4-5f25-bf59-368a1261a405&redirect_uri=https%3A%2F%2Fic-consult-kit-admin.oktapreview.com%2Fadmin%2Fsso%2Fcallback&scope=openid&state=jCRI3VLNQxSbxLJ5WRVQeTaO85ox8MCb&nonce=CPUpd3f3McVXxjOYBvEl1S7gyOG_Ga64&code_challenge=mOWH9EDge47HKqYfPMNqA_mmYIQnrpHvB6_5TE4Ki0Q&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hingehealth-wf.oktapreview.com/oauth2/default/v1/authorize?redirect_uri=https%3A%2F%2Fvouch.hingehealth.io%2Fauth&response_type=code&scope=openid+email+profile&state=7ueTrPc23H4m6WcAI7S4DgyOwKPSw&client_id=0oa7w44hgyZJSe9tU1d7&code_challenge=f__OeVrE-rJIgDe26z0jI4n9nMesk4CFRXIvjHs-wR0&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://illinoisgov.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa1fje2oywtPLwSg0h8&redirect_uri=https%3A%2F%2Freciprocalqa.srs.illinois.gov%2Fauthorization-code%2Fcallback&response_type=code&scope=openid%20profile%20email&code_challenge=6C6QKeddfrFSfSU1TsfuauLDoLSnd04oXKtplb9Q7i8&code_challenge_method=S256&state=OpenIdConnect.AuthenticationProperties%3DgD4nE5ZILsNqkEhz1-Qb9kHxyfdio2uExc5fk4T2k0DR6HmQgJykjw5QEfimZbzwWOTCH3QGHidIJnb3gZV6oHooXsAcLAfHAU6T0ftLlkgEZMAHx055qUYyoDkJH1NvlQ-aFY7JJCJqTJiGl2ob_Dd7mNkUM22zb3NtBjntP1ixgjuU0OX6-uXki42VS4gNBLNLuZnLMxgMqgzb_bLdPeih8Jtf8x_luIuIe6bYDtnvAJEJFmPhtD1fq29JrHPlpBl0XoMmSsHHjU3xgkcLg13iT2yvy7s_ij7ARkT25zt1lDup9T3AhnGXl6Ty-nx5lDyBrfxScxR0Kr9lgwaFMFb15i7qyVdV4gNuDx4F6jM&response_mode=form_post&nonce=639277351432745525.MDMyYjYwMWUtNmY0OS00ZGQwLWI2NDUtMDA5ZGM5YzdmZTcwYjU0ZmIyNzItOWI0NC00YjY3LTg2ZDctNDJiZDFjZDFiMTNi&x-client-SKU=ID_NET472&x-client-ver=8.18.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://iptiq-pnc-emea.oktapreview.com/oauth2/default/v1/authorize?access_type=offline&client_id=0oaq1r9dfAz28jLhh0x6&redirect_uri=https%3A%2F%2Fsso.d.eu1.caramelspec.com%2Foauth2%2Fcallback&response_type=code&scope=openid+profile+email+groups+offline_access&state=8vD7cCIy0R1ZYbwxrAOo9sQXTFTCJLr1lpVlIBa8A22SSa4S4uqQT7pj7Bg8dBYQ%7C27077829-628b-4125-8f54-465db328fab9
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://hmh-prod-98aa6ff0-c472-4ab0-8808-f811ace8909d.oktapreview.com/oauth2/v1/authorize?idp=0oa22ik2672uwa5Kl1d7&grant_type=authorization_code&state=eyJhbGciOiJSUzI1NiJ9.eyJvcmdfcmVmX2lkIjoiOThhYTZmZjAtYzQ3Mi00YWIwLTg4MDgtZjgxMWFjZTg5MDlkIiwiYXVkIjoiaHR0cHM6Ly93d3cuaG1oY28uY29tIiwib3JnX3BpZCI6IjkyMDA4MDYwIiwiaWRwIjoiMG9hMjJpazI2NzJ1d2E1S2wxZDciLCJpc3MiOiJobWgtcHJvZC05OGFhNmZmMC1jNDcyLTRhYjAtODgwOC1mODExYWNlODkwOWQiLCJleHAiOjE3MzI5Njc0NDQsImlhdCI6MTczMjk2NzE0NCwianRpIjoiYTAzNjZhZTAtM2Y0My00N2NkLWI3Y2YtMmMzYTJjMmY4ODI1In0.d_W-ozZ-j3tFf08MEZVAtMUjnvOzDU-bRt_69HBN6CH3LkryrGKKEa0z5A9wHWYdAtbEfx5CusO3DAj3QC5ha_gv5Ar9MC6GUANfDzow0o7Pviukhb2iqc5NHSs5DrpQRJ1zD3DIQWWKsiYkekvLDZDQXm9GA9QGulvrlypJ-mzQBYthIuJQBcG7YQ1RvwYNf7OqGFnkSaWj1b96CaX588CvdzR7u2-VNFCaUltR6POPaxfFRPXkBKoSVGquzSH6v64IIsZ0tBNPn0IIqBS2Yzx5F-l7wJa83VkbY8N59L1vmLQI96HDXWeU4sBv2xaeZRpqQBjw_b_m2pCyCkNcSQ&scope=openid%20profile%20email&redirect_uri=https://my.hrw.com/okta-hrw-sp/api/v1/callback&client_id=0oa15mbfbmXEBLEsh1d7&client_secret=MmDRHxFV8eadT9BQP3JsqrILXxyrL10995OxZeF7&response_type=code
  baseline: 302 -> hmh-prod-98aa6ff0-c472-4ab0-8808-f811ace8909d.oktapreview.com
  canary  : 400 -> (none)
https://iress.oktapreview.com/oauth2/default/v1/authorize?code_challenge=cJOERAz8pR-aH3pZqOiOhRoXyycOjGkfdV1vgbUBr3g&code_challenge_method=S256&nonce=8bfd8b812821a16c7139b50d92a9258f5fa8400f33e096210506ac73cdbace10&state=%2F&client_id=0oaxsh98g4o5Jy6by0h7&response_type=code&scope=openid+email&redirect_uri=https%3A%2F%2Fsre-cc-automation.aws-dsre-staging-au.iress.online%2F_callback
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://incode.oktapreview.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=8g2r9qtTPDK0MX0wvW_HTvm4QNnJ9BXsbg6MmekJsjM&code_challenge_method=S256&nonce=V1l7Y2fy5SAryLhBCPEhpcZzYqNLRMWC7jEkpNerrbrsnulyy8CHz16VM83UhAIv&redirect_uri=https%3A%2F%2Fincode.oktapreview.com%2Fenduser%2Fcallback&response_type=code&state=pFVH0VSS4JZ8ND43D5qwV2CFSdCDt9ySgjMkWnYAkbV0fGvxN4NPxOLbbxqVndIo&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage%20okta.myAccount.sessions.manage
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://kcc.oktapreview.com/oauth2/v1/authorize?client_id=0oa1eqe5jumOarvxL0h8&nonce=638620510329635085.NzJmN2RmNjEtYTA5Ni00ZDc1LWI0YWYtNTU5YTZkZDg1YTRlZmRmNWVkOGEtZTA3Yi00MzcyLWE4NzAtZDY3NzRmM2NiNzNh&redirect_uri=https%3A%2F%2Fdev2-b.itaas.gwsweb.net%2Fauthorization-code%2Fcallback&response_mode=form_post&response_type=code+id_token&scope=openid+profile&state=OpenIdConnect.AuthenticationProperties%3D-jLlA3MhtOqe5vngoyANNfHjiB836o_gFuiuHr6_cb6U0Z8zhcQODRg4IsWgj3oaserzaVv7Mkne9SHyFstbnZQgMuiW0wJe4L6vq3e0sCky6JwsfnxdBi2BcNSID4fcahVZq28JZs98YVKGymHBNcMROgPvUvil_Vu3TOKEjHxQmnt8xBZUNZao5nXyahxJX9sRy7kbo0-ZG2M6WtDczsMruc_-6J0hZWXJLa6IpvEYNsgrC5I8r6xBPq1wAi2LnzzMylZPpcGd2QLPxz_eZw&x-client-SKU=ID_NET472&x-client-ver=7.4.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://jaworldwide.oktapreview.com/oauth2/default/v1/authorize?scope=openid+profile+openid+profile+offline_access&code_challenge_method=S256&code_challenge=-ED1bxAw4oKISVR_Dh8Qr00kYtHGzBqp1NKo-jZsbf8&response_mode=form_post&nonce=638696204278200215.NjliODVjMjctOGJiNy00YzZhLTk1NWItMWFiYTkwMDBkY2E4ZGMyZWU3MDItZTUyOC00ZGViLThkNzYtOWM4MDZkY2QwYjkw&state=CfDJ8LwIGTixckZHtBCz6wY8T9PX1aeS2JCPnsLmab8hAJNW5fFmfWhmAb3NTj8aFgueVK2oO93uiZMU1dkJW0DwXLl73lCY-0c6mwfVU-1DXMzoLvc4KcXNEboOLOzApTes7ntzMkQC_4hY19ZRUJRHd7SPh-PEP1402yp3VYcTxkqlAWIjVdYnZHuHvLGt6SeNFQ7mpYFDj7CBnTjG3L0sP8Oru_RHFxnwzhea0lISpvGmO-q5DFK0NDaILi7klq8jfr4hTRk9dpst5ebdDbJCq-sryxyTqimkXstg_rbQWKySBhN3kjdAvCz1hENKPHuAclyJe0AVV1sVu3upH63lxUZl3GAOE8_TG9Qx3BNc-LoRkQMc1dGOiUYKAgtKtY3saQ&response_type=code&client_id=0oa8x5wibrpOcRwH71d7&x-client-ver=6.15.1.0&redirect_uri=https%3A%2F%2Fadmin.jatitan.org%2Fsignin-oidc&x-client-SKU=ID_NETSTANDARD2_0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://kbhome.oktapreview.com/oauth2/aus681orv3J5nRFWd1d7/v1/authorize?client_id=0oa681j1euJAWfWGN1d7&nonce=19229803-b484-4000-b3b8-575627e615d8&redirect_uri=https%3A%2F%2Fbuilder-kbhs.dev.saas.rate.com%2Fauth%2Foauth%2Fcb&response_type=code&scope=openid+profile+email+offline_access&state=af463dd8-8c99-4216-97c1-910d5c5bd78e
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://kpmgstaging.oktapreview.com/oauth2/v1/authorize?response_mode=form_post&redirect_uri=https%3A%2F%2Falumnipcuat.us.kpmg.com%2FSeparatedPartnerDashboard%2FIndex&state=OpenIdConnect.AuthenticationProperties%3DqHSC3YoeqHGhqYQzJ9J6_cODGjmSf5OUsTIhdbYaYhxkF-4j0tVcGTCQzZNXuMeKAuGnPuAJD0jO9jjA1j-Scpa3KPKhTGeCcuoQQjzJhJ9Dweq0F9RNdHbVHZNRxGwzwLxG3l-Eaofvsr0rhX7SgSm8XmAytJWGK1i_KYrg_hkzTBlZX6HJ8tehuxM-P3QvaZRL1FqqsMQ5dG7dzk0isscOLVgTkpK2_1jcCijNjzyREmnaP4X1iMqi1QdBmvKwLWFwf3J35eOvprK5cHkTQbUE6QnfDTwPxPSIaU6MY_KLWR_1VOQRWhDHe_Htut0IZgKcvQz2WjFnkNWaIxPnXO7tAVd8h5E0-O7fbjvDTQcApX9wvmXLhk4ThnEEZ8zuk-Ofew1AfSUtwXD339wM4oazZjJ5z1z99JA-6Q7Ig_A&x-client-SKU=ID_NET461&client_id=0oah4de2vafHQjMWa1d7&x-client-ver=5.3.0.0&scope=openid+profile+email+groups&code_challenge=7jXmQqp-Xp5kOqW_W4mmC42lW73CTSlq5YB4n-sHvTU&code_challenge_method=S256&response_type=code&nonce=638633814343227502.NTA3ZTlhZjItZDZhYS00MmFhLTlhMWYtODhhMzc1M2JlYjkzN2FmOGJkNjctYjEzYS00YTZiLTliOGMtNTY2YzUxNDFlNjZi
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://kueski.oktapreview.com/oauth2/v1/authorize?redirect_uri=https%3A%2F%2Fpayment-dashboard.staging-shared.kueski.codes%2Foauth2%2Fcallback&response_type=code&scope=openid+email&state=768d999def5502d588957c2501e9816f%3A%2F&approval_prompt=force&client_id=0oa22zrk1x5whzC940h8
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://marsh-mmc.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa15hrbzmpmSV54X0h8&nonce=638618307576126211.NTRiMmJhMjktMmY1NS00OTQ4LTkwMzEtNjllMDA4MGNiNTI1YjQ2YmIwYjEtZmE4Ni00Y2E2LWFkNDMtYjRkZjkxMmViYTNk&redirect_uri=https%3A%2F%2Fuat.jlttmr.ceecat.com.au%2Fdefault.aspx&response_mode=form_post&response_type=code&scope=openid+profile+email&state=OpenIdConnect.AuthenticationProperties%3DqBv6_eNtPHK2uWByln13Fd3TdbBzM1ba2BusJUTRaqY7tWdX6u75C_trJbvtBI05PzjZzIL8juHN79zty41a5-LMfr0JGLL5pH8D3clbt-2It7F_srGftSH1yzZvYbDvtZZCbWiW8IKYMIHstEptL3Zmh3n5qsPWjCqRaujGaO_RjtPqNAk0VqVoIRsAz-1cbKMpot7dTLUP9MXjgaiy1LbTbxj3YAP6ZuQ4rcqmIYKz7uP9O0FsL9OKss7hI-dv&x-client-SKU=ID_NET461&x-client-ver=5.3.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://massmutual.oktapreview.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=c2iYjX0GauomQ-FuN9kNSaGTutLAG6WYldQu2leC3cU&code_challenge_method=S256&nonce=2cfau9lpfADdivMoQoHpb2z9TBkf8D1Na1ivu4XJL0Sp3zvZUwyp18W7v6sD4Dnt&redirect_uri=https%3A%2F%2Fmassmutual.oktapreview.com%2Fenduser%2Fcallback&response_type=code&state=byiOzqLCcrkfVs4qoD5OR87lP7HUDyAv9SPwrjlIONFsAclaBwLJ7g1HIf1DaoNd&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://massmutual.oktapreview.com/oauth2/aus2iwwefkdUcrNTt0h8/v1/authorize?client_id=0oa2ixqp3lsEwKkmd0h8&code_challenge=FKmRCPxd7fT0SpnyvuCR0ZzGQLMbCFzZhD_8YsZkpGg&code_challenge_method=S256&nonce=EgEkPUteAaTBp3LM5h001UB6cAWOBft6uCDUwGELLQHsdrrbeycDJY2nfrHvDapQ&redirect_uri=https%3A%2F%2Fstars-qa.massmutual.com%2Foidc%2Fcallback&response_type=code&state=gv3xUMEHs3SsyP8RQY8YOqII8Pq8zF38rUK8gjnbVI6O1OuKqVuXV0SUJ2cTs8iR&scope=openid%20profile%20email%20groups%20employeeDualID%20employeeNumber%20offline_access
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://monashuniqa.oktapreview.com/oauth2/ausqn6wdi7gXsH5PX0h7/v1/authorize?client_id=0oaqn5uy3qnZ7vwCs0h7&redirect_uri=https%3A%2F%2Fidentity.idmqat.monash.edu%2Fauth-callback&response_type=code&scope=openid%20profile%20email%20offline_access&state=4bd7106987b64bee9d77750ff22db582&code_challenge=RrB4jbdDuzkw9yLApXt4Cy_qOX3WeMei6rucEaWGJgs&code_challenge_method=S256&response_mode=query
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://mckinsey-uat.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa2b0yty1rn386UA0h8&response_type=code&scope=openid+email+profile+groups&redirect_uri=https%3A%2F%2Fnpn-getstarted.mckinsey.com%2Fopenid-connect%2Fgeneric&state=hVNwclGK3luqnS4l7MaMTGkILBMLUYgh6_wHRUwEBTU
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://meijerb2bdemo.oktapreview.com/oauth2/default/v1/authorize?code_challenge=Bx3Mp_cw8SWaJbZ4w59NxNEWhdZFP4ZHe3GGat-iPG0&code_challenge_method=S256&client_id=0oac17p08jFRtRFcy1d7&nonce=638705182193960519.YTUxYmE1YjUtNmY4MC00NTA2LWIwMzAtNzg3MTllMDA5NTQzMWY5NmU5NGUtY2Q4Yy00MGFjLThlN2EtNWM2Yzk4ZWQzMWYy&x-client-SKU=ID_NET472&x-client-ver=7.0.3.0&response_type=code&scope=openid+profile&redirect_uri=https%3A%2F%2Fi-vss.meijer.com%2FVSSMainInt.aspx&state=OpenIdConnect.AuthenticationProperties%3DEAZ9ONVMDDFokFYTAXMq1DUv02AiWY3L3eLvqwkpbYKwqBkoixxt39OE6whNxzFbbEmC4a7jyCdMu4QPJEK4w8JiXqDHUnVYL_C_s01r0KFXJoLJaOZVI51ZyWTDKUgm0GSkG1IBpnWfJz7m5pMRp6duhp5tBM2dMh8X131Bzr04FfXnSru-RfNEBVvBM641mVWKKZYv0NtwWdZQI35w3AyyH6pxnrusi8XQCvAWWIYj0ZBMsjufiNXBsC3NDS-H0aUxYUyBbxQPuSgvZf5CSAZAKdRqlcxfCPJFIfp-nM1CyRf9cIBzSRllcd_HSHUH&domain_hint=meijer.com&response_mode=form_post
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://myflfamilies.oktapreview.com/oauth2/aus2a6ehexqzAyg8F0h8/v1/authorize?client_id=0oa2a6e9kw0nBvS1B0h8&redirect_uri=https%3A%2F%2Ffrc-dev.myflfamilies.com%2Fauthorization-code%2Fcallback&response_type=code&scope=openid%20profile%20email&code_challenge=IoC-xt_rDZPdNLvA-qsiolgzgL6hwxmqhw1wpz5qSos&code_challenge_method=S256&response_mode=form_post&nonce=638807013870041904.ZmI3MGFmZjUtZjdiNy00Y2JmLWE3MzMtMDQ1MGU5OTU5YzhiMTk5OWU2ZDEtMmU3YS00ODIwLWE3YTUtZGY4YWQ1Yjc1ZGY0&state=CfDJ8MOHb8lj1rhBv2ox76_QX24aAyd146QTfwvfupzZAglHRyDvu3xSEih3JEIfxy0jrCIGGP1ngTDoTJEQVQJ2jwoLQqlg2X9-0AoV2FyF5H-kJhpptMvmHguaPdeOpfk9bCQJG7P-3q7HyZCAIfydbLKUp731YNGz6TI-psqMN44ZRghH2gHRLM2-7abJfEAKpDHREupFpYbo5LGQOGVxOyTSCVfCJ0ALkOQc80G1IDO-HrStyk8TZqXJJhVzY3zUPtRsHr3oEmckvKVPXo-Y1CZ4hOCFOP-P6JmIb-39L7egb0kkr3fRj37HZJohHOPS8hTiUADC1dLviqaPNiwxgdv92IPb-K46dLiAt8GT0tTJRhcorpJ6nciOO5xdh3u9vDXkIozosmPehVm0Z3MBT-8&x-client-SKU=ID_NET8_0&x-client-ver=8.3.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://myflfamilies.oktapreview.com/oauth2/aus299bxshooBeOa40h8/v1/authorize?client_id=0oa299brwxmxI87cY0h8&redirect_uri=https%3A%2F%2Fadoptiontransparencydev.myflfamilies.com%2Fauthorization-code%2Fcallback&response_type=code&scope=openid%20profile&code_challenge=F6XrFzYcZHcRDm9RJjnmJUj-jaU62uKvBUM-p9ExKYI&code_challenge_method=S256&response_mode=form_post&nonce=638807016866563138.YmU2ZGEyYzUtZmNmYS00MGE5LWI4OTctZTEwNTg2NjAzYmM4NzM1Yzk4ZmMtYjM1Mi00ZTdlLWE4YjctZmM4MjdlNTE1ZDA0&state=CfDJ8A77A0VCAaJKiJGVavgwBIeUCKROEldCZTKPqBDh3n94v-KEc_tnNfEibKoCsDJmoihKI05UZP17dswl8ZdlVnAiLyMswCgmg6CP26NcuIN9PugWB8kvEIyJQdr7DlCX_OGHX2qofeI4dSNh8nsMqFLboq5i8bheRakiG-8hLu4CluTH_JBNAffeS0Q52z1YD-aKF4bbsFvGjzr8SrQuYVkU7mOxb_bpYrFkfgG4rP66Hgz_xi8sRT9j_GIBqKABWndZwtgsxHkkuLeDtImoOhIdeCqPEoNUqdylZMIv7atyPjqFS1f7RIlPPmbaXmCXiIuphMoQhHmDiZidYWdW3oHMcO2QmoCRfS-kDgrLFPy6zrcwlM77DbQuXpc1q_iJtZL_heJjE270bvhAa3VciZ_baFFTbD3V8WturOj6N3qNUWj_zm2xOQ9NFbHsvhBpdQ&x-client-SKU=ID_NET8_0&x-client-ver=7.1.2.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://mycdsglobal.oktapreview.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&scope=openid+profile+email+okta.users.read.self+okta.users.manage.self+okta.internal.enduser.read+okta.internal.enduser.manage+okta.enduser.dashboard.read+okta.enduser.dashboard.manage+okta.myAccount.sessions.manage+okta.internal.navigation.enduser.read+okta.internal.navigation.enduser.read&state=tatT5g8DXTpfriIgM73ZbTR7MOgS1bY1oCMHoA5LdGI&redirect_uri=https%3A%2F%2Fmycdsglobal.oktapreview.com%2Fenduser%2Fcallback&response_type=code&nonce=cU4ZQM-_QyivOdT3NJ29JDmARZc1ZjEmYeBUQklFIvU&code_challenge=_a0djBC5jV7BXyPiW-LrEJQcTmEqnjWJ-VhzWlQZinw&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://naspers.oktapreview.com/oauth2/default/v1/authorize?client_id=0oa19d1p03z9SK9eQ0h8&redirect_uri=https%3A%2F%2Fcomms.prosus.dev%2Foauth2%2Fidpresponse&response_type=code&scope=openid&state=d0BObYz3ddm1kHZF1E%2F87b7qyF2oqJk3w0OhLDw7Av3YMw3p0yUmogPeF8x%2B2KF9aTWI%2FzxfGOmqaaa1QiOk7BT2%2F0LYABB56Eg2%2BHEByb4BTQNz%2FpeCyjp5pV0HwNIn5FHNfxpCj9zXsCk6TICRWyWXsynfrOAwNx877WkhH74TuGnsh0jLrYxzS%2BWnzbSofGrBTj%2FBUlzknpdCjBy52wWpqlSaA%2F0w4pVw8EtdDGtwRfWxGg%3D%3D
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://mycdsglobal.oktapreview.com/oauth2/default/v1/authorize?client_id=0oaepxlr8mw6GHYii1d7&redirect_uri=https%3A%2F%2Fadvantage-dev.mycdsglobal.com%2Flaunchpad%2Fsignin-okta&response_type=code&scope=openid%20profile%20email&code_challenge=8wHLK4e3h8BcajNnziKxB8b_Z2eSWUaKu7Q5RWwGJ8M&code_challenge_method=S256&response_mode=form_post&nonce=639046892848031425.N2M5ODZlNTktODM0ZS00N2ZhLWJmMWEtMDFlZTc0MjBhMWQyN2Y2MzMzNGMtZjk2Ni00MzE5LTk2ZDktZThjYzczYjZlODZm&state=CfDJ8MLOtUVw2gRPoGJCXkxFQS6bFlgQHs0hVq3_5XPjnjrQpXnubNEOQ3V6MyPKgp_r0GD1M1wwXYWwcK6vVh1KQXkR5nMVHcj9j9qRapgO97ow8KtT-QGomsjDnJ2xuK78A9IM6hpmxpUGMtvdGbN7I2KB0WlF8OuYj00E-JNm_MXXoCqD2OYeWW1ri-uwIR5uOoWAO3ommIEzpOTW4m7fwksoC1Vj9GiZ5Di3r1Mj9wxBczu8grcgQEd5aSNCMXR5Tid4ch-U1gX4ahuS9N_Hy3RwGA8Aj3mCcEbnM-BF9FUGWse7TXEGkzZI8bpCK8QNZOjRJwdwCSuT6gmvdEBcwjExOf5eZCC6uajZHevDm-WDG0pepgBI1Iuw1eVS4qDRsiZAPpFGh9e0XElRzukj3hNHy8TnRwsivDwf9P8Ydvs0rhvPqB8g5iGjnVQD7fafBtPWlXPw7iQUoZqbI0wyblJFlJ2XzJfa_rxiNqK2sIeK9h7kcudz3VlEV5QxTAX0hTtfKsAnKDK-BiRxcPZDeb1K-6eKXorwEBQyA-_f41bR&x-client-SKU=ID_NET8_0&x-client-ver=8.2.0.0
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://newscorp.oktapreview.com/oauth2/v1/authorize?client_id=0oa1r7ay4847LoFHn0h8&response_type=code&scope=openid+profile+email&redirect_uri=https%3A%2F%2Flogin.lumapps.com%2Fv1%2Foauth2callback&state=b7fc8c08fe78434c9a6e9923aebe9940
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://nike-qa.oktapreview.com/oauth2/ausa0mcornpZLi0C40h7/v1/authorize?response_type=code&state=WFX31bASYEHfZY4fJ7p-gjf0&response_mode=query&redirect_uri=https%3A%2F%2Fzodiac-dev.nike.com&nonce=RXimvHUd2KNtbbOSUzaTY4f9&client_id=nike.niketech.zodiac-auth&code_challenge_method=S256&code_challenge=sk43EstR1ApzB5vt8Qrpl90S2-cOitS6KuRTvCWJyrc&scope=openid
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://org1-propp-2d8d.oktapreview.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=MjelrrkHYazee_KRIeMSXlBu6Q9v7Pv9LYftWTxfZog&code_challenge_method=S256&nonce=KxQnTlBUPNcYtJ8Fli4VZZpIRUrMun5rOBbaWNSAFEJqJrPagObwov5yhe1VVgjQ&redirect_uri=https%3A%2F%2Forg1-propp-2d8d.oktapreview.com%2Fenduser%2Fcallback&response_type=code&state=3ALGAPyXTpZUKtvbbG98Tx3AwdgyuQLnnPK3x0vwfyQhooCH2UzWqkFBaLjQGQOP&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage%20okta.myAccount.sessions.manage%20okta.internal.navigation.enduser.read
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://partnerpoc.oktapreview.com/oauth2/v1/authorize?client_id=0oanfasmgdTWNt6K50h7&idp=0oanfgh4kuGV3SBzm0h7&nonce=somenonce&redirect_uri=https%3A%2F%2Fpartnerpoc.oktapreview.com&response_mode=fragment&response_type=id_token&scope=openid&state=somestate
  baseline: 302 -> oktaprise.okta.com
  canary  : 400 -> (none)
https://partnershealthcare.oktapreview.com/oauth2/default/v1/authorize?code_challenge_method=S256&nonce=638670500066148466.ZTgzYjZhNjMtN2U5Zi00MjM3LThkOTEtMTkyYmNlMTZjNWJmOTdmMDI4NTctZmYxZS00MTcwLTg5NGEtOGEwOTVlODhmNmU4&code_challenge=sK8SI6qO7FzWWHjIsuLa6JmW5IkUGbmozljORnIi6u4&state=OpenIdConnect.AuthenticationProperties%3D2yZv7m9frexsBiw8bw8s3F_ULepkfi58cEZ1XbW8PFlJsWSJoIClYdZ96Jai3vBp0mUiMnnGvGpt3t7IDLCmqw78qQv17cRH13SK7G3yZfCsBxZcYckYNwQb3apyAH_lmuNnyGZ4uYAPYT9CWIXOYOryFHnZDIsJP0-jVJAbWIdsHNPmhnRIihr_N6fy_CSNEu7VmfymMF3kl6E8m7USZy-oPXL23QW5FVdMZjyAiSe5C4wtvLlFpQgbMJuuOLhex6K-YePAU3nmAOHzCl3FwE-fjeRj3Gw1Rm-NA6p4hm6qE8VUpuk3bv2vDbsym5ywHLRvC4uyq1_h10Bn1a6RAsHbTDA&x-client-SKU=ID_NET472&redirect_uri=https%3A%2F%2Fstage-epicdigitallibrary.mgb.org%2Fauthorization-code%2Fcallback&response_mode=form_post&x-client-ver=8.0.2.0&client_id=0oa1c4wmbdmA5cLif0h8&response_type=code&scope=openid+profile+email
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://penguinrandomhouse.oktapreview.com/oauth2/v1/authorize?client_id=0oa22efhl6phc1plJ0h8&redirect_uri=https%3A%2F%2Fahab-admin-tool-dev.dev.ahabtalent.com%2Foauth2%2Fidpresponse&response_type=code&scope=openid+profile&state=xiuqx3LEMchDJcKozB7Wg4JqX8RFwGNo3tYRbfe5%2F9AnqZRYwsOngdPEouY%2FAPHwazEdtWwcSvFS79jTYZWE1ahuT0uo41T98yScNk5cAwAgTIHjcUwBlc%2Fjsrou4PdA9TSmTPUmKl%2B436VP%2BYZ4MmXItp2qFJczNX3ULkeZD46YmjGeG0ysUztOSZvbwpnytwkEPlEt%2Fvg5ql56Abz1ad0QhLTXLKg60yVwvCTg883nO8yQBA%3D%3D
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://pplsi.oktapreview.com/oauth2/default/v1/authorize?client_id=0oaqduokoySlc3FNu0h7&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Flogin.dev-legalshieldinternal.com%2Fv1%2Foauth%2Fokta%2Fcallback&state=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImQ2MGY1ZWVmLWQ2YmUtNDkyZC1iN2Y5LWFhNjMwYzQyNjZhOSJ9.eyJyZWFsbSI6ImludGVybmFsIiwibm9uY2UiOiJkNWI1MTQ1ZS03NTI5LTRiNDktOGZlYy0wMmFhZmE3Y2YyYmYiLCJwYXRoIjoiLyIsInBvcnQiOiIiLCJhcHAiOiJhdGxhcyIsIm1vZGUiOjIsInN1YiI6bnVsbCwidmVyc2lvbiI6MCwianRpIjoiM2VmZGZkOGUtMzVmYy00NjBjLThhNDAtZWQ1MGU2ZDZkNGZhIn0.p9THqsERuhnWpeWafkL5RdY25MUtCum1QvIFlym0Wcyy6ZndSK-uzpQc1J-786hW2uTPG8n0ykkP8YEMIDJQ1g
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://phaedon.oktapreview.com/oauth2/v1/authorize?approval_prompt=force&client_id=0oafqpqi3fYt6gpq81d7&redirect_uri=https%3A%2F%2Fservices-stage1.wyndhamrewards.com%2Foauth2%2Fcallback&response_type=code&scope=openid+email+profile+groups+offline_access&state=Utfzhd2cwjFEY3mCMocdpKxRKXWc-rIZbgawJF9f_vY%3A%2F
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://realogy.oktapreview.com/oauth2/ausdtpyw647fbrcPi0h7/v1/authorize?client_id=0oam9rql6iuiCTyVH0h7&redirect_uri=https%3A%2F%2Ftools.stage.21online.com%2Fsession%2Flogin%2Fstart&scope=openid+profile+https%3A%2F%2Fbtt.realogyfg.com%2Fsecurityapi&state=20220414715414015e2d7a72e690f9c3bd20e9808c8d111394bd822a2aa2d964&nonce=e14f05c50022abb0dcc420611b0b9cfe&response_mode=form_post&idp=0oadw5tqwgwg5EBPd0h7&response_type=code
  baseline: 302 -> realogy.oktapreview.com
  canary  : 400 -> (none)
https://quorum.oktapreview.com/oauth2/v1/authorize?client_id=0oa172fn1recktA9f0h8&nonce=A891D647A79374C92A3DDE3EF55279CABEDFC7D875B5AA97988EDC778AC852C1&redirect_uri=https%3A%2F%2Ftest-land.ondemandquorum.com%2Fauth%2Fokta%2Fcallback&response_type=code&scope=openid+email+profile&state=cpkGa_6LEcG5WQ-OsOkHRYH3
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://rhoworld.oktapreview.com/oauth2/default/v1/authorize?nonce=ebe6848b96a5486a86e99cf4b6ddb09c_20241227030823&state=redir%3D%252F&scope=openid+profile+email&response_type=code&client_id=0oa1w8cuq9eKswU7t0h8&redirect_uri=https%3A%2F%2Ftracker.test.cloud.rhoworld.com%2F.auth%2Flogin%2FOkta%2Fcallback
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://recruitics.oktapreview.com/oauth2/ausw384lfGAdwj8XK1d6/v1/authorize?client_id=0oaw2y0rv8mJCiVTr1d6&scope=api+openid+groups+profile&state=zcg3a9AeHysn4gNwTr6r4WWy5EkI1yM-IakNGAvm4VQ%3D&redirect_uri=https%3A%2F%2Fapi.platform-staging.recruitics.com%2Flogin%2Foauth2%2Fcode%2Fokta&nonce=IdDSdD2q0S9_S3G-UKS-b8vsIxbCPfkJ9BHq_pDFKHU&response_type=code
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://safetyculture.oktapreview.com/oauth2/aus1xqmjangPBKVQB0h8/v1/authorize?client_id=0oa1yf3u4aihf0R3k0h8&code_challenge=0tOMw5BrIypezi6Tr5BNj9orYENVZfD_dkMDHhXlkIw&code_challenge_method=S256&nonce=fJuFnjbp2aExoesRwOZ8dTpQvYzBIqXItBR2PylBCUkcuQsy0kVIEOCypHrflAWY&redirect_uri=https%3A%2F%2Ftools.slate.scinfradev.com%2Fimplicit%2Fcallback&response_type=code&state=CaK11ZXSsneVXgBE0B7a6P33z2q7yk5DVCyXGXorZlBG5Dve8OuJ6FpDNB96PhJX&scope=openid%20profile%20email%20groups
  baseline: 200 -> (none)
  canary  : 400 -> (none)

### hackerone / Cloudflare — 67
program: https://hackerone.com/cloudflare

https://aem-vh.cloudflareaccess.com/cdn-cgi/access/login/dev-az.therailwayblackheath.co.uk?kid=4d1d06492ae2507cefd416c79c0d69da9e83491ef094fa3a69f5bf82a774cd9c&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjdhZDM0ZDYyNzhlNjlhYTM5NTE0NWE3NTdkYjA4NjA2MDNkNjljYzFjZGIyYTA3Njg1N2NmMjI1ZmMwYzNhZmQifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjRkMWQwNjQ5MmFlMjUwN2NlZmQ0MTZjNzljMGQ2OWRhOWU4MzQ5MWVmMDk0ZmEzYTY5ZjViZjgyYTc3NGNkOWMiLCJob3N0bmFtZSI6ImRldi1hei50aGVyYWlsd2F5YmxhY2toZWF0aC5jby51ayIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA5MzUxLCJuYmYiOjE3OTMwMDkwNTEsImlhdCI6MTc5MzAwOTA1MSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkRFIiwiYXBwX3Nlc3Npb25faGFzaCI6IjA0YTM0NTQ2ZTI4YWU0ZWJhMzE2YTViYTdlOTZmODAyMmQ2ZGFlMTZkOThmNTdiYzk5YjlmYTdjZTkxMzJhNzIifQ.DRvBoXHxhbf2dIZ0Kk8ZThOVmoghHuxbTVeGP72ZRC7svcs_I-kRoLdiF_hue60cL7JvkE8Ci5UP9FW9jckO3QTPd547WFRHMqCm2gRRtxtLEd2BmtyZW22VxXw7tKfxbHWyXU7hTBwzvWfGLmozezfp9cTRlTl4NP-AISWOsZnFUoZLwYTFXlL4fh42wgUvQhXi4yXi7suvmP3sJyxGFT06YJGBEGscHBrP3F9kR0H9NLDtMBszK7S6YBy4Tfh54luBCejenR235FWP_5xPQqhPxaWrUjscbvfTgkqSXuiIi9EiF0TkncqLPSv5RQlxP2ua64_CMsxkM9i-WFthBg&redirect_url=%2F
  baseline: 302 -> dev-az.therailwayblackheath.co.uk
  canary  : 400 -> (none)
https://anvilda.cloudflareaccess.com/cdn-cgi/access/login/core-headers-test-owners-live.pages.dev?kid=70de11b5d3bf10007e68d3c0673b886d87b9d84576d7117975ebef3d5efa7b9d&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImFiZTE2MjUxMTQxMWQ5NGI1NjdmYTc1NTkyOGM0ZGMwMmIxZjg1M2ZkNGY0YjIzYWY1MmRhNTUzMTBjODU1MmQifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjcwZGUxMWI1ZDNiZjEwMDA3ZTY4ZDNjMDY3M2I4ODZkODdiOWQ4NDU3NmQ3MTE3OTc1ZWJlZjNkNWVmYTdiOWQiLCJob3N0bmFtZSI6ImNvcmUtaGVhZGVycy10ZXN0LW93bmVycy1saXZlLnBhZ2VzLmRldiIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA2MjQ0LCJuYmYiOjE3OTMwMDU5NDQsImlhdCI6MTc5MzAwNTk0NCwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IlVTIiwiYXBwX3Nlc3Npb25faGFzaCI6IjZmYzMyYTZlMGM3NjI0ZTRlYmU5MGZmNjIxODVkYTUyNDdmMDI0NWIwNzM1Yzc5YjA5MTI3MTZlY2QwMzcwNDEifQ.k6BVZt2s1JLtyZlP53ZiqAcEFMaY7iWOEXl_pYuB1n8-_zrJWlegHKMAdGtzRThJ8JlDKJVjT7z5cZQfzHayCVWg0qLcHGxQnyiA3NjbJC04TFcSZdRW2pKFBBsip_2CyPBjcTTvIi9p4KCETh-u2DbneFBeUqaP6JPISIIEKFmeu4QIJc_jGtE-Q7VAQzXtgyyfW9GmWhc_9rIDppwalKHMkCsJRscEol9HUeMW3xrH238mrvMXdwXn9ZAxJpoX7OPpWD9thtoWkRfwUx8O8QmWdROibCxNV9Jlqyp7dmN35Mjhlfu_Ojb-OETyxDW49iGLNbZtWYGZ73PDG6PtXA&redirect_url=%2F
  baseline: 302 -> core-headers-test-owners-live.pages.dev
  canary  : 400 -> (none)
https://calendly.cloudflareaccess.com/cdn-cgi/access/login/75789-workflows-service.spaces.dev.calendly-internal.com?kid=a38cb885c4ee42ec9d6f42dab55109decdd6b407d8577fbd0c2731db601a0da2&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjFmYTE5YWY3ZDk5YjNlY2U5ZDNhNTJiOTA0YTk2YmFmODQ5YzRhNjIwMmY3ZDVjMzk1ZTVlOWI4OTkzNWRkMjMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImEzOGNiODg1YzRlZTQyZWM5ZDZmNDJkYWI1NTEwOWRlY2RkNmI0MDdkODU3N2ZiZDBjMjczMWRiNjAxYTBkYTIiLCJob3N0bmFtZSI6Ijc1Nzg5LXdvcmtmbG93cy1zZXJ2aWNlLnNwYWNlcy5kZXYuY2FsZW5kbHktaW50ZXJuYWwuY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDYxMjEsIm5iZiI6MTc5MzAwNTgyMSwiaWF0IjoxNzkzMDA1ODIxLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiQVQiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiMDVjMzkyMzBmODJmYWJkMzgwYTdjM2VkMWFhNTg5NDEwODZhZWU3NzQ3ZTEyYjBhNzFmNGY2ODQ5ODYzMzFjZCJ9.PED3B2V8HhiyTV4ou5rWBIczHILRprMh3WTHwm-NtShbcM8KALW_6O3kXWd7HDKW9_sSgXzVXQUWzWyQisvhjHpUKLm8ZuEuEQIJBBQh5MEe04gyH2ning6sfoaCsMJeX3bvU6jt1F3H6d8hSdvwpNamICbiPDKoTQHTMccE2zopsGJ4wvVY9_Et2HYQM7nzKFX5sHXq278m-mFiJLnpVo6LW1RstJ2v9rP7dfQmtvBP23etMYS5QZqcRY72Ae_BgJgKnDEZ8LbZs9rtmsG5Ny_3974B5MEjlABO4c69CAWCO0OQNMP8WuC3O0jZgLNXRIhp3_2g1T-4Vqx4Tg9HcA&redirect_url=%2F
  baseline: 302 -> 75789-workflows-service.spaces.dev.calendly-internal.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/nc0113-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6Im5jMDExMy1jb250cm9sbGVyLm1vZHdhc2gtaW50LmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA2NTg3LCJuYmYiOjE3OTMwMDYyODcsImlhdCI6MTc5MzAwNjI4NywiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkRFIiwiYXBwX3Nlc3Npb25faGFzaCI6ImQ5ODhjYjAzMjg3N2FiYjU0MDcyZjg1MGUxMTRkNDQ3ODc1ZDI4Y2QxZDZiYjNkOGNhYzJmZmI3NTk3MTI5NzYifQ.aaIbsZ5WCU6bfLrTFXCrh_a222MsJh-pOLIt1WMRciwaLi5j17R6jdPvHwRH-NNI9MYXMwvstnCgdlV3tJc_Ex5rSyayGGNH9PoQcz0bvRxPyoTLi3mVaczRUt96fXLqPVwd2yo8Ak3xsVKZ2v1LvkdU6Gp1I4nUEB3flXXgw-gtsAvthz3iHYd6-G8rEMtsRXNOKsiXsBJMMRXozvyKii3g1EQqM7429FXaBMDX1JlQzYb5eMBu7L7OmVUedDd8cqnzdKxFmkoKoNY0hlG0au6nQEL6FWDy4ytRvoMGiuvjfZE2EslvGGceqYXxjihUQbDGf_J3qC6S-kYov3rBug&redirect_url=%2F
  baseline: 302 -> nc0113-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/fl0204-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6ImZsMDIwNC1jb250cm9sbGVyLm1vZHdhc2gtaW50LmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA4MDMyLCJuYmYiOjE3OTMwMDc3MzIsImlhdCI6MTc5MzAwNzczMiwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IlVTIiwiYXBwX3Nlc3Npb25faGFzaCI6IjViZmI3YWYxNTE1M2M4M2Q1MjY5YTJmNzQ4MGY4ZTA2NjdkMzhiYjhkZGUzYzYyMmY0ZWM3OTM4MzFmM2I3ZTAifQ.PXUT8K2GzRV3tjSfgupU75sXxVbmrcNBF6B7g-N92HJitIljcb7MuW_gdbJ7sQyACoghqto9AX-oo6UEvq5PKFW3Y74SqEe_Gs7h4TY5rW1TJDGFXn9BDh4lgqtceXBEWhh-RgaOA2aQoQ2f1qohvJG1hLXQbIoD1z4u9U2CZ1xisDMdcWeXcLxx-VdgZpGfTaJ5BX0pi1Kpb0PD-pw3qiEkP1c9Ev3kJ9M9hdKaO4WU3PJOOe_GU3nGSK9ar-f22sy8dqDtJ-s5uZe86ew54nksS9pVenlDE83S-ha1uGKvr6EDFbqRt2WNsxiAorbTEjoN7A4pgv-1rxAqDes_Cg&redirect_url=%2F
  baseline: 302 -> fl0204-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-fl0210-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1mbDAyMTAtY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjE4MywibmJmIjoxNzkzMDA1ODgzLCJpYXQiOjE3OTMwMDU4ODMsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJTRSIsImFwcF9zZXNzaW9uX2hhc2giOiJkMGI3Njg1MTY4MjllNzczNjk2YmYyYjE4MDgwYjgwZjY5NGQ3MjUyNzdjMjM2MWZmNjQ2NTNjMWNjM2ZhZjhjIn0.YVh_WErNTk3MEfQQByGCh0xeoggf-H1r5LBeaznFwpx-2WYByIKpxJNdLTYuC5EvMXY-ySxtj86vBlqhzpiJSfwarIjp-v5115Qa3JgkqNyq_tDmtnH8p_Gaf3uayV2mk7nhu69pOf8uCeVjqibgLceHfSIphQ4npWqlqs0C5Wau1KxSeHCzQh49eCwcYbdXlfZS2MOQiWorAaSocX0Z4aJeg0o45IQDkzQQ4Dr-oi-5vrRseWazobiusLgPKICgMVQpDym3nq6PsNasjItVLhiCediRDZfWyposQgS2vGK4cjXZBLfTIVmi9cjprEJySobPA5HH7NB9vEvjMa39Tw&redirect_url=%2F
  baseline: 302 -> ssh-fl0210-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/oh0708-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6Im9oMDcwOC1jb250cm9sbGVyLm1vZHdhc2gtaW50LmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA2OTE1LCJuYmYiOjE3OTMwMDY2MTUsImlhdCI6MTc5MzAwNjYxNSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkFUIiwiYXBwX3Nlc3Npb25faGFzaCI6ImI3MDJkMjcyNDljYzcyYTMwOTQ5MmY0MzY2NmJjYzhlOGQ5MGFjMzAwMTZiMjVmZWY2NGIzZjM2N2M3ZTc1YjYifQ.easCJNxHYOTGapXfnUEXFY_JFGHNPZPLV9Xiu6SCmDVm33fvJRauUJDwk4AWywnOYSwt-q59IfqrNWXliOHrDkCcsyPQ9yf1JA_GGHTn_XrvhShMaAEotOQmoWkKhyV57LeVi-o4YsSuL3S8o6C7f_JARRnnE4jes-Gi03cg4smPfP29FkJhgt1_Y-1Is6SaxUb3b6UEszdxX6hRqjpSinZ8RYSis7zLETuBqSNuwI5ELqDVrFsnU4D_CDUqmS0pah2cxrjC8q96gQo5cjPXDzjT9FVlYa8edKZD45R8dyHBtFUQIDR1e40zMlP8pI3AeVVPGfrMvtlM8VmyVySeAw&redirect_url=%2F
  baseline: 302 -> oh0708-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/sc0302-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNjMDMwMi1jb250cm9sbGVyLm1vZHdhc2gtaW50LmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA3NDY1LCJuYmYiOjE3OTMwMDcxNjUsImlhdCI6MTc5MzAwNzE2NSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkRFIiwiYXBwX3Nlc3Npb25faGFzaCI6ImVjM2UzYmI5YmMxMzFmODRjYTg2MjNmMmM2NjRlYzI5MmE5NTE2ODkxMDVlY2M3YzAwYzQzOWY5N2NlOGI2OWUifQ.WkntPpquEwvkraDPOYeyl_PWbWC_rwEwg0v3tzjgT-8Iz5E2GffToTX31713HXBg3Gr2pXGgh3wF8UYW9x4bmuypVGj42eUeAJ6ZQK1wOZyURVxwFJL-TBzMjB9EDt8hSmyZLC16hJRS6MAkb6dJ_PNtuwcrkKRA9WKopM1K7Gxm_mQ9FX-KrqpnPlZWeNvxrzB9AsuGofglXEx2hTtItMs8Y0wLet4i1uJkfI9_BoRVbHAjoS5QEeiLQ2ceb5i5k1S6A2i1_Tz1KE9g4r3KqtLHUsnIWRAguQCHoBp3cVwghockpz2ngUiYGy8pmarOYOv_e32WAAe-_jpwO91M-w&redirect_url=%2F
  baseline: 302 -> sc0302-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/oh0701-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6Im9oMDcwMS1jb250cm9sbGVyLm1vZHdhc2gtaW50LmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA2MzIzLCJuYmYiOjE3OTMwMDYwMjMsImlhdCI6MTc5MzAwNjAyMywiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IlVTIiwiYXBwX3Nlc3Npb25faGFzaCI6IjY1YWZkMDQ2NGJmZjAyZjBlMjZjMWVlZDIxOTVlNTVkN2M2YThiOGExYzE2M2Q3YWUzN2M2YThkMWJkMDNlMDYifQ.a_GBreFxcInHTvLM8Uc9CCJAwnoQTBoLEQXkttkV90t8Nl3f-ywb8Zz4lL1i4WxoJqdEMtSUguHD6noV3kJ98xb5-qMygr0OyGc22xm5B9r1nN2IydljpZCxIhsxzFosnxGOZ3f0TADOyAi43JE3K9HKPSd2RzfKRqexfRdz90FLFBZbRUdaQaZmedZc72GcS9zkWm3jBAA8ltD7elf1s6UMW3OK6nFlqtZp-7tiYvnAqF7xJZYJtgH9d_IAjguq7n-gub0X49km-2h0eN9cCpD0kX_dvnmxzhMW9ZjFhfMCrZyF75bon7OAdxzWECtjravCwbJAXfw3nTP2bNi1oQ&redirect_url=%2F
  baseline: 302 -> oh0701-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-fl0222-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1mbDAyMjItY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNzM2OSwibmJmIjoxNzkzMDA3MDY5LCJpYXQiOjE3OTMwMDcwNjksImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJmN2JjY2UxMDlkYzYxN2NlNWI4MjUwODk4OGY3ZDE4YWUzYTUxOGM4NGI3Zjg4MGQ3NGRkMzNhMDliOWYyYjM1In0.lY5Cv-NX6pF4FUudJqS7tkA-C2ypPEJoebQ3jJ2jyN9v3TJPqQXXhjN6lt1uyA_ewxhHxkQ5QjFr9l79FoeG89V8vn07X1lcmvAvSfSVbP6DpCwwSj9RBmgy5a1LtXC-NDHySJJmZRt1oit904xKavsJJtcZcFuzdMozr9WXH704RX8k6VtIDze8h6OL9156IOKL9M9l-NO8tCZH9panB3GKqS2Rt2jNp4RxuuloGVjkE9DzRa7dBDXFYP0xfOlzm08BHSbLhphRa4GmmOsW_--M056usF-2eCrzHbG0N-bCAePRcpJ8s3Sl-EieN4u9B0sJo2_NgJPqrSWZ-qRAKQ&redirect_url=%2F
  baseline: 302 -> ssh-fl0222-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-nc0113-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1uYzAxMTMtY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjU2NSwibmJmIjoxNzkzMDA2MjY1LCJpYXQiOjE3OTMwMDYyNjUsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJQTCIsImFwcF9zZXNzaW9uX2hhc2giOiJhZDUxNzUxOTdiOWUyM2I2ZTM2NWY4M2UzN2RmNmM2NTJlMzU5ODc0NzQ0NDkzNDg5YzIxNjI3ZTNhM2VlZTI5In0.SM9gW8tG7BXRuyxvY480u68XtNdf6nc6waE8oD88MKPimHZsgnNynWUHeZPGSWkXBtnbxg_NDFdb1riotUhDBjRxf0RhX-l828TddQXWtJyjyP3WOXEqJ9btnBdWGv8q3qN62V_kPRyCEETc-txx3qZyvOQ9FOjRmKPGSbQFj-X4nTbPl9bbMEBIGA5bh_-sXmQd-tL2MxGgkgnnChU8Ye5VPoDd8P8K0xMiLTzqydK6H6x7NDUI6Kag3lh4taYfXz0itVXoh0J-UWejtwRH6tWIFgJiht-FwfDfxHtY3MpMcxFQhoD4B9LNdmYGhFrLIeoTbAnSBfONHqTA9puCJQ&redirect_url=%2F
  baseline: 302 -> ssh-nc0113-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-oh0701-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1vaDA3MDEtY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjg4NSwibmJmIjoxNzkzMDA2NTg1LCJpYXQiOjE3OTMwMDY1ODUsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDSCIsImFwcF9zZXNzaW9uX2hhc2giOiIxNGM5MjhiMWNlZjE2YWE4ZWU3OGM1ZDkwZDBjNzI1ZmI4MTFmMzAxMDYxOGQ4OWE5YjAwMzdmYmZjNzQ0NWQxIn0.eBGZQFxbFhD9-Kg_qdFW0S3cU8S1jV4I8aFpPPnDGT02VGbsoRkIkLUESnbhYBrZZlzFY-RFg4RlpqIH1AHidmwN87AYSYxL8Kj5RvMPJmO9nBLFMnBF9ukZIDWscRssyJsww95213LRLk25LQAWQPSo93667veT_8gUXvIOMBVZ1sBpBMirlF1VWYyr4wG0U-E3ycrkq-QaWUFA_dPN1CVFaS3KfMg8kSQhP8p1RQWPcsw8NTNyFPTyXGBYRo00SMDCMpSch4R6luKQRHkLyKMtuwIEilCD6ll2JpO6QH21D-YTndZ7cuOt4th9L5UMx9TdRS8KzkoGZL9p3S8J7A&redirect_url=%2F
  baseline: 302 -> ssh-oh0701-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-oh0713-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1vaDA3MTMtY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODk5NSwibmJmIjoxNzkzMDA4Njk1LCJpYXQiOjE3OTMwMDg2OTUsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDSCIsImFwcF9zZXNzaW9uX2hhc2giOiI3NmU5ZjAzMDk5NjQ1NGI2NTA0ZDdiOTJmZmYyNjkzNWIxMjBhYzUwMzE5YWY3NTkzODViNTA4NDJiNmY1OTI2In0.gnDJLGP8UoF461qLjWcojXkkA_9THoAyDSWpqFTi796MJ9Yi54qbMCeJcn-fqpVAZCVfJLjjAKwthat5-7AnKIcCsqU4IYTRMtfs9ttvnPEB8V7cf19vjLnqVCVbXRYHpTZKaf2GbvwrLWnzNVPRlW2EAWOzTQ-65MCZuEU7tDwYInULdSWW10yjr5gkQzl7SSq-SP9HKCpvoJEHYLU7IUOQ1ioMD-j4r0Qgp89OVRTSbcIQMqEL0TNLLP0yc8gJJxkXTHw2LcPaRvePuvCL7-swQhaLPmsbMFLvrr67Wb8JKyhuS0kit7Wqvz4R2Plrd1UIMrk9FL-IAtCijgnX0g&redirect_url=%2F
  baseline: 302 -> ssh-oh0713-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-oh0708-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1vaDA3MDgtY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNzQzMSwibmJmIjoxNzkzMDA3MTMxLCJpYXQiOjE3OTMwMDcxMzEsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJkODNkZWRmNjQxYWQ4MDM4YjdlZDQzMGE4OTVlNjY3MWFiMGFlMGMyOWI0ZmM0ZGI1MWY2MmQ0NDYzYTZiMjBlIn0.lqbz2HZULBESmyhmsiF5DrnDf6BoClwmQrWXN1VSyiSvCwF9KmTI8ivoL6A8-tti_YhZGZBSsxjhMyfSY8e7caAOMK-o7PsAorMZTDyztjOvXjH-Dxs_TdyNOi7WY1ro1MPr9veir1aNOUTBzTKtc_rfcCTGeU4fxLKiCb2m4qFfCUO_6-MhVv1QIeJoQDXa03wz-LLWo3RA7N6oVnSOM5w3ZyVmYAPfLetgU32SNLCSY9Xf7VGp6ExYwgaJibCcZkajYuc27jlf0NixU1TtNQl7AGJ3BsOhr7e7SBq7sVfcw29VzJT4Xs1itkamERAwspogueVx2zJ7m0mNvULClw&redirect_url=%2F
  baseline: 302 -> ssh-oh0708-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-sc0307-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1zYzAzMDctY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODU3MiwibmJmIjoxNzkzMDA4MjcyLCJpYXQiOjE3OTMwMDgyNzIsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJBVCIsImFwcF9zZXNzaW9uX2hhc2giOiI4OTk2MTQ3NjMxZmY2N2JjZDRiNTljNTM3ZTI0NWY5OTA4MjI0MGYxZTQ0MjY0MjI2NDgzNjA2NGQ3NmVlMzNmIn0.Ud7ZUPZoYhsGYmRRvVErpKvnbAkbgamuCsxauKt3I_CYtLin-uzrVIwIJRo6JHLn4F6vHWVNskMMW7cGvCHTCe_Rbbong6LpeeZst9SCAe0X4vdNP1LzDxHGmoFeUpoT95WWQEHq7Tg0c7cyNS7AVK4ljesfEIcpYYxlDlK7Yo6lBqxGrFQuq5liJy0XTxFHMmSgkpQ_LgY_WxwWS9cEKalFqZfcI9LvE4tDHKYXIcjC-CC3rbkNppfcgukJ0RvbIDjaWmjn5QiVfLZssmJDclpUFXdACbMDbFN9O7450OxuyBdmHQHAtY7_ErAlgME5GjSMxuOoy8uA8wYxgOzkOQ&redirect_url=%2F
  baseline: 302 -> ssh-sc0307-controller.modwash-int.com
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-pa0501-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1wYTA1MDEtY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjU3OCwibmJmIjoxNzkzMDA2Mjc4LCJpYXQiOjE3OTMwMDYyNzgsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJiODViY2I1ZTdlNTc2ZGFlZTI3Y2JjN2Y2NWM0MzFhODA2NDRkMmE0MzY5Mjk3NTQ3MDAxNzE5MDAxNGVlODI3In0.jezJEcOzVsgkte4r6huVpHimFEb8GEU7lJBrGQN8nQa7--60x45IjEJM6h90dbD56-g93YYaxVqu9zHq2AWfpUHTnDvPlB-44VF15-DY2GL61AhpqC_uedUl7usCmz2a64Wpf6rWaMLqW38P0nwA_-9jXagS8-EYSW1q5c8IdQe7h9A_ciLcbg38QYM8eskiNCWsML_IR-PYeWWX4ZcNdM1FUDxpHtm3oArxUpyGyVK0Uz1uCyGeKY70o-1CpRE38nlHNYqD2wulK_yzwHt8qPsVRFs6dnuRR0EPebQqItFOb4szWHgsYKcupSgZzzz7r3M3gcHgHs-uPUPAVeZBlA&redirect_url=%2F
  baseline: 302 -> ssh-pa0501-controller.modwash-int.com
  canary  : 400 -> (none)
https://cencosudxio.cloudflareaccess.com/cdn-cgi/access/login/task-collector-metrics-recover-api-staging.cencosudx.com?kid=942e43af071e1c626bcfa6b47feb414dab6f6abcffa2b572d535f98926175dc3&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImM4NTQ3OTZmMjNkM2Q3MjQyNWJmZTU0Zjg4Yjc0YWE2MmJiZGQxZTZlZmJiNmVhMDI5YTlhMDUwMzdiZTY1MDMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijk0MmU0M2FmMDcxZTFjNjI2YmNmYTZiNDdmZWI0MTRkYWI2ZjZhYmNmZmEyYjU3MmQ1MzVmOTg5MjYxNzVkYzMiLCJob3N0bmFtZSI6InRhc2stY29sbGVjdG9yLW1ldHJpY3MtcmVjb3Zlci1hcGktc3RhZ2luZy5jZW5jb3N1ZHguY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDcxNjYsIm5iZiI6MTc5MzAwNjg2NiwiaWF0IjoxNzkzMDA2ODY2LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiZTA4MDY4NGY2ODQ0YjkzMTAyYjhiN2Y4YzIxMjczNTdjOTQ1NDMwZDljYTBkM2JkYzljMGQ4YjFkZjI1ZmNjYyJ9.Dil4RFvLiYbvXIC22w6CW60x-CE32dSmd9OISOZ47tVFr1Meu9_7x0NgBuEFrxI1uTFzNdb_ie8ywytcPajaDM3woeiGjRPu1GNy0Dqiyg_no3iyqCTEiwH22gLhHDOs5DPGGLjrrFXca3s-QVE753yOT1Id6uhSB8pF3DZ0MK4FLOt16er8RKv2kmjdIM8aSnjnVGdw8L--73e2lCCfdJ67czmDM7eRCEuLCC--i_6CwByUy0p8nBRwWoYONRNWjZ6mF9764pk8U45nM-bzTRax75WquBK3eizJ7ogzty-ox6gKt7P-hBvcSTLq111VyfMZmezJNKoVxPL1eHFpJw&redirect_url=%2F
  baseline: 302 -> task-collector-metrics-recover-api-staging.cencosudx.com
  canary  : 400 -> (none)
https://cencosudxio.cloudflareaccess.com/cdn-cgi/access/login/connect-cl-promotion-services-api-staging.cencosudx.com?kid=942e43af071e1c626bcfa6b47feb414dab6f6abcffa2b572d535f98926175dc3&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImM4NTQ3OTZmMjNkM2Q3MjQyNWJmZTU0Zjg4Yjc0YWE2MmJiZGQxZTZlZmJiNmVhMDI5YTlhMDUwMzdiZTY1MDMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijk0MmU0M2FmMDcxZTFjNjI2YmNmYTZiNDdmZWI0MTRkYWI2ZjZhYmNmZmEyYjU3MmQ1MzVmOTg5MjYxNzVkYzMiLCJob3N0bmFtZSI6ImNvbm5lY3QtY2wtcHJvbW90aW9uLXNlcnZpY2VzLWFwaS1zdGFnaW5nLmNlbmNvc3VkeC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNzkzNywibmJmIjoxNzkzMDA3NjM3LCJpYXQiOjE3OTMwMDc2MzcsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJJTCIsImFwcF9zZXNzaW9uX2hhc2giOiJhMTBiY2Y2MGIyZDMxNjZhZjY3NmM2YmZiZTAzNmUxNDlmMzg1YTE4ZGMwMmE5ZjU4ODA3MTI0ZjJhZmQxM2M3In0.Y772O0ISZ-juXV-pfgKVVX8R9s8L2ANsHc6Q8LTKS9QXxb7fDB4rTdOhyQgxf84fZEv16HsZNq8wTUKY3iFSqWo3NmBAzEAYsEquk2eKTTAuD2x5u0DACYJJ0O7hendc0NLMeKT6FJKVOepr_bp0zZ-vT9m67iGf6D5dT6Dqf7zeb4H6SWSzpGdV55hq10lepP2eqBV2pkVhvlKPu6EV8iKW1vcMKoJ6xDJRudgvGuKGp2clfDe2dW8Fy6XqFtcAGexAIGlJ8i2ECBuQYl-DOkPu1BHZD0ocF2AWSG8kD8E-RRUsObnNt6lGyBZH7RcHE_LFlOCqg9uwgd7u17ZXTA&redirect_url=%2F
  baseline: 302 -> connect-cl-promotion-services-api-staging.cencosudx.com
  canary  : 400 -> (none)
https://cencosudxio.cloudflareaccess.com/cdn-cgi/access/login/yumi-posters-api-api-staging.cencosudx.com?kid=942e43af071e1c626bcfa6b47feb414dab6f6abcffa2b572d535f98926175dc3&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImM4NTQ3OTZmMjNkM2Q3MjQyNWJmZTU0Zjg4Yjc0YWE2MmJiZGQxZTZlZmJiNmVhMDI5YTlhMDUwMzdiZTY1MDMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijk0MmU0M2FmMDcxZTFjNjI2YmNmYTZiNDdmZWI0MTRkYWI2ZjZhYmNmZmEyYjU3MmQ1MzVmOTg5MjYxNzVkYzMiLCJob3N0bmFtZSI6Inl1bWktcG9zdGVycy1hcGktYXBpLXN0YWdpbmcuY2VuY29zdWR4LmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA3Mjk1LCJuYmYiOjE3OTMwMDY5OTUsImlhdCI6MTc5MzAwNjk5NSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IlBMIiwiYXBwX3Nlc3Npb25faGFzaCI6ImExN2IzMzE2ZDMyMWIxMTgyODhlMjIyNGQyNjYzNDk0YTFkMGJkOTRiN2Y3YWI5MmM5ZDU2ODBjYzMzNDNiYmYifQ.FOaD23kViH5MKnnEvbeTi7f6vCxdxF8Q0WDr0t9GNUFj8--zUTlBGnMLMKYZUPwGq4yRBJjNvxw7Vd9BIkuNfepT-bsx97w8pVoyjrmoh5YKQ1U0pK-PWcGMp1mkqXRg-F6iOHjtCThD2QSuwhSe8wX7IHF-BiTax-LV4l-D5HQ5eDo1ZP6FBMwkCBigazQGJUTfaqnYfphrsu2DKdTLf7WXDDf1oYYp-92geULOTkFY-06sjqeaFaST2zXh2qZdkKvJf09AKvjTW485q71n9KJPc49OByXunguPoa55GkBS1B6STj7x06WU_JaqVNT2TkCVsabgogr_1SGxBqubyQ&redirect_url=%2F
  baseline: 302 -> yumi-posters-api-api-staging.cencosudx.com
  canary  : 400 -> (none)
https://cencosudxio.cloudflareaccess.com/cdn-cgi/access/login/argentina-arcus-bastion-staging.cencosudx.com?kid=2330a5ba27b31a66a589c8277d481c03efabacc8fdecd1ecd94cc7f3465fd4e9&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImM4NTQ3OTZmMjNkM2Q3MjQyNWJmZTU0Zjg4Yjc0YWE2MmJiZGQxZTZlZmJiNmVhMDI5YTlhMDUwMzdiZTY1MDMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjIzMzBhNWJhMjdiMzFhNjZhNTg5YzgyNzdkNDgxYzAzZWZhYmFjYzhmZGVjZDFlY2Q5NGNjN2YzNDY1ZmQ0ZTkiLCJob3N0bmFtZSI6ImFyZ2VudGluYS1hcmN1cy1iYXN0aW9uLXN0YWdpbmcuY2VuY29zdWR4LmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA4MDU4LCJuYmYiOjE3OTMwMDc3NTgsImlhdCI6MTc5MzAwNzc1OCwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkRFIiwiYXBwX3Nlc3Npb25faGFzaCI6IjUwODk3OTVkMTIxOGNhNWFlYTRmZmZjNzdhZDYwOTcxNzMyOGQzOTdkYTBlODQwOGNjMDkxZGI2YjA1NGZiN2MifQ.rr-smSOuT001f4QcgYi60_poNU427iMN1zKBzWR1gYW7GACDhREygU5BnnOJcnaTtIyz-QCh-nMvOos3ZvaZ72XAThavM259mLOSYvHh6bvvaIz7I5KtYpGuhI5YulFW17JD6_gI_bkYFBOtNcO0r9_s5eFt0nI_WQSr-0q8L_BtewH0b_2ahqG6RwPUKdxrCw2iAa_tM_rcNfLO3PmYmdTwAF_qgDRJdRF70YiEOYYI7fNwyRD4wQiA_KHGNiTRZxcTzkFWvm9Jwrvw8Nb7DV6p4m7HhUdHwZXfRLVoetNgdJXPGNI5p-ZCDyLgj-RxR-201PS8ABlyJI7p-QlGqQ&redirect_url=%2F
  baseline: 302 -> argentina-arcus-bastion-staging.cencosudx.com
  canary  : 400 -> (none)
https://certifyiq.cloudflareaccess.com/cdn-cgi/access/login/internal.certifyiq.com?kid=adb885151653b04141d2a5f95370786d48763cf9e156dec891426464232518b0&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjExMTgwNjQzNTk4MzgxNTFjMDUxNTc1NTQ4NmNlMTJkNmZjMmEzMWU4YzcxYWEwMDk5NGVjNTBmZTgyYmI1NDMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImFkYjg4NTE1MTY1M2IwNDE0MWQyYTVmOTUzNzA3ODZkNDg3NjNjZjllMTU2ZGVjODkxNDI2NDY0MjMyNTE4YjAiLCJob3N0bmFtZSI6ImludGVybmFsLmNlcnRpZnlpcS5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODUwMSwibmJmIjoxNzkzMDA4MjAxLCJpYXQiOjE3OTMwMDgyMDEsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDSCIsImFwcF9zZXNzaW9uX2hhc2giOiI1Yzk5YjA1NDMxNzQwODcyNDVmNzczNjY2NmRmOWI4ZTg3YTY0ZjBlMzc5MDE4ZDI4NmYyMzNmNWJlODcyYWY5In0.Etc2nvOsjz9RGSwBH-GWXCFatSzUL4ocsheKlRsgQtrYEUAqvLVlYXcnXxpkz7A6BRon-bzV3H8n_qYixNTrMHC1u990RG0E6tHbR6ALuQLM5NzMOwaBgIM9bfLPVtDHzwRQx0ShUvzTV6pI_ux6WCX1uUCYkezCaghAp1pcOe2Xr5fJtVs0gI81ugfl-HnAbvXf6-X8FUooJAGmHa1LQX9zgBFlBHZux8R93Guh5VHHvr1S2CmCSCtNJWtF6RHr2X90a1keIXa0mOj4zM_nnjiD0JCoi8bPrIHwVHMgiu6p9OUqapMrzwyEGTb0_GRlkRBNykmlUn4Kf9VyAoKIRg&redirect_url=%2F
  baseline: 302 -> internal.certifyiq.com
  canary  : 400 -> (none)
https://clickfixed.cloudflareaccess.com/cdn-cgi/access/login/clickfixed.uk?kid=5bb7ac1956f90b79a5023716c68d3ddb2aec0fae98440159015f1aca44a762bf&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjQ3NmQ0ZDE2MmIyZTllNTE3NjU2MTkwYWRjZTIyOGI2MDdiMTE5ZTRkNDdmZDI2NTZiMjQ1NTVjYmJhZjlkNjAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjViYjdhYzE5NTZmOTBiNzlhNTAyMzcxNmM2OGQzZGRiMmFlYzBmYWU5ODQ0MDE1OTAxNWYxYWNhNDRhNzYyYmYiLCJob3N0bmFtZSI6ImNsaWNrZml4ZWQudWsiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjQ1NCwibmJmIjoxNzkzMDA2MTU0LCJpYXQiOjE3OTMwMDYxNTQsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiI5Mjg0OTVmNGRiYzcyYjlhM2E0ZmJjYmIzZWQ0NzExZWQ0OGE2NTcxZGYxNDYyOWYwZWU0MGYyZWUyOWU0NGNjIn0.moK608OIxZe9L_y0sAJSwoindl6Twwom8Xb500qhH3-c8W1gfdi_pfKspPAJQf0dgJI_HAk7j3uXmod1ZdwaMPUvAf50_VZilnd871Pm_ctsD9hvuQYCHop6RbkD3Nb5qgimclS6g-hZJJQLf9-TW3amXBPXGG29SHN5YNRp59IAkwo13dlBcHpqeIxrazmQTYhkpSKe8mVawyaw6UscGchnCPyAQvxRgIFoJWuZiDs6H_afCUpRyJDW02kyoZ8MtdkgXHAB3sr63CNP2EHY2MM4cfvjOQA2FUTuYQpspxuDJA6C3RuF_muePoEMWnkOeXaOCuHkT111Av4Cjfug4g&redirect_url=%2F
  baseline: 302 -> clickfixed.uk
  canary  : 400 -> (none)
https://dbllc.cloudflareaccess.com/cdn-cgi/access/login/cloudflarewindmill.dentistrybrandsllc.com?kid=b335ac67f81535ecc9ad21e5e2df9efde80e022b28e233fbc32187ed0691bea7&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImVhYTg5YTE2OTMzMTQ1M2Y4YTE4ZTdiOTA3ODhkYzRkMmU4ZjBjOWIyOWVlN2E5MmVkNDU3OTcxZmU4NDUxYTEifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImIzMzVhYzY3ZjgxNTM1ZWNjOWFkMjFlNWUyZGY5ZWZkZTgwZTAyMmIyOGUyMzNmYmMzMjE4N2VkMDY5MWJlYTciLCJob3N0bmFtZSI6ImNsb3VkZmxhcmV3aW5kbWlsbC5kZW50aXN0cnlicmFuZHNsbGMuY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDY3MTksIm5iZiI6MTc5MzAwNjQxOSwiaWF0IjoxNzkzMDA2NDE5LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiVVMiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiNjQ3YzE1NmY4NWQ3NDI0OGQwODIzZGFhYTRiYTgwODM1ZWY5NGE1NzM0Zjk2MDg0ZTA0YTFlNjcyYTAwMzAwNSJ9.fNyAHO-FkHflDnDv5jeIsC4tccmLYY06XfoTwNtwXQv4X3qsQkuiTKIv8VFRte6dR4QbAiyNLtBJIyipapwsDIARwFc78IqXkUBolZytX0dQ0eojVNb-HW33Ys9VsZ0sWewf3ThweGTLRpYEb3nPI6eIzTRYacTGur0auJMcYDUzja5smnUQ0LZ3HZHrPhZ9M9RtfymEMXC4aYhYg7ho3WwnqCut0ddecOF54jQXDBPRD43hEQ95yFLCfwBDNG-OO4iWIkbkfcagSqf1QhA81GxPbMGiRXoz0pDITK9yazL0MVI0sVXBlM3_enaG_wUnsJBcZbpJ3aXMjCHmB2SgdQ&redirect_url=%2F
  baseline: 302 -> cloudflarewindmill.dentistrybrandsllc.com
  canary  : 400 -> (none)
https://ctiark.cloudflareaccess.com/cdn-cgi/access/login/gateway-ai.ctiark.net?kid=8b92af05b22caf1fe009799fad397ffef5b1fb892fd8f5737eb03c03f9a3021f&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIwOGJlMWZlMjAwOTA0NzZiZDQ2MDJiMjBlNTI3MzEwYmM1NThiY2Q2NzA1MmM3NDk2MzM5NDcwY2E3MjQ0ODAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjhiOTJhZjA1YjIyY2FmMWZlMDA5Nzk5ZmFkMzk3ZmZlZjViMWZiODkyZmQ4ZjU3MzdlYjAzYzAzZjlhMzAyMWYiLCJob3N0bmFtZSI6ImdhdGV3YXktYWkuY3RpYXJrLm5ldCIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA2NDMyLCJuYmYiOjE3OTMwMDYxMzIsImlhdCI6MTc5MzAwNjEzMiwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IklMIiwiYXBwX3Nlc3Npb25faGFzaCI6IjA1OGVmYTFlOTFjOTZkNDM2Y2M5YWM5NTE3N2JiYTg5YmQyYzJmYmM4ODcwNWYxNGFkOTU1NTBkOTIzNDgyMWYifQ.rWxddAwToyXdbAZIPNPze9N5MWJEahyy6iMZhU9Tdw6WVMklTv6rvbmL73fSGQ6nHrvpd2ySNdE2-aIeVdfSB6BsLud9BFz3db6WlrZHaVxgkpubEZn7ttZMHkuTg28T9iEjIeizxMyCP7Ii0u_bN2x2Y04qxrg2SFplHeSWf2xf_El4pnU3OKorJY-kNFQenq-gsqOMvRb6IiN5It0Bxzi5j0qUCf50WGQEQql304eW5W00qKLdvdGxGL2lUXvvdginhgVnZbbB-WAlBIviVYpiYIfuVb6LDoex4CG6YA6bxy-mzavwtZLG8m8YdU8-jmhfzNeRK8nJnwWzv2QjTw&redirect_url=%2F
  baseline: 302 -> gateway-ai.ctiark.net
  canary  : 400 -> (none)
https://celloluano.cloudflareaccess.com/cdn-cgi/access/login/ssh-oh0714-controller.modwash-int.com?kid=3719161614cc73bb9b634cb1d6dc6a8c9b8737decc16f58369683e9b3541bcd8&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ4MjU3ZDc1OGYyYjZkNjA4ZjgzZjkzYTE1Nzk2MDhkMGVkYjBhOTI1YzQ2OTU5MmVkODc4MzVjYzI4ZTdkYjcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM3MTkxNjE2MTRjYzczYmI5YjYzNGNiMWQ2ZGM2YThjOWI4NzM3ZGVjYzE2ZjU4MzY5NjgzZTliMzU0MWJjZDgiLCJob3N0bmFtZSI6InNzaC1vaDA3MTQtY29udHJvbGxlci5tb2R3YXNoLWludC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNzE0MiwibmJmIjoxNzkzMDA2ODQyLCJpYXQiOjE3OTMwMDY4NDIsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJiYzVhODcyZGUzYWJjMWFhOTM2NDJmM2ZiMTcyOGY5MWMyNzI4YTIxY2U5ZDQ5NjM5OTcxZTIzZTIwM2U5YzFlIn0.PA4Tk0yqt5JPR2dT_k3znF_ljwcefCS_yIEDG44CxMdw2xaw-T7p6e_43uKjYof0NjzTkESLtpuSMqPl1xQw0sjpDHPnkL_zr3xYwQnWSXIfAhCKFa-WSWSLAlA5xt8bK4ilDdOhETRcs3DDBjv-tlLx1oPPF1W3SCmaIyX6M6PJmHAYUh5Ye-srnG2nDzJg62fYxTGpMOHF6DmxG8HPcGf7gJP3W0_ObTsYPNL1lbp1GgeB6s9s9JUF_8L1mtpFqC_LFlTxvYvKGirx7Zk7Bzt8XvA22ad3cEDUoghMRkTZ_N7e92uoYZMgLtt87Bepe-_w46tPC7X1gaD7tcz5OA&redirect_url=%2F
  baseline: 302 -> ssh-oh0714-controller.modwash-int.com
  canary  : 400 -> (none)
https://elsewhereindex.cloudflareaccess.com/cdn-cgi/access/login/control.elsewhereindex.com?kid=a8c1a784597904e6a82abc8dab229e2bc2f61f3b37a1a6b397f86b9ee98401ad&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBkNWFhMWMxNzg1Y2M2YzgyZjc1OTJmNTQ4ZGE2NDAzZjRlMGNhY2ExZWQ0OGU2YmVjYjc0ZjRiOWNjZWUwYmQifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImE4YzFhNzg0NTk3OTA0ZTZhODJhYmM4ZGFiMjI5ZTJiYzJmNjFmM2IzN2ExYTZiMzk3Zjg2YjllZTk4NDAxYWQiLCJob3N0bmFtZSI6ImNvbnRyb2wuZWxzZXdoZXJlaW5kZXguY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDc2NjMsIm5iZiI6MTc5MzAwNzM2MywiaWF0IjoxNzkzMDA3MzYzLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiVVMiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiNmUwZDRlZDM0YjAxYjRjY2MxNWU4ZmIxMWI4Yzc2MTFhODZkZGMxZWIxY2NkMWNmZjRjNWZmM2JmYjY4YTdjYiJ9.Spgs7YNebRXsoEAuDOiy0YvxJAbE_mmb4gU-bEg0s2BpE1-wUjUhR49wqz2Ir8F5SfR_2FKz_sueIxeNkY3yhhnBiF_fC3-FBvrAWai-BN3C8Rtsh_4JtBeTSY_JdlrZiSIah6kVXBdwThkK6Aqy90_Cm6K7hOGRH9fH8uybPiDH8cZ9855AQTeVKSM9AkWvMg2hAcaGBh4rfL9d-0vMbOnfCKLQObt4KbGdYepJjZ_TrQwjmwF4Q_mJSoncIv1zZa4_QnfS9aY4ee0m-yEqDBpMH9ijdc3LBwR5TJ0FHHpNPOpzfz56i28gksNx4gTYiLu0GvsVb-EOAPTN3-kygg&redirect_url=%2F
  baseline: 302 -> control.elsewhereindex.com
  canary  : 400 -> (none)
https://flat-cake-7c01.cloudflareaccess.com/cdn-cgi/access/login/governed-ai-delivery-office-demo.pages.dev?kid=daba1dfa0042af1d2e0e00659c026996748266c46118108a40c6b5a247c7ef89&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjA0YTRmMGQxMTEzMDE5MDQ1MGQ3YThjZmNjYzVjYzVlMGY3ZTUwNzY1OWY3MmYzYWFmYzhhMDA2Mzc1NmJlY2UifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImRhYmExZGZhMDA0MmFmMWQyZTBlMDA2NTljMDI2OTk2NzQ4MjY2YzQ2MTE4MTA4YTQwYzZiNWEyNDdjN2VmODkiLCJob3N0bmFtZSI6ImdvdmVybmVkLWFpLWRlbGl2ZXJ5LW9mZmljZS1kZW1vLnBhZ2VzLmRldiIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA3NzM4LCJuYmYiOjE3OTMwMDc0MzgsImlhdCI6MTc5MzAwNzQzOCwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IlVTIiwiYXBwX3Nlc3Npb25faGFzaCI6IjhkNmI0NzZhZDY4MGIwNDIzMjQ2OGQ1MmE2ZmRkM2FhYjc4Y2EzZmU3ZjZiYTgxMjI0MjI5ZjUxMTJhMGE0NTkifQ.U8FeNJ_05q9lILdX_iiCfcCjZvS3CUFaLsmEJJYLuD-sS7pGSF3P0uQfNQua4MWB5LV_57amSnIwOaCvWfKz_0Kl7hvaL_EQbCbaqC2Zj7g839S6tGvo8FCBtlvNCgHJYF3HUNcelmwQgkHnooe8FF5qZzKbuVmpQJwvUeHDDitZF08MkXW4OUidfKqg4FyQkYEgl2fmQpk_wejeXquOM8EvzJBBrORBLVQnsRhgj2Carti6nyuteMI0NBjUs6eO8vK6eu5BCdxok7rOwKwRxN3mcjnrFQgq9FACny68X94-um627lSuBNKDgzp0tOpeKTgpJOBwi_0OAmzv8zecxA&redirect_url=%2F
  baseline: 302 -> governed-ai-delivery-office-demo.pages.dev
  canary  : 400 -> (none)
https://flexxiblevdi.cloudflareaccess.com/cdn-cgi/access/login/fws-mcmutual01.flexxiblevdi.com?kid=1c6948fc0ba788cb2ff2d1ec16df8652554682bf79479cfffbe1eb75fd4c3b9b&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjhhMWU3MjA2NGEzYTNjMzk1NGRmNDRjNGFmN2E3NWVjN2M4MDljMTNhNjFkN2Q5NWNkN2M0ZWVhZTExYTY1NWIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjFjNjk0OGZjMGJhNzg4Y2IyZmYyZDFlYzE2ZGY4NjUyNTU0NjgyYmY3OTQ3OWNmZmZiZTFlYjc1ZmQ0YzNiOWIiLCJob3N0bmFtZSI6ImZ3cy1tY211dHVhbDAxLmZsZXh4aWJsZXZkaS5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODAyNiwibmJmIjoxNzkzMDA3NzI2LCJpYXQiOjE3OTMwMDc3MjYsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDSCIsImFwcF9zZXNzaW9uX2hhc2giOiI2MjVmMjI0ZWYzMDM5NmYwZDQzMGRlMmU3Nzc0MDdiYWUzYzY5YTI5Mjk1MmQ3NDkzODVkOGM0ZGExNDlmNTQwIn0.E3bdDuXcbDO4kZExCQvQF5gp_YXr82OS3iShLS9VFnRmx7HmoSW5v2pYJfdCWhPjghOGfoj9WqhzibH1VbwGoHWjeB4bUkDo749GC9aM1HvXESpU7W0b68Iuh9J1bFd2zOkiHwvuWdydZOrYjegEWVo7ogptxXJAdGokjFs90xJPCF-CZu0f4pBQu24aZ3spRFs6kq-by0SdLyGlDlWnq9b8sRV5e6qCdMlSPTbpnVxoYqrdab6CixX3OWtSQKWpZyvLbawDCHiqb39iS9ZePOQ17aq3RtTboGX10OnkgivBBEC3DmB-jbfsgWOuKwNdy8hEklhiYmQKadb9Jd9RvA&redirect_url=%2F
  baseline: 302 -> fws-mcmutual01.flexxiblevdi.com
  canary  : 400 -> (none)
https://divine-pond-886a.cloudflareaccess.com/cdn-cgi/access/login/clients.changedynamix.com?kid=7bdd6ccfdee7d3ca1b91383c625a83c00fb0fd1e5db3e29c1758c746d91274fb&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImM4Y2UyODRkNTgwODlmYzMzYmUwODlkNDdlNzkxZGZhZThiZDRiYTY2ZDFiOWY4ODExZWUwNDJmZjE1ZDM4MzgifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjdiZGQ2Y2NmZGVlN2QzY2ExYjkxMzgzYzYyNWE4M2MwMGZiMGZkMWU1ZGIzZTI5YzE3NThjNzQ2ZDkxMjc0ZmIiLCJob3N0bmFtZSI6ImNsaWVudHMuY2hhbmdlZHluYW1peC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwOTI1MiwibmJmIjoxNzkzMDA4OTUyLCJpYXQiOjE3OTMwMDg5NTIsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJQVCIsImFwcF9zZXNzaW9uX2hhc2giOiJlZmQwZWU3ZDZhMDk2NjRhMGFmY2M4ZjM2YTYxMGY2NWRhYTcwOGE2YzAxYWExZmY4ZDBmZjA4MTZlZjY5NTI1In0.AS_Ef6bRZl9wC5-xIQTflxAbx-B16z35WTw9fTjW01d9BMvVjlqU21HhCFrKngPwj2jwHvFHYrwQRNjR-HuCgOEmR4TZDmPmB6F5FKCd0Q9snoXnxwmuP1FVAWXhKZ11cbsa3YXZpghpqB2d2QnkAsgjzVA3TvApOGhvRWBtqs8XHAjIbWlv8ouNIavRGtC9zT0jyq7t4tuqg3UkFYLVuZtA78PAkuLGxxNGishtR5-HE_dW8mOszVKRGtWhU6S1EtJBRo3rGXiXOFD2kiOHHFEGcm_6JwnRQlI2hWy57c0_lxbs6MuWsCwefvw7Bh2Xxwtt6ayIm-bFW8P7rQFVdw&redirect_url=%2F
  baseline: 302 -> clients.changedynamix.com
  canary  : 400 -> (none)
https://exeo.cloudflareaccess.com/cdn-cgi/access/login/hermes.exeo.cloud?kid=705c1f02f96ed1f9a1ca1c0fdbd10cb808378b09893d6024ab9bb9c46ac2c9b3&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjQzNTYzYzA2ZmFlMmVmMDAyMGViMWYzMTRmY2E1ZDlmNTExMTQ1NGIyYjRkMTkwNDA1M2Q4OTlkNjNkZjU5MDgifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjcwNWMxZjAyZjk2ZWQxZjlhMWNhMWMwZmRiZDEwY2I4MDgzNzhiMDk4OTNkNjAyNGFiOWJiOWM0NmFjMmM5YjMiLCJob3N0bmFtZSI6Imhlcm1lcy5leGVvLmNsb3VkIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDgzOTgsIm5iZiI6MTc5MzAwODA5OCwiaWF0IjoxNzkzMDA4MDk4LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiMDAxMWQzMWVhMGNkYjNiZDJjMmY1OTg2MTBkNTAxYjIyNjJjODAyYjVhNjJlNzg2NWFkZTczOWU0OTU5YzJkOSJ9.KyBHpFWpDzkEUlXy2BWWaLy4LEBMgw7Kvhwo-UpAh7kLbLFWIZCZ41T1LZoGoYaySL7BA_uCpfvBs0K2K286kicRxGytofNwMq_6JMLrzvbOD99GEJFkOTE4m-DGKpYOf_UQ6mcJat-QjiBLuHGseEI2f5Eeex38ndmnDZJzHVvJjS0RNdK2gMZNtHqZVWJPdfPEjm1-K27V-5Mz_RtS8PCiAruHhqehj7G6tCvPYla8maPeqf3mULlplHvqmUI2Nq6Hc8kf26rRwxpYTYGhP_HzbgFEOksEjY7L5imzpE7rGMDu84YXdxYXmn2QKwXLZVXphJjNErDqUOptC6CFBA&redirect_url=%2F
  baseline: 302 -> hermes.exeo.cloud
  canary  : 400 -> (none)
https://falling-violet-5d53.cloudflareaccess.com/cdn-cgi/access/login/handora.me?kid=d7f4d4f112820db96e910066a250068d27a894a740b4f47c2538abc29452f96a&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijc1NDk5MjZhYjcxZWYwMzY0MzFmNTFkOTc1MjM5MDRjNmZkNzE5Njc5MjE3NzE2NWRiYWQzOTZhZDg1ZTM3MWYifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImQ3ZjRkNGYxMTI4MjBkYjk2ZTkxMDA2NmEyNTAwNjhkMjdhODk0YTc0MGI0ZjQ3YzI1MzhhYmMyOTQ1MmY5NmEiLCJob3N0bmFtZSI6ImhhbmRvcmEubWUiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODI4MCwibmJmIjoxNzkzMDA3OTgwLCJpYXQiOjE3OTMwMDc5ODAsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDSCIsImFwcF9zZXNzaW9uX2hhc2giOiI4OTdmNjZmM2I3YmU4NWEyNjNkNGM0NWMxYWFmNWZmMzViNzdmMjZlNmRjMWZhNzY5NDlkNzJkOTZjODE5ZDhiIn0.j8iNegLg9c9QXWuo7haaDWVfHJSb44SWQSAefHnN-7q2oz2Z6M2wFYVtELFZtDbNJR06EBVOWLS60adBQMV0DMOSVtck3xGax_pPBA9tcjmHzrI0gM14dT2r23W3Ds2S2JYGn3P-PipOIyUU1cFuAP3t2RNr5L2sYloLz9Ukf4nBETHkLa4TGOXP2MtXiwrtAcmy7NzAY_-S4oNWhBa4QA-58EYoEiS8iRqNjchjbLEqTO6aGdeW80awadikR_l2CUVpk0gQuM94ihCUlTTuTwgZopegLabTWRaChUzJhxaq8hCVjXc8_oRBapUwr6LxSruJ1-dVt-EoAPxbVtCBBA&redirect_url=%2F
  baseline: 302 -> handora.me
  canary  : 400 -> (none)
https://foodticket.cloudflareaccess.com/cdn-cgi/access/login/theomuys.restaurant.foodticket.dev?kid=54dd158dbd9cb6625dd75a3c0d9253b53374b58f5ae8b1e203ed7f8fbf917005&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjI2N2QyZWUxYWNjNGU4NmNlMjFkNDI5ZTNjNDY0N2I2Mzc1MmJmOGU3NzM5MWY0YjNmYzQ3NjMyYjZkOTNlYjgifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjU0ZGQxNThkYmQ5Y2I2NjI1ZGQ3NWEzYzBkOTI1M2I1MzM3NGI1OGY1YWU4YjFlMjAzZWQ3ZjhmYmY5MTcwMDUiLCJob3N0bmFtZSI6InRoZW9tdXlzLnJlc3RhdXJhbnQuZm9vZHRpY2tldC5kZXYiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODUyNCwibmJmIjoxNzkzMDA4MjI0LCJpYXQiOjE3OTMwMDgyMjQsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJQVCIsImFwcF9zZXNzaW9uX2hhc2giOiI3Mjk0NGNjYmZhZGZiMTgwNzcxYjRkN2RlZjgwN2U4YjRhMmFiYTJhNDMzZWNjZTE1NGVkNDY5YjFmOGE1YTBkIn0.lAvL_ikIfkIlsRgY2rWzjYoCaIqsEG3PoxP1-oQTeMh5PcFD-fIYnxECrkVuD0gH_vKkGorxHcXRn2Rpo-MlgcCJ3PK-MtZLOGetYEXUOFsJCSSJ58quTTdzWRjDNsFpkZ4ZG1SHvo-cFlY7HFrKkB4Qj-JiKFgvoj8GEq1SEWjlAAcqmukj3B-Xe43qoIXDubJF272zOWr6ExzeUqY7jk9YxCwUvIvZ225ApAMKuzXJcu1wCYkEJxyXgVhnLeS97Gb7tsViTJOjtpd-vW5zJOdZXGvErMTJ1bLF3nwtfSq6oK9P2HhOIVS2vYfh0aaTQcF18VJkh1szmF56Lw1x0w&redirect_url=%2F
  baseline: 302 -> theomuys.restaurant.foodticket.dev
  canary  : 400 -> (none)
https://glidegroup.cloudflareaccess.com/cdn-cgi/access/login/internal.dev.glideblack.com?kid=f86d54432da67505f909bb853c1030c66b65b5ec3008e3d2e5d72a78c24e7690&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjViZGU1NDM1OTVlOGM0MjkxYTg1ZTU1OTljMzU2NWE5M2Y5OWI2OTdlODVmODRjNzllNzU3ODFjZWVjMDljMTMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImY4NmQ1NDQzMmRhNjc1MDVmOTA5YmI4NTNjMTAzMGM2NmI2NWI1ZWMzMDA4ZTNkMmU1ZDcyYTc4YzI0ZTc2OTAiLCJob3N0bmFtZSI6ImludGVybmFsLmRldi5nbGlkZWJsYWNrLmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA4ODE5LCJuYmYiOjE3OTMwMDg1MTksImlhdCI6MTc5MzAwODUxOSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkFUIiwiYXBwX3Nlc3Npb25faGFzaCI6ImIzZDc2ZDAyZThjM2Y0YjBlMWY5NjRmNGZhZjNhMGJlMzU1ODhlOTUwYzQ3MDg0NTIzNTIwMDI0NTM5ZjgyMmEifQ.p9IwRI1nehLIdXObnMr9l0zQBPLflFfFJL3Yx6fY79Pg_XTIuerzfwSXHZ4R7YYKanqVatvoEJ6s3nvuaI8v3wgUTG6iyInUhxqMiDJ7sYegVMQnYV3c5lgPC0uxZf5waqIsn77g-RzoUjI0kscici8_oAarmov2WZ8RZr__wOKqoRtjso-uNdL6KaUl0DysOlvCoBhmb3IxrUrFvFKKvTNdRxEuCit9RMkmBYQe4cYluXyPfAEzPRmKaB1BKgY7KLgNzJlH_C9bYi2o1Rt2CvT6G8pkBil1OoVTnsGnBIwYzBwQ7r_cleWCLeKtXHzXXoP0dJUgiX2oGTQVlY0ePg&redirect_url=%2F
  baseline: 302 -> internal.dev.glideblack.com
  canary  : 400 -> (none)
https://iabilet.cloudflareaccess.com/cdn-cgi/access/login/wl-test.iabilet.ro?kid=c2630ecc599b959573f7ed3a5bea4077aa63e72048595494fa88acb332e079b3&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImRjMmQwZDNkMTBhZmZmYTgwMDhiZTYzNDBiYmY3MTA3ZTAxYjQzMzVmYmU2Njc4ZTUwNTRmYWYxMDEwODQzMjkifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImMyNjMwZWNjNTk5Yjk1OTU3M2Y3ZWQzYTViZWE0MDc3YWE2M2U3MjA0ODU5NTQ5NGZhODhhY2IzMzJlMDc5YjMiLCJob3N0bmFtZSI6IndsLXRlc3QuaWFiaWxldC5ybyIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA3MzI1LCJuYmYiOjE3OTMwMDcwMjUsImlhdCI6MTc5MzAwNzAyNSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkRFIiwiYXBwX3Nlc3Npb25faGFzaCI6IjU0OTExMjYwM2E5ZDEyM2ExMDhjMmE1NDQ0MWQwYWJiNTVlYmQ3MjA1ZGMwZDM0NjMxYTJlYmVhMTUzMWViM2YifQ.CQAOsMcvSJaB3rwHD68KTeh0GFV6_WS3PYD-VTTBs1X14yto3KlzfEzfA4GJNXNBpb90yYLhXBu98hblbfJLrmUEHMB05-oXD3CSzVlUnjl8WvLPyFV8UcMqIQaCOcrMXn90qYyAD71Y_R7NSkNuJTT4bIAavyUmODzV8cJMSwDktMtofM1Yy83ouwHhIc9QtJ70oF7LI2pgn1aorZQH-DHHqbZ4Ok2N8JCYFqh6aajt00ww17V_CYcHQVcozArKYPfK4rzGhc1UpVA6LZe8C_Fj32ySS8s-5w59qo0K4_Syy6J4ZxXyka96l-fbG089VTDxxbymm9j6yGVJ6Rjdfw&redirect_url=%2F
  baseline: 302 -> wl-test.iabilet.ro
  canary  : 400 -> (none)
https://hark-agi.cloudflareaccess.com/cdn-cgi/access/login/cf-sandbox-control.dev.hark.com?kid=d0f520771362397a7fe86f86d22f016e94c0d4badfdcdffb450bef9166355c1c&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJlYzk0NTA5YmM4ZWJmYjBkMGEwYWFkMGZiNDE5ZDEzMzJiNDk1ZDhjYTA1ZjAzODNkNjExYmY0ZTA3MzRhMTIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImQwZjUyMDc3MTM2MjM5N2E3ZmU4NmY4NmQyMmYwMTZlOTRjMGQ0YmFkZmRjZGZmYjQ1MGJlZjkxNjYzNTVjMWMiLCJob3N0bmFtZSI6ImNmLXNhbmRib3gtY29udHJvbC5kZXYuaGFyay5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjQ1NSwibmJmIjoxNzkzMDA2MTU1LCJpYXQiOjE3OTMwMDYxNTUsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJjNTI1ODc1OGQ2M2VjZjNjYTU5NTIzZWYzNDNmZGRiZWNjMzkyMjJmZDE0MGU0MmEyMjQ5YTNjNjUyNTUwMWQyIn0.HHUKt-RaABfBYm97koc0tbUfacuafGn0L-oIgPPZnC1xR5YgZmX3cVemAyTdyzTk9aZ0sjqhfXD-5cZk5HcGSJu9cxQFiwWS_df4Z2t_lMzPLbACbcBxuYOkGpLLI3g6pM8JvhFyGyZ8KxGi-c9MrwjJfKiWVfO3eD35k9e6zJ0sjGuK68l4TNhM0OkGOUo8gvOWRBhOeHuLnPuipLDPvUhQ1X7KxCQ54D7jwCf6qYU-6n3YEIGwFSDLbR1LpoMyoIQ9u9q2gEZEWORl5zrgbld8Kfy7cJT-_3zYuGnFD-2w6ST8EYeirp2NHtQYbxClm1ZBnFe5Z9rfxISzq9iveQ&redirect_url=%2F
  baseline: 302 -> cf-sandbox-control.dev.hark.com
  canary  : 400 -> (none)
https://guardme.cloudflareaccess.com/cdn-cgi/access/login/api-client.ie.preprod.guardme.info?kid=1480a7ca66060a2cfb1923a76b42ca49b1ba79cdce3380f30f10c58c692e5bf5&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImUxMTM3ZmU1YzA0MTQwZjk1MDlhODI1ZjUyYTQ1YTBlNjc1NTMxMDZjMzNiYmQ0MDZjMmIyYjg4ODVmODNmODAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjE0ODBhN2NhNjYwNjBhMmNmYjE5MjNhNzZiNDJjYTQ5YjFiYTc5Y2RjZTMzODBmMzBmMTBjNThjNjkyZTViZjUiLCJob3N0bmFtZSI6ImFwaS1jbGllbnQuaWUucHJlcHJvZC5ndWFyZG1lLmluZm8iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODI5MiwibmJmIjoxNzkzMDA3OTkyLCJpYXQiOjE3OTMwMDc5OTIsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJhYmJkNjQxYzQ0MDkyNTlkYjliOGVkZDliODRlNzA1NTEzNGFjMzgyNDFiOGY1NTM2YWY5Njg3NGQ5MWI5NGMzIn0.kElWuRcdeNXaf8KDgNuQpM9H8QMUfX0sFGgBEX1_5LB5JIWogiKAMf6fbIkuVP1_KpmA2FIKgCssNo687mNnbEhLPIRF0C0VfxP5oN4VSCDlIBu3GTNQP64-U6lxzJTteT5HxR8UtPPR_-3Cs970zVWxDox7C0647q_rmXiGNRhTrRqly5bbKAJXmow58sCSeKi5kT_q6ZR7iAV92N1riwSvJ2zlo-eNabtHu26Kl2K9MVuBRaokkdsUwupIxWNdB2mwStPngpaWi5FM_Rlng8foP2hTWGMCelaEC6HjPllX7xE9ReycGy232X7j52B5MpQYEAe1po4G6KR4RVAmPQ&redirect_url=%2F
  baseline: 302 -> api-client.ie.preprod.guardme.info
  canary  : 400 -> (none)
https://itonthespot.cloudflareaccess.com/cdn-cgi/access/login/billing.itonthespot.ca?kid=7e5fe546a64eaaee5f277d3901e89a14abbf25ba3f34609d906d79b7e4f9cd00&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijg1NWFmNzg3OThlNGUyZmE3NmZmOWViMmEzZWU3NTc4MmFlMTcxMjQzOGJlYWE1ZjU2Yjk1NzY4NzQ0MjhhYmYifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjdlNWZlNTQ2YTY0ZWFhZWU1ZjI3N2QzOTAxZTg5YTE0YWJiZjI1YmEzZjM0NjA5ZDkwNmQ3OWI3ZTRmOWNkMDAiLCJob3N0bmFtZSI6ImJpbGxpbmcuaXRvbnRoZXNwb3QuY2EiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNzkzMSwibmJmIjoxNzkzMDA3NjMxLCJpYXQiOjE3OTMwMDc2MzEsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDQSIsImFwcF9zZXNzaW9uX2hhc2giOiIyYzdhZmM3MDc1ZDViZWQyOTEzYmVhY2Q2YTkxYTZmNjgwYmI5ZDY4MDMzNjAxZWYwMWUzOTllNjMxY2UwNmRkIn0.SLMDRzP6v3m-lQpOh8Pky9Zw1p77WiZQsObzZBhn-lz_euQqUgonHLgqD13op5IxtjsyCX1n-wSjyILuzmPLDsfXT0dJkjaFjq79iinU9lIuEWzCygY56vaTiux8HpWbqDkh1RGv6720ctS6JPf4NtYQN1HLm9Z0bHmgtQy3JLSRumQkKMpjMwXDs7MG2us4XTFAf2KKYDY3d42uBXuFPRtniKesSmjA8qFA268hCXuvA5y1YH7o_dbr8DEEaNci_h4X6rESqMMgWkEKYTVKsNz7l_UMJ01yMjl2IKIpyuLfv-PXitwWaf9wsAMWRCkJrtL8di2nuYg8y1aYlUL73g&redirect_url=%2F
  baseline: 302 -> billing.itonthespot.ca
  canary  : 400 -> (none)
https://guardme.cloudflareaccess.com/cdn-cgi/access/login/api-client.uk.preprod.guardme.info?kid=1480a7ca66060a2cfb1923a76b42ca49b1ba79cdce3380f30f10c58c692e5bf5&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImUxMTM3ZmU1YzA0MTQwZjk1MDlhODI1ZjUyYTQ1YTBlNjc1NTMxMDZjMzNiYmQ0MDZjMmIyYjg4ODVmODNmODAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjE0ODBhN2NhNjYwNjBhMmNmYjE5MjNhNzZiNDJjYTQ5YjFiYTc5Y2RjZTMzODBmMzBmMTBjNThjNjkyZTViZjUiLCJob3N0bmFtZSI6ImFwaS1jbGllbnQudWsucHJlcHJvZC5ndWFyZG1lLmluZm8iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjg1MSwibmJmIjoxNzkzMDA2NTUxLCJpYXQiOjE3OTMwMDY1NTEsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJESyIsImFwcF9zZXNzaW9uX2hhc2giOiIxYzg3YWZiZWQwMWQ1NDliNDk3ZjU5ODk1MDMxN2QwZDQwYTAyOWU1ODk1OTJmNGZmN2RhM2FjN2EwNzZlNzk4In0.B-oliUYjlTtGEma46x0mTcuDs89QdGOUMC_Wsc24SeyIm55EIdQZtBWcl5twNp_a3TMqb4U1mKPy9MOeicq3zFArC5u2ufjfCFH_piPQPrlIDnzuk8S2t1Q3NUijPo1-d3ALS1z3jV6CdsP4VxOPiTxCTYNNe14NbnIHRKfL0cF92suHpIXUcJxG-p82-VvokJzhWDDCCpKrjPE2ilwW3kjiRLPSBMoKgvcskO4fNfCzbenNtesFNE8g5NrpX2GZMa8sjjruKbH9rz6bz9J3ZLF-rAQTIDpM7SSAw7qY8oS-BZw_LrVz-ha3O22kTWkshJGJynCYqnaVARSYZUdZOQ&redirect_url=%2F
  baseline: 302 -> api-client.uk.preprod.guardme.info
  canary  : 400 -> (none)
https://jmgsystems.cloudflareaccess.com/cdn-cgi/access/login/support.jmg.systems?kid=d411dddfa00eebab0ac5dcae6759eb5e568d153fe09242cbf134e38da3638f9b&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjViNTYyMWE5ZTg2ZGEzMTE4Y2Y1ODY4OTQ1YTI2MTBlZjRlNDE4Yzg3NzkyYmVkN2Q4YmExM2NiNmQ2ZDkzZDEifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImQ0MTFkZGRmYTAwZWViYWIwYWM1ZGNhZTY3NTllYjVlNTY4ZDE1M2ZlMDkyNDJjYmYxMzRlMzhkYTM2MzhmOWIiLCJob3N0bmFtZSI6InN1cHBvcnQuam1nLnN5c3RlbXMiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwOTI0NCwibmJmIjoxNzkzMDA4OTQ0LCJpYXQiOjE3OTMwMDg5NDQsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDQSIsImFwcF9zZXNzaW9uX2hhc2giOiI0YjVkMjg4OGE4MTYyN2MzMGY2N2UwOTc0NGE0NDU0NGU0NjBiMmE1MmJjMDdhY2IxMWExMDdmOTFkNjE5MzA5In0.3TE_fYWEJ_YhQLDQAur0NipsH-w6LTF6HNM3qiAiH2K8zad0JIPHZnwzgLGuM10DTpkTkmXBo_oHZ5fvjc5498TXrr5DQy1N6dBP48m80a8it8rjdQOCjw6-2_vilBBI8AOU5Y8Hu-uuWIFTxKJB755VgX0vjXVA-iiD2iq4ZtvuHWnEwqbXjY411Ju2JO79khQbkmbmbj_9qPvnSqS8jsTvXcN67o3hP49mM5L3mMa5fbmmxlfHBbxMcD-S-xqz04YcR5qwrAE4cAkgwrAQKVHTgwGnt0ImFhUh6aKjdY629TquuCOHxoQhOWayu89KHgpVmgWy_DAVeqgq654EbQ&redirect_url=%2F
  baseline: 302 -> support.jmg.systems
  canary  : 400 -> (none)
https://jenphym.cloudflareaccess.com/cdn-cgi/access/login/starter-saas-standard-docs-private.clearvia.dev?kid=9d0c20dbfa8c736a253d8d794ab2951eaf466c91040611a779b2fbf38a4392c5&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIyNWFiY2E1YzM2ODA2YTVjM2I1M2FiM2RkNmRlMTU3MmYxYmFkMjZjM2I0NGNmNzBmZjEzYmE1OTA3ZDdhNjMifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjlkMGMyMGRiZmE4YzczNmEyNTNkOGQ3OTRhYjI5NTFlYWY0NjZjOTEwNDA2MTFhNzc5YjJmYmYzOGE0MzkyYzUiLCJob3N0bmFtZSI6InN0YXJ0ZXItc2Fhcy1zdGFuZGFyZC1kb2NzLXByaXZhdGUuY2xlYXJ2aWEuZGV2IiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDYxOTAsIm5iZiI6MTc5MzAwNTg5MCwiaWF0IjoxNzkzMDA1ODkwLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiYWU5NDhkOWQ5ZTE4MDIxZTQyNWMyYTczNWVmNDA4YzgwOGY3YzliMDE0YjYwMzZkODBhMjJjYTkxYzM2MzQ2ZSJ9.oYDSiou4gP9PHj0Y4jy3RCVl6wC9KmJJ6DcGR3xqCA4s18iiXbcRE_y6ZrOs0ISAIJ15QuDtoSgMi7stsM56112mU47cvBzffhMhkLGq4RIo3MOQrZrjiJFlSnL2xohWFeNtuAkncE2p2bBEJlV98LCMQ_kmnC_ubtfzvlgUXQsjejYnUVggXv1dkoUQAehl0WQqAvy-L2sCtXf_-SR9IpygaLomTtA9-R8ureW0B0Kq3uruZHkGiRI92znWiq9ss9X5XaqQQVuNO4FBE2EjHT3aelx_VqAyoBqi1kM3Kx_tLXRwmXmSm0v5_0BBZEQrsmHjfEl4pVUWQYki0rX_ZQ&redirect_url=%2F
  baseline: 302 -> starter-saas-standard-docs-private.clearvia.dev
  canary  : 400 -> (none)
https://kept-website-pages.cloudflareaccess.com/cdn-cgi/access/login/kepthq.app?kid=06fdf1cdf09a72def31295516cbb32631967e77a9144665f89c65c792e3ce3dc&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OGFmMjMzMzMwYTk2ZmFjNTUzMTBhMmQyN2E2MmQ1ZWM1YWY5Zjg3ZDBhOTg5OTNhMzk0MjZlMDg1NGI2NzcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjA2ZmRmMWNkZjA5YTcyZGVmMzEyOTU1MTZjYmIzMjYzMTk2N2U3N2E5MTQ0NjY1Zjg5YzY1Yzc5MmUzY2UzZGMiLCJob3N0bmFtZSI6ImtlcHRocS5hcHAiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwOTI1MywibmJmIjoxNzkzMDA4OTUzLCJpYXQiOjE3OTMwMDg5NTMsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiIwNzk5YmIxMjBkMDJkMWJjMzA5ZGQxMjA4NTgyNzI2ODc4OTk0ODBmZTE4ZDhlY2Q0NjdiZjlkNDBiY2Y3NjQyIn0.ArCdSyrRuTQQ0eRQSYkKB6U6iy294WHQFZvHXIGQaV3qGWUufEX35a5359cxW7-8P3GcnRO9MiW8r7CiAW_OlupD_tjAIHDGP16auOpGpYyxJ-qSrc7rSADOVY4XTfT5PBhHwZLY0gNgQL8JipvSMoKoJLkZLerXl0udO2-_8iTcBLn-HjL2TbiymVrha1j2XcsZijvzWkRex-uLyrhOHRbNxI9pH2dqHBK-arerFgZDZieDyvSAPLXTdlzfTYb2qGcP_ORAAMcgBNyL9ygkDz9brpiR1ImN3KP5Aso7Ys5X-iFiVWfgSWA03fx_XMhZVZvZ3JoXtODzLtaDTzEDkw&redirect_url=%2F
  baseline: 302 -> kepthq.app
  canary  : 400 -> (none)
https://jyskebank.cloudflareaccess.com/cdn-cgi/access/login/test-auth.jyskebank.dk?kid=f975aa0d5f8f4c53d1c0c28cdcf6cb1a879250264d9070a2e5761f4ef82ee24d&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAxYmRiNzc0MzM2YWJiZmI1ZWEyZGI4ZjcxOTgxYjcxOTFhNTIyYmJiNDBhMTJiYTEwNDg3ZDNlMDJjZDk1NGIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImY5NzVhYTBkNWY4ZjRjNTNkMWMwYzI4Y2RjZjZjYjFhODc5MjUwMjY0ZDkwNzBhMmU1NzYxZjRlZjgyZWUyNGQiLCJob3N0bmFtZSI6InRlc3QtYXV0aC5qeXNrZWJhbmsuZGsiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjk0MCwibmJmIjoxNzkzMDA2NjQwLCJpYXQiOjE3OTMwMDY2NDAsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJESyIsImFwcF9zZXNzaW9uX2hhc2giOiIyN2MwOTg1NTVjMzU5NDdlYTZjYWE1ZmE5MjE5NWRmNjI3ODVhNjUxNDIyZDZkMjE5YjAyYjNiMDA2MjExNWMwIn0.zZYDNhxSHOsGC9lkxdlEdmmgi2dWkvbyup_OPf8e52J7vzL3fUDYfPDofU3l4i9y90K_n0JCNrWAPBSyvQXoI0HyUvg0UVoduLAM0D4ogmsRaBRP844mxGSFAi4WqW7s43ZFI8PkbNOLXw4etCYthOqOcHfv05Yeee5zKZu33jxpHDGSIee4y55blIOwpUmN4UIlcGk9WiWbC7CQ-559zZSVq7U5o-2NF7tNmEikseJUTztEep9gvbwpyCrTWoPQYX87Vr9_MPFX5htRFYpCrcDLXZWUWqCdwRoeSW-BvECyZ7yJ3s5Y6EY225aUEm84DGrx2VG3TS4gQOBEIOpfZQ&redirect_url=%2F
  baseline: 302 -> test-auth.jyskebank.dk
  canary  : 400 -> (none)
https://moneybees.cloudflareaccess.com/cdn-cgi/access/login/presentations.moneybees.ph?kid=6444cebe0171a0d85d639debcfa6fc08c93987a86bec3e619ee096d1cd4c9047&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjQ3NTc0ZGJjNDJiN2MxMDRmNzMyZTM5MmQ5OGRjMTc4YjJmMmU3ZGM0YTdiZjZmOWNiMzk4MWY4MTYyY2FhOGYifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjY0NDRjZWJlMDE3MWEwZDg1ZDYzOWRlYmNmYTZmYzA4YzkzOTg3YTg2YmVjM2U2MTllZTA5NmQxY2Q0YzkwNDciLCJob3N0bmFtZSI6InByZXNlbnRhdGlvbnMubW9uZXliZWVzLnBoIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDkwODksIm5iZiI6MTc5MzAwODc4OSwiaWF0IjoxNzkzMDA4Nzg5LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiRVMiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiZTI5YjQ4YzA5NjdiYTU1MTVmOGU0ZjY0ZWZjMDAzNWUwMmZmOTNkZmVkNWJhMzg2YzkwYzc2MDZlODA0YWNmYyJ9.y30zYLJKIV0MqFnELe3lGZoRqSYzT9CmTTKX7pVXHfJfKu3QrCujjjlK0XniitWF1bQc5eldK6jr_xsmI78y5L54Pj7FzMmfBEi82b369AvZ5eeTgqJ7BCRvndno2Tn-Qv0a7iWFp3d7cuUPVSOxmj8qWE038bld0-8_JQ11vwuLawsGhV6OiJBIDhazxO7-8d7u4Fl9kzHU_oew0yxnb2MP-Y26eZcT6AirQCh7Z9Z9pnHuRVPXumwzjHph5uhxmifEmOOZ9M_uLGvt8CAOplWgeQwEcxTngfT8extCk2GZXAIZmNNbHYs1f7GWbpjKvK-UmDaDG372084fZZSEgg&redirect_url=%2F
  baseline: 302 -> presentations.moneybees.ph
  canary  : 400 -> (none)
https://membercentral.cloudflareaccess.com/cdn-cgi/access/login/devportainer.management.mcinternal.com?kid=a5b95d28ba107205b0a79b633919bac93c7eac669ef527473f202a4a9bc3933b&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImUyNjc1MmI0MzYzOTIxZGZjMTM3MDBkNjhlNTkzNDg4NDgxOTU4MmI3MDIzZmJlMTcwMGQwZGYxYTMwN2YwZmEifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImE1Yjk1ZDI4YmExMDcyMDViMGE3OWI2MzM5MTliYWM5M2M3ZWFjNjY5ZWY1Mjc0NzNmMjAyYTRhOWJjMzkzM2IiLCJob3N0bmFtZSI6ImRldnBvcnRhaW5lci5tYW5hZ2VtZW50Lm1jaW50ZXJuYWwuY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDg0NTEsIm5iZiI6MTc5MzAwODE1MSwiaWF0IjoxNzkzMDA4MTUxLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiNWQ4ZGFmYzE0NWE0ZjJjODc5MmU1Yzk2OTFmZDMxZjU4ZTJhOWNiNWI5NDFlYzhjZmFlOGIxZDI0ZDVkNWRiNyJ9.ed7OCFEzbC7ejcP_kBSpCZhtuABeSw3F0I5-Fn7lOdSLRvui-OLK2Ez7TPRyu6cc03Bd3PE-TvoQFirqYV_M4_xPlkFWuRocSENDoK4Cub7CkrMfDQk3HTpCdQbDu1ixO7ll-T5xUCkUfj-YuNJ-atCS05ueEkGxhJ68zaMx8MRi-ZWxC2ILm6aK2PvPC8DBZjNoa3KF_OdkDogTMsO5JcXnrK3S4-EzxXgywbUbxBSl32hNot-gMg8X6PgwCNd1DsB2Qq0DgSctQLuOkHTucYb_2V9jBhjjy8aFvtaclFqIvvnWaGH37fvNxxEmeLUJsAmW4ppdvIrBuqTkv0QtGQ&redirect_url=%2F
  baseline: 302 -> devportainer.management.mcinternal.com
  canary  : 400 -> (none)
https://nwxs.cloudflareaccess.com/cdn-cgi/access/login/clients.accessworxs.com?kid=4290232068ff66262867d1b0cd58073f7f2c9f0b0050cd831c1b70d2dbd33ebb&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjljZGVkYTg2YWZmZjMxNjJhZTg2ZDFjNzA3NjFkZWIzZWY3N2IxODY4MjhjOWQxZDAxNDhkOGUwNzRjZDM5NTAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjQyOTAyMzIwNjhmZjY2MjYyODY3ZDFiMGNkNTgwNzNmN2YyYzlmMGIwMDUwY2Q4MzFjMWI3MGQyZGJkMzNlYmIiLCJob3N0bmFtZSI6ImNsaWVudHMuYWNjZXNzd29yeHMuY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDY5OTksIm5iZiI6MTc5MzAwNjY5OSwiaWF0IjoxNzkzMDA2Njk5LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiYjRhMDhhNDkzODIwMTMzODRjODcxYjZkMWVlMzEyNDMwY2Q0OTYxM2VhZmRkM2UzZDVhYzMxZDkxNzUyZDJkYSJ9.FKo9N9IQKMLqxkS79d-hlppKctLgXBxX74snqpjtlL0rutWnyBJoxUMGtGDqL551P-20dmxMS2zXSwltigR5Z5RZWoGYlCMRbvKjw3riuyczSAsqJfB5b9u3fNCj4Lb_daolEh2A6jeVXRjRciayS2GKzhajvIx17EkEyEw7j7ECh1OcwkNjRs0xKblX4BhXVL5G_zrKgtQmBbhDhl1-d9tbA5Aj5M8HOpvA-LH0QtG27E6ICgL5ys-PmGbJAKplHdbAbDyOeztXKaN16rkMM9qGPVbpuh92sLipZa4xdKXG5X-IjnPRTfSNOZGivnZVRxsjCndjyawxpiVINEAdQg&redirect_url=%2F
  baseline: 302 -> clients.accessworxs.com
  canary  : 400 -> (none)
https://qualibee.cloudflareaccess.com/cdn-cgi/access/login/alertmanager.app.qualibee.ai?kid=3589ab26c3c48087f3a925d99958d2d6589d4e4afb3e664e0d9c225451945ec2&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjRjMTBjYmVkMjRhOTRjYzk0MDZhZDg5MTVjNGIxY2I2ZTQzOTA2NTQ5NzYxM2VkNDQxYWUxZWI4NzE5MjA3ZmQifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM1ODlhYjI2YzNjNDgwODdmM2E5MjVkOTk5NThkMmQ2NTg5ZDRlNGFmYjNlNjY0ZTBkOWMyMjU0NTE5NDVlYzIiLCJob3N0bmFtZSI6ImFsZXJ0bWFuYWdlci5hcHAucXVhbGliZWUuYWkiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODE3MSwibmJmIjoxNzkzMDA3ODcxLCJpYXQiOjE3OTMwMDc4NzEsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJlNmU4M2JiMGE1NDM1MDkyYmUxMTMzNmI0YjEzZTMyMmFjOWY1MjhiMWY0Yjc5MGU2ODNlZWQyMDg3MWM4ZjlmIn0.OEcz4lCkUa6egiEcKk01YQHQzrxdi4rElCl9WFrw5ikOSBFWRauSg7nsqxuAJ1Pl6TMjOC6sPW-nIeWeasXgOQonEAjucYvy41eSG6cUCft5Ym3XE3j_COTKuO6yHYw9yZLWzk0Fcv0jfpXwebZAKEXb3--fZ3rEqCT0YxF4DnSpQ9qGtMh_R5EUgVpjtVNKoOileossF_a4yp1oha9iPt1nV38kgPt9H_Z-c4NR-mgH_deWjsc2dWRjpEATkflV2Pni_5uIGt8muUbuLTobgu862TGZEU9z0iWPWI0p-BoWFkOZL3WuE0e6BijQVrRMhmb6hQoMcXVZlkH7fhpRMQ&redirect_url=%2F
  baseline: 302 -> alertmanager.app.qualibee.ai
  canary  : 400 -> (none)
https://nadivpn.cloudflareaccess.com/cdn-cgi/access/login/ops.nadivpn.com?kid=36cde34ee9f18b98402e1ff09c613bfac4d96c7a6316d80ca30fb3fe1debf37f&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImNlMzVmOGJkYTk1MWE3NGQ0MGUzNTExNTE4MWYxNzFiM2JjNmMyODQ3ZTE0NWMzZmZhMTljZjU2ZTE2OWJlNDgifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjM2Y2RlMzRlZTlmMThiOTg0MDJlMWZmMDljNjEzYmZhYzRkOTZjN2E2MzE2ZDgwY2EzMGZiM2ZlMWRlYmYzN2YiLCJob3N0bmFtZSI6Im9wcy5uYWRpdnBuLmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA2OTUwLCJuYmYiOjE3OTMwMDY2NTAsImlhdCI6MTc5MzAwNjY1MCwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IlBMIiwiYXBwX3Nlc3Npb25faGFzaCI6IjFmNmQ0MWU0ZDQ3OWQxOWRmZDZhMjhmMmU0ZmRiNjk1YzJlYTUyYjUzZTQ1N2MwZjhkN2Y4NTc3ZTk0ZjE4NmEifQ.ktChM75xTzN1kVj_EMMgfzpuI2xFwipFsxYKTTJ8IPxhGHUvyw_0ZQO2i1UsAroAB2DHJQECJ6HgyVKy27SENQscmQkGAjCAFWpT1-x4yakGdr0rDveXlrFcSFQUvrm0_tWVcfJRyzRN08IZ7ogkSN6dtuh1lOw5sWI76ZiCiZL2o_ZC9L5Qu6bibDtuiuPP0UfQBtrGjiY8jZr3SB_vm6u7TTV-9nXTDxHJ1VWLEjrQ75hT9w7NfcqHyJw1BbGPz_Z5l8-DQlV-036Ewjn9lP9oWzAGw6OL7UDTsuvQdeaAGfwCksH9AFbpYAmD-GeiOa7fUiWYGl1xgY1vcC-SwQ&redirect_url=%2F
  baseline: 302 -> ops.nadivpn.com
  canary  : 400 -> (none)
https://membercentral.cloudflareaccess.com/cdn-cgi/access/login/devrancher.management.mcinternal.com?kid=a5b95d28ba107205b0a79b633919bac93c7eac669ef527473f202a4a9bc3933b&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImUyNjc1MmI0MzYzOTIxZGZjMTM3MDBkNjhlNTkzNDg4NDgxOTU4MmI3MDIzZmJlMTcwMGQwZGYxYTMwN2YwZmEifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImE1Yjk1ZDI4YmExMDcyMDViMGE3OWI2MzM5MTliYWM5M2M3ZWFjNjY5ZWY1Mjc0NzNmMjAyYTRhOWJjMzkzM2IiLCJob3N0bmFtZSI6ImRldnJhbmNoZXIubWFuYWdlbWVudC5tY2ludGVybmFsLmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA3MTAwLCJuYmYiOjE3OTMwMDY4MDAsImlhdCI6MTc5MzAwNjgwMCwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkNIIiwiYXBwX3Nlc3Npb25faGFzaCI6ImIxNzI2ZTA3YjA1ZWNmZDIwNWQ3MjA0MTVmMzIwZGFlYjMyYmIzYjJiMTA2ZDg5YjFhNTFkYmI4ZDI2NWFkY2EifQ.JmOzYNf78HGOZifFnu-82845JKdZLR46-Xg-wB_Oow-5cZOySwPjLtC7WjoMtSj9P2tR6R7qultrjf0dg6agXojrIOg-E5TlHsaVPQwmYF3218hAYBYHZzJQNS9rsdvKsAeOykeJIhYa9FY84hV_VrAoZ-pxoAF9S-Sa3-ZQCSKX55fbRxRWEfnuJXG37xoxUnWiaNrMMW7eOjI5hToacr9ie6e1khlgyDvgVnPTKfnyfcs8hx3Ee78ajGv1TfqRZYSY5P_rj-HfoKF-JGrsG6jP10F0p9GGkXgg7-o-FgKhnVDJWCOXdTkpJtDk2wsGkby0KRQB0OnmQumiN-5-ZQ&redirect_url=%2F
  baseline: 302 -> devrancher.management.mcinternal.com
  canary  : 400 -> (none)
https://prothmandigest.cloudflareaccess.com/cdn-cgi/access/login/local-gov-digest.pages.dev?kid=65153e867536176c0c16efcffafd3bc182b65ad57975512097553bc64b28d010&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImFiY2VmMjYwOTdkMzE2NWNjZjM0Nzc0YTBlMzBhOTBmNmZhYWI0YWEzZmFhMDIyOWU0OGNiMjZmNDczZTc1OGEifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjY1MTUzZTg2NzUzNjE3NmMwYzE2ZWZjZmZhZmQzYmMxODJiNjVhZDU3OTc1NTEyMDk3NTUzYmM2NGIyOGQwMTAiLCJob3N0bmFtZSI6ImxvY2FsLWdvdi1kaWdlc3QucGFnZXMuZGV2IiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDgwOTUsIm5iZiI6MTc5MzAwNzc5NSwiaWF0IjoxNzkzMDA3Nzk1LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiMmNjZmQ0ZGY3OThjMmI3MDA2OTE0MjRkNGQ4MTNjMzRlODUxZjg4NjQ1MDRiODFiZmZlNTQ2NmYzNDg5NGViZCJ9.RC4DdllgbNkAnlUS4oKnoduhbMBSxzSXZbqcUCQLUNbqJAtTzENZdCJNAjrd_zoGvf2jMNQlL5KL6Je2xqjcqmJGqJ9aLQdiNMXlRS3ELXT08F7wTBlc6ENBkBC64QRsQ7p0OfBA0_k0_vfG4j3OsDpfrOtBlYSBh9tF1o3IcFvH5SY3IwWzGeXrfiyFrWpBUGBhzvTwK4FUL4L-ax-NaANdyJlP21uURXmDKQLUbpuQeX_hosFq2sxqIF28goQBhzAgbhhQXouCC3Kp7iOSjTPnB7NlB2jVcS5-vqgOJ5TBQe6_WKjwk9TEr0YZdhTG8O-nqFcSmZrY3uPQQ5Z58w&redirect_url=%2F
  baseline: 302 -> local-gov-digest.pages.dev
  canary  : 400 -> (none)
https://rh-verified-edge.cloudflareaccess.com/cdn-cgi/access/login/cluster-us-west.rh-prodnet-sandbox.rhinternal.net?kid=8bdaecfe328e914c4e3169dd0f5585790420641e7d25818615bd07f16d5165d5&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAzOGExZjA3NDVhZjllMWMzMmJkYmIwYjQyYzhkODI1ZjU5YTY3OTAwZmE5NWFlZDc5N2YxZGYzNjhiYmRiMjYifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjhiZGFlY2ZlMzI4ZTkxNGM0ZTMxNjlkZDBmNTU4NTc5MDQyMDY0MWU3ZDI1ODE4NjE1YmQwN2YxNmQ1MTY1ZDUiLCJob3N0bmFtZSI6ImNsdXN0ZXItdXMtd2VzdC5yaC1wcm9kbmV0LXNhbmRib3gucmhpbnRlcm5hbC5uZXQiLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNzM2NiwibmJmIjoxNzkzMDA3MDY2LCJpYXQiOjE3OTMwMDcwNjYsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJVUyIsImFwcF9zZXNzaW9uX2hhc2giOiJjOTE0YTVkYzM1MDBlNmIxNGFjY2Q1YmY3YzQwMzJkNTBjYjEzOTg3YzcyYmMwMGExZDg2ZDlkZDBiZWYzMzlkIn0.qzLXrDi3jxAAdmY5oMBgjBVG7UzO8AG5g5-i_s6Mh6BuqfKNWYnqN2yEyL2pgSOMJUoOnT5X8lkDfldLKEXuuv83GKKTpsvtJtayEtBAoXu5Q2Y2D6mwqLVMozzh41aiv834vSvEoydbdsLJJVeYiBl2FdKcefDKWk6C3vTrtNEkmBNkWhAmFqhZcmohwFYlvsPAUHxscq-Q_vbTh7jpQfQjtlK7plnN-5ZiK7_nUM-ttV0Jkt2ZPzInIXieZ9hvQFYWvtp40WbkyzUSWmpIMJMS5qQcyB8v7hkWd0Bvi4W3U23oxUEeQu5j-CMJos9bxpcIF1O0AVT0-t-Ux_lmRg&redirect_url=%2F
  baseline: 302 -> cluster-us-west.rh-prodnet-sandbox.rhinternal.net
  canary  : 400 -> (none)
https://rainbow1.cloudflareaccess.com/cdn-cgi/access/login/gateway.localcoin.tech?kid=fdcbef388d56ce8876adaec78306d154425b4e10da8f711f5b45ee90adaee249&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjY0MjExMTU5OGYzNTc3ZjVlMDQyYTk0ODY3YWY3OThhYzI4NTAwNTAwMDA3MTA3ZWYwMmRlNjhmZDcwZTcyMDgifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImZkY2JlZjM4OGQ1NmNlODg3NmFkYWVjNzgzMDZkMTU0NDI1YjRlMTBkYThmNzExZjViNDVlZTkwYWRhZWUyNDkiLCJob3N0bmFtZSI6ImdhdGV3YXkubG9jYWxjb2luLnRlY2giLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwOTI1MywibmJmIjoxNzkzMDA4OTUzLCJpYXQiOjE3OTMwMDg5NTMsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDSCIsImFwcF9zZXNzaW9uX2hhc2giOiI2OTQ3YzhiMzQwMmJlYTgxYjUyODA3Yzc1ZWQ2ZTUxZTRkZDAxN2RhNjAyNDk3ODFlZmNkM2YyNGFhZWIwMGY0In0.Yg3brOLPzsHS-q8oh55XAmnuufobLQNt7jGZYbnzLmCINH1zf_Ov1WgvYwsogvD3ObolA15o-zgLusAk-vM88t8X76awjvK6xFSm0R1vha4fhYWujBWIDyt2Gb_oSVDkFXwBfjXlVdne5Sa21fkHQghccFHtQ03bweqyGN5mWFKD3sD8FC6SCZML7HaRjZ6q0N0sxKyY35RgByha9ax3L1EyLnQ50pR47H8U-U1WVHnU5NyUl1tv0zzLUpAsbN0uE-xRcnlOhR8dHl4rYq4do8w-FoU5h5MwPI_EvlsfKyHe7Wp9EJdEqsYFR_F2p4XzNZwvjXANJ58iOjHKRRXPbg&redirect_url=%2F
  baseline: 302 -> gateway.localcoin.tech
  canary  : 400 -> (none)
https://schlaeger.cloudflareaccess.com/cdn-cgi/access/login/amazon-wettbewerber-recherche.pages.dev?kid=87689eea18a36b764f151902883ed1585315913f8280a3178a0d12aa1dea3d6c&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImM4NDY5YTI0YTg3ZWZiNmM1OTE5OGIwNTExMTZhZWI2Y2IzMGMxM2Y2ZTNlNTk0YzAxYzA5MzQwMWNhMWJiY2EifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijg3Njg5ZWVhMThhMzZiNzY0ZjE1MTkwMjg4M2VkMTU4NTMxNTkxM2Y4MjgwYTMxNzhhMGQxMmFhMWRlYTNkNmMiLCJob3N0bmFtZSI6ImFtYXpvbi13ZXR0YmV3ZXJiZXItcmVjaGVyY2hlLnBhZ2VzLmRldiIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA4ODM5LCJuYmYiOjE3OTMwMDg1MzksImlhdCI6MTc5MzAwODUzOSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkRFIiwiYXBwX3Nlc3Npb25faGFzaCI6IjdmOTU5N2VhZjc4ZjUxNjk4YzVkM2Y5MDJmZWZiNTA2ZjhjODBhNDI3N2Y3Y2Q0MjM5ZDIyYjJhYzU0Nzg4MDkifQ.ZtOPdJ6Da7uR549RSnHMoXbTVJm9EOZ9N-yDc7taXN5HxEZ45CSl5_fQx2reZlI9KrnmJ2W0rNrETE-Gw1pzlINlMgbMnkgix7ftuF73sqBb6H2yrhO0zRHtcToAxfrMI796GbGLdqvp4Om3LrPcwlGtkxDohqUYy2w4b--IbNi1o7nNVlXpcFhuuZeletMIMg9IGcUD4OX4j4RXOsB7hASDbzyeHj3xm_smYYHmdQj-2wmlc7JE_ASYmT2rskgDFgfbz5EnOROYG9NIMtcHubDPq_6auFIK4up8hHj3m3Z6gibabB-Ue6b5fh5Xvud_BZp4njeAH0IYeizotGrroA&redirect_url=%2F
  baseline: 302 -> amazon-wettbewerber-recherche.pages.dev
  canary  : 400 -> (none)
https://ramp.cloudflareaccess.com/cdn-cgi/access/login/internal-docs.ramp.com?kid=da002d8a7ed34a737728c318ca0cb5429c7f4ddc7c6927c74e9f05a747213481&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjM4ZWEyNjlhYmFmMTM0NTM5OThiYmUyYjUyOWY5MGI1OTZjNGUxOTQyMDBjZjAwOWIwOWJlMmMzYjdlMTg4ZDAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImRhMDAyZDhhN2VkMzRhNzM3NzI4YzMxOGNhMGNiNTQyOWM3ZjRkZGM3YzY5MjdjNzRlOWYwNWE3NDcyMTM0ODEiLCJob3N0bmFtZSI6ImludGVybmFsLWRvY3MucmFtcC5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwOTMzNywibmJmIjoxNzkzMDA5MDM3LCJpYXQiOjE3OTMwMDkwMzcsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJFUyIsImFwcF9zZXNzaW9uX2hhc2giOiJkYzM5YjRhOTUzZDMzYTJlNWY3NDMzYjI0ZjFjODBjN2JkY2E2OGIwMzQ0ZWFlNTQ2Njc0N2NhNWExODcwYzZkIn0.nJb67f4KhjlopunIqHw0-5d0xYslEmlwf5B2TfAO3b29NaG5TP3JtgF295UY6Y8L6rJOPRNgZpbQv4l-frje7HGeH21slbRHxYUUtbcpDkMn-3ro53fz_pQPBJO021cI3oK_A6TI3we1aHQBtRw7lzGjOetfQ0hgbysk_FoDEdwn2tgQSjqbozNcso4dAGht3A_spIUJNJP3J8hwnBQoLGHEo3xrsrVyPy5jRb5YS17h9hMBrSVQUJYwTd5n7OOWuHvViYWFri6d_DdwxSdBF7KCaSeLWD35X28ijAU3DoaxD2Yqbu9H2BsM06cZsjrFLwOt5cwMwsNLqQ0B58aNbw&redirect_url=%2F
  baseline: 302 -> internal-docs.ramp.com
  canary  : 400 -> (none)
https://patient-art-fb77.cloudflareaccess.com/cdn-cgi/access/login/stoneharris.com?kid=15fb860f04ee0c7384b7e1709961a4f4e018733bd1ec050e072ac20cd4832741&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImQ1MDYzZTg0NDlhNmQ4OWQzYzk5ZThkOGM3MDQ1MzIyMjZmMTE0YzYyN2ZjZjBjZDYwZWJjOGExY2E2NWQyOTkifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjE1ZmI4NjBmMDRlZTBjNzM4NGI3ZTE3MDk5NjFhNGY0ZTAxODczM2JkMWVjMDUwZTA3MmFjMjBjZDQ4MzI3NDEiLCJob3N0bmFtZSI6InN0b25laGFycmlzLmNvbSIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA4ODA1LCJuYmYiOjE3OTMwMDg1MDUsImlhdCI6MTc5MzAwODUwNSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkRFIiwiYXBwX3Nlc3Npb25faGFzaCI6IjhlOWQ2NDY2NDMzNzc5NGM0YTY2MGFiNjI4MDNmOTVkNGZkODliY2RiZjQxNTEyZTA5YzkwYzM1MzE4MTQyYTMifQ.gdO6fmAgIVnF3WnkNdrGmrFf4DLpQJYyFTR8KMbMJ6FiwRUAgcbjOJN5nLSwKvGsKCNf6udDXEA75-MTWH3GZxprQ4mC6iOak_Qr0osbNuZeu6d8Ut8vpPZV8Vp5EIU5uGxVQX7_6KZuLRTWh5ViAZzcuH_4Gm4So8fT4yd6A0aREHcI7TcsZ1MunZ85AzkqtKr8ar02KlGTjFIYNyvj7r0FVObZUuD2-s4JhQhhC4WqPZ8jy4raCh56UWvAQfpDhJwnHu7C-tTCmEbObBhN7rIOHJhLdhMaixuLuuQcq4rgp8TNX16umPxwinbL-Svwowa25zylDX8AG_daLEN48g&redirect_url=%2F
  baseline: 302 -> stoneharris.com
  canary  : 400 -> (none)
https://rapid-wildflower-5584.cloudflareaccess.com/cdn-cgi/access/login/coremind.tech?kid=9b5b67a62adf4df840d26281270bf94cf60ca266b4212174404d709363adec00&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OGFmMjMzMzMwYTk2ZmFjNTUzMTBhMmQyN2E2MmQ1ZWM1YWY5Zjg3ZDBhOTg5OTNhMzk0MjZlMDg1NGI2NzcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjliNWI2N2E2MmFkZjRkZjg0MGQyNjI4MTI3MGJmOTRjZjYwY2EyNjZiNDIxMjE3NDQwNGQ3MDkzNjNhZGVjMDAiLCJob3N0bmFtZSI6ImNvcmVtaW5kLnRlY2giLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwNjQxMCwibmJmIjoxNzkzMDA2MTEwLCJpYXQiOjE3OTMwMDYxMTAsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJDSCIsImFwcF9zZXNzaW9uX2hhc2giOiI2NWNhMTMzOWYyODY2YzE4NWUxMzBhZTI1ODJiNTZlNzZiYzgxYzFiNGNmYTdiNGRhYThmYjU4ZmRiMTRmOWYwIn0.CUhLewZCZfDfT3b2MtJL7xNiDhVvXT7BiYdT36TkaQi1rCnRvaX_tW0IOX1uC1NG47IoOq4GYVzt7F6jbiCR0EN_HAtMhD8AQLbcpKhGwHZZm-lSA_ezr1fZydTwugPRlI9O7msm1dl_KxRlzl_waZQeZGcJExIA7VsWuBdVmtmHajriqLez4WFFx61Uvs56Yn_ba60NR3zsbEquW1NmocU73XaHNKtM411tzzXZuRwX1VMNADMBJ-gUlZ8NGB6e1xjNrr5BkZs3oqJRbuGdMqsZnlrcXwSUYT6ZoBGZ5G8dCtkdpqROuatmq6fzM5oyGke2zC-BkUsTwItx-9OUFA&redirect_url=%2F
  baseline: 302 -> coremind.tech
  canary  : 400 -> (none)
https://squidtoshidev.cloudflareaccess.com/cdn-cgi/access/login/beholder.uat.kraken.com?kid=7d1cce887d7661b7bd00830463f64e029b6915fe5274a19d771051db6f072bdc&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjUyODk4MTU0OTVlNjZhOTFlMGUxZWYwZWY0MDU4NzA3YzFkYzU3ODAyNTg5N2VlZTJjN2I4ZTE5MWJlNGFmNzAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjdkMWNjZTg4N2Q3NjYxYjdiZDAwODMwNDYzZjY0ZTAyOWI2OTE1ZmU1Mjc0YTE5ZDc3MTA1MWRiNmYwNzJiZGMiLCJob3N0bmFtZSI6ImJlaG9sZGVyLnVhdC5rcmFrZW4uY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDc3MzYsIm5iZiI6MTc5MzAwNzQzNiwiaWF0IjoxNzkzMDA3NDM2LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiSUwiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiYzIwMjcyMWVmNTQyZGYyNzJlMDlmNjQ0MTEwNTc4OWM2NDlkZTE5YWZlZjY4Yjg4MmQ4ODJkZDljOWM3MjgzMyJ9.jZsR6HNvd1nG-JSCJhKTqWVuFEtnz-HGm3ltQrC8H9OiPlxcz5Z2I6sG2yoyHQwx_71OGG6dMOEMZrm-Zoo7Pry1lJjBm51b81sTJH2CpYy1p5o0qnBa7cqHMK7HzL84nflpkC5wK3DuPZ5eEU25TNPIW6FdwSz1K-pPcQHTlr630-SLauuQ7zeMw0MFZ0J-ZPLxnQFNdIigJV5vdCIGD-cHuLF0EYv8_kKjFQ0cM9xCKIVg7YxtDPEbpFEr6E0vySpQXhl9_pcKsGzWoX3m4g1LbTwGUqbAGGvsVBDg4BA3zWEuc-BHjfksgCm6fKMT5gtd6q3K5piDyBP-4wqF1A&redirect_url=%2F
  baseline: 302 -> beholder.uat.kraken.com
  canary  : 400 -> (none)
https://squidtoshidev.cloudflareaccess.com/cdn-cgi/access/login/beholder.dev.kraken.com?kid=9a556391c7d0b6ff30ea44b9c8035f249e7e64d8fd0f796859db530ea34006a5&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjUyODk4MTU0OTVlNjZhOTFlMGUxZWYwZWY0MDU4NzA3YzFkYzU3ODAyNTg5N2VlZTJjN2I4ZTE5MWJlNGFmNzAifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjlhNTU2MzkxYzdkMGI2ZmYzMGVhNDRiOWM4MDM1ZjI0OWU3ZTY0ZDhmZDBmNzk2ODU5ZGI1MzBlYTM0MDA2YTUiLCJob3N0bmFtZSI6ImJlaG9sZGVyLmRldi5rcmFrZW4uY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDcwNjksIm5iZiI6MTc5MzAwNjc2OSwiaWF0IjoxNzkzMDA2NzY5LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREsiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiYWZiYTg0OTU0YjUxNTY4YmE3YTdkMjI1NjBjMWE4MzJhZjk0YmJhNDk3NTg4MWZkNGZkM2U5NjhlNmFhOTdmOCJ9.TSoumzUH1VIjOZTARghMevLYk4nt7xRe5TsiVc2wI1_FGec01vpTd8SGDWZpETe1a2quZpF7iHnWEJKnSgyxD329nIqVUuOhzv1uLapi6UBn3RIso89dszGm7dOAZ3FZwMfxbTayOZAXOZM4vbTRHRcy9YgcfCesNOQiUg3CBz84GXwo6tkojZAugceYLSWEEUUI-btbEr4B5AZXXxKtCnBm-go0C0BQfMA01dJKTCJHCJ3Y3eiOk1--uDVoivoDTIUu7SBTj_xjwWYCahtGY8hn1sR-W6FmYhzMPMKbngHeoer_PGwu7MmcHWrGuJEu-ITUk5yok-LFXMZLF8YPGA&redirect_url=%2F
  baseline: 302 -> beholder.dev.kraken.com
  canary  : 400 -> (none)
https://shrill-haze-0631.cloudflareaccess.com/cdn-cgi/access/login/clients.sixfiveapps.com?kid=e43595dea4ce514b055af1d66bbae68aaaefa57367d62d8320c6e83a9723c3b1&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijg3MTc5ZmI4ZTQ0MTY5MGMxNGU1MWVkYmIxMDlhM2M4YWIzZTJjZjhmZjhhN2ZhODc2MGM3YzQ3NzM5ZTU1MWEifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImU0MzU5NWRlYTRjZTUxNGIwNTVhZjFkNjZiYmFlNjhhYWFlZmE1NzM2N2Q2MmQ4MzIwYzZlODNhOTcyM2MzYjEiLCJob3N0bmFtZSI6ImNsaWVudHMuc2l4Zml2ZWFwcHMuY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDczOTMsIm5iZiI6MTc5MzAwNzA5MywiaWF0IjoxNzkzMDA3MDkzLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiRVMiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiN2E5YTEyNjJiMzA5ZThkZjdjYjJmNTRhZjY2NWM5MmNkMTVkYjIzYTRmNWFhMDgwZjEwMjU4ZjFlZDZkMTBmMSJ9.QK6ss5FjRVnWoy_4kiwrQoqc7l1W1Oiezc2_ptUwX1yCwbrN2ddDNfN3n6T1hHMZI5GvaUUx99kloe9c0Sjh5rPgivjO9-A5kE3L7Sgigs3lbwCjPa0h-E2D5WmtKceSuNUkbutB8103_zlMw4KN6OPwablv6enD0qSj2sTqNd8tAAqheXw_oi3gtvvx14vYYkq1HGqnaogWNKiGBvv8WOliXIzU51-uyVpcoOJ7NoIQCzGCxWx-8WnmLAa9QbxETfTef3eHCCGQFeR5XWgcWTDiW31AzOpot15tv-dIF0kFt8T20PXeqJgOZlSlJKFcxdzOUiYQk5qhvTzFzlPFTA&redirect_url=%2F
  baseline: 302 -> clients.sixfiveapps.com
  canary  : 400 -> (none)
https://tight-firefly-a2cd.cloudflareaccess.com/cdn-cgi/access/login/app.schwabmeat.net?kid=4ef5f921fb00dc75a797f296ad2e81ab4215688df7aaf3c512b94a51458a1d61&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImExN2VmYjIyYTM2MDFlZWZiNzg2OGM5NDhkZmEzMjgxOGEyZjk4MTczMDBhMjI3ZTYzYWJkYzg5ODcyMWU4NTgifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjRlZjVmOTIxZmIwMGRjNzVhNzk3ZjI5NmFkMmU4MWFiNDIxNTY4OGRmN2FhZjNjNTEyYjk0YTUxNDU4YTFkNjEiLCJob3N0bmFtZSI6ImFwcC5zY2h3YWJtZWF0Lm5ldCIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA4OTQ1LCJuYmYiOjE3OTMwMDg2NDUsImlhdCI6MTc5MzAwODY0NSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkZSIiwiYXBwX3Nlc3Npb25faGFzaCI6IjgzZDE5OTNmYjBjODI1NTE0OTMwY2M3NTEzNjQ2ODdmZjcyMGE1MDJkNjY5ZWFmNzM3MTg3ZmVmNDVlMzFiOTYifQ.m_IzCyEm7Are2fWejHZLIGz7MmGziUsAnlbJ10QEx-dpOCspJ08um7mPvsOjg_T7T4_blVJXboEIUC5E4Zfn2xoHJwTWlYbW4k5rs0YDjBkYnfFOF0090rvtgdPnIxmzXxlAZsc_cOcbH9LT-fayhDMyjzO2NFSnAe0_YAlQOUln8JrZVbh4wbhhg5YpsNW0IoGmva8eJ5tlbXLOkVcBHh_ajSW91UG1U6ps4Uou_9wtik0RjR1_Wy-B5DSMguZea3SQdqzU-bN1CExNVtTWF5e96x4ntNsFIEGh-GugceX25Gu8WXrw7HYvRqaVBOimAIV-x_qtuSCGvzRUYuFyvw&redirect_url=%2F
  baseline: 302 -> app.schwabmeat.net
  canary  : 400 -> (none)
https://watchdogsecurity.cloudflareaccess.com/cdn-cgi/access/login/app-dev.watchdogsecurity.io?kid=e7388b9dfd017bbfc5cd2ea974115fb861cafaedfd90b93d5899011e8338c121&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJmNGM5MTJlZGI1NGI4ZTZlZmZjMGU5ODUxYzIyMGZkNjRiZTY1MDZkYzU2NTMzMTk5YTA5ZmE0MWM2ZjI4ZGIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImU3Mzg4YjlkZmQwMTdiYmZjNWNkMmVhOTc0MTE1ZmI4NjFjYWZhZWRmZDkwYjkzZDU4OTkwMTFlODMzOGMxMjEiLCJob3N0bmFtZSI6ImFwcC1kZXYud2F0Y2hkb2dzZWN1cml0eS5pbyIsInJlZGlyZWN0X3VybCI6Ii8iLCJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlzX3dhcnAiOmZhbHNlLCJpc19nYXRld2F5IjpmYWxzZSwiZXhwIjoxNzkzMDA4OTI1LCJuYmYiOjE3OTMwMDg2MjUsImlhdCI6MTc5MzAwODYyNSwiYXV0aF9zdGF0dXMiOiJOT05FIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX2RuIjoiIiwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9za2kiOiIiLCJjZXJ0X3ByZXNlbnRlZCI6ZmFsc2UsImNvbW1vbl9uYW1lIjoiIiwiYXV0aF9zdGF0dXMiOiJOT05FIn0sInJlYWxfY291bnRyeSI6IkFUIiwiYXBwX3Nlc3Npb25faGFzaCI6ImVmYmUzY2U1ODUyYzhkMjQwNWQwYTI0M2NkMGQ4OTc3Njk2ZTVmZjExZDU5NDhiYzk2NmM3MTI3MDQ4NWViZWYifQ.PI0OONVjSKE4ecPlCa01BNMbFwlhWe8ieCNupOxIuhjQ5WvV8E4CvJTipw2gWOErQOBvGnzMvrbjc5ezKij8_rQIAJXMymoHBmWX1gVCQ2sqC8yjhLFLFyoB1OUrw0deC1e_rJZIGZWIooFY6OIO-vkCKkQwFIsp0KYrh_zcvycrh0TJaldB2kpOl2KvjT1fu9runfGWes8mflD0uYSU8wSaJPKhIeKNjMjhk80ni6_rlwltotQTObHgGLOwWPgYVJILZF6OPfBeTM6zVfmT38hgsuzvTuctD0WG_teHWoGJkpmVMEry0LItm8Fbfgz1hnTxsIiHIl4cVaGGK3VrwA&redirect_url=%2F
  baseline: 302 -> app-dev.watchdogsecurity.io
  canary  : 400 -> (none)
https://stargen.cloudflareaccess.com/cdn-cgi/access/login/track.kamstar.net?kid=95f8f0a906db9f066c5ab074d678c1692f0032de43c0d23f8105031bc4e90be0&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjAyMTMzNDM1MmZlNmQ4YmYzODY2MDE4YzQxYmM1ZmJmMWExYzljNTZiMTIwNDkyYTQ3ZjMyYmVhNGQ0NDc1YWIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijk1ZjhmMGE5MDZkYjlmMDY2YzVhYjA3NGQ2NzhjMTY5MmYwMDMyZGU0M2MwZDIzZjgxMDUwMzFiYzRlOTBiZTAiLCJob3N0bmFtZSI6InRyYWNrLmthbXN0YXIubmV0IiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDY4NTEsIm5iZiI6MTc5MzAwNjU1MSwiaWF0IjoxNzkzMDA2NTUxLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiVVMiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiZjY3OWQ0Nzc2MjRiMThhNmVmZTZiZjRjN2VhZTM1YWVkMjljMmVjZjBjOWMzZTBjNTkwMGE4NGU3NDM3NTNhZCJ9.AdRQbre4V8rLq39hRjqEbXu9hies3nRpVrexb_sOvvq4F7OwVzjtjDpoUYtVDoESDZVIuJPGRiFIqeeZb7Io7lQZJXGTn6gv4LvCD6U8rFK2nriePtE80BAgYCnVrVwCGfzEsHS6Y7s4em1yjCTBtmTCY_yjZPL6Wv4lH3SIoo7pqEpOs6st0Iysx5QmOQWSX28zcOKUN2yUJjvM21nhhf-huTj4XKF02SSuMnrSU3IhzPeZ8_dWIAlwyFA9oOwCtmkx9J3uKdCVvu6JWuI_c61jEs3MDjo_-cd9xhXPxLxiiNBHr7wGVeInBuIl0mCGUk1XgDpTfcma5faKGEqfOg&redirect_url=%2F
  baseline: 302 -> track.kamstar.net
  canary  : 400 -> (none)
https://watchdogsecurity.cloudflareaccess.com/cdn-cgi/access/login/dev.watchdogsecurity.io?kid=e7388b9dfd017bbfc5cd2ea974115fb861cafaedfd90b93d5899011e8338c121&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJmNGM5MTJlZGI1NGI4ZTZlZmZjMGU5ODUxYzIyMGZkNjRiZTY1MDZkYzU2NTMzMTk5YTA5ZmE0MWM2ZjI4ZGIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImU3Mzg4YjlkZmQwMTdiYmZjNWNkMmVhOTc0MTE1ZmI4NjFjYWZhZWRmZDkwYjkzZDU4OTkwMTFlODMzOGMxMjEiLCJob3N0bmFtZSI6ImRldi53YXRjaGRvZ3NlY3VyaXR5LmlvIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDg5NjEsIm5iZiI6MTc5MzAwODY2MSwiaWF0IjoxNzkzMDA4NjYxLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiN2IzOGJmMmRiYzg3OTQyODViOGUzMzFlNzRkN2IyMDNhNDVjYzA0YjI4OTdmMjZlYzRlNTE1M2VhMTgwMGJhNiJ9.jNEP6966TtOGAcDxNFTN3p6treilpN-15M1LtZRolFDbmGwGG-4GaGolj_GgtjOgFap0V12AojkQrQO0F_6gjTEMy27DIUHPuVjZ0BRNie0m8NVwuqekDDfQ_6DvAvCTfprZn3pqAg2nylUhHFGPaYbnGYFoWQYGhM-JAwALMb36DEW_tpdB6i37utO-rUO1lt5uP39yYY_H0GWq7yKXmQTArmmu_WsfPByMhIUZX2wBvLcjQXingPTP7HLQ1l1w5zM6sMRFJKvGTA1rn5iIZXbIlO-B15X6a6ox6ZVaUFNzyZAkqPV0JBzaKInWDRNKM5rCPyJWsuc-aIfWOm_VvA&redirect_url=%2F
  baseline: 302 -> dev.watchdogsecurity.io
  canary  : 400 -> (none)
https://wonderfulai.cloudflareaccess.com/cdn-cgi/access/login/demo12-claims-review-demo.bo.wonderful.cx?kid=79d502c54e87775c7f358dc2576c6c94aff9ac22ae7fece2a62af5a7e5dabefc&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijc5YWNjYmQ0Zjk0Mjg2OWQ4ZjAyMzJhYTcxMzQ2OTg2ZTk4ODU1OGI4Y2Y5ODhlYzU2YzYzMmJjMTExMTY4N2EifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijc5ZDUwMmM1NGU4Nzc3NWM3ZjM1OGRjMjU3NmM2Yzk0YWZmOWFjMjJhZTdmZWNlMmE2MmFmNWE3ZTVkYWJlZmMiLCJob3N0bmFtZSI6ImRlbW8xMi1jbGFpbXMtcmV2aWV3LWRlbW8uYm8ud29uZGVyZnVsLmN4IiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDc4ODksIm5iZiI6MTc5MzAwNzU4OSwiaWF0IjoxNzkzMDA3NTg5LCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiREUiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiOWYwNzBhZjFlMzY2ZDUwYjBhOTJmZjY0OGFiM2ZkYmVhZTQ2Njc5MmJkYWI0NjBkM2ZjMDE2M2NiZTRmODA0YyJ9.LJ_M5oebMhVsuoglW5-J-xaRZf7mSvntsIxcnPxWHvu_YhxireKYLoRTCdqHtbIYGiUxu72KN1m4SzO536l92NpG1JcEY_iiKc_9EQNMfOqqBbgAHkrGckhDvHZH3FmKM5h1qwwSZMfFyZZX4HHhw-6VPCZCr2TDz2FH5jchoVWuKLkw8Uafb2XQMYzq8MFpLDA4xvDrFGLwl7qXxjtA6ksZhn2Rzt4h4DJ76baW9v6jtzmYGifjWsKZuBLi7xO3MMnYMMLXvEHKXs2ECr-kuA1wrP0qgHCDKLpTgqEcS12tPqjjKjV-9-Ri5eISc99c9xA7K_k-jvC_Py_LSZn1LA&redirect_url=%2F
  baseline: 302 -> demo12-claims-review-demo.bo.wonderful.cx
  canary  : 400 -> (none)
https://winter-forest-16d1.cloudflareaccess.com/cdn-cgi/access/login/paxmoneta.com?kid=74cab9c778420bf0bf55d90d8f13a5f5425d80a49298b1e220a37fa39939862f&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OGFmMjMzMzMwYTk2ZmFjNTUzMTBhMmQyN2E2MmQ1ZWM1YWY5Zjg3ZDBhOTg5OTNhMzk0MjZlMDg1NGI2NzcifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijc0Y2FiOWM3Nzg0MjBiZjBiZjU1ZDkwZDhmMTNhNWY1NDI1ZDgwYTQ5Mjk4YjFlMjIwYTM3ZmEzOTkzOTg2MmYiLCJob3N0bmFtZSI6InBheG1vbmV0YS5jb20iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwODMyNiwibmJmIjoxNzkzMDA4MDI2LCJpYXQiOjE3OTMwMDgwMjYsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJJTCIsImFwcF9zZXNzaW9uX2hhc2giOiJhOThhN2E4OWEyYWE4ZTUxMmZhOTlkMTdhYTMxNTAxM2U2NzBiMzYxMzhhNGUxOTgyZmYyYjc5MjZmNGUxNWNiIn0.HZcMWUeB6GPEr9s4FRu4ndO8IjA5WRG_dK8usHGp2-4yLznQi6VzMMaW8Z9h-JLzg_KUoE6_YaoJfaeciN6gWoqta8JeVUP5CkipOTU7SU0ZLp3VGjOsjt_DuSLqjOEh8sU2yb1EGFTezAemyBCSzoX3NQvOAwQlnmO2plBcVeRsUzVuAzQmSujgVd6BOtz5NPBGTmt9w2-U5pI7obAOqepy3IExl-vIDg2LSRxOTwOMv2Y358ig99vdhYxkT_ev5ivGvPrSWFeDRU1hNj1m-Kwfc5Es7wHRosJkGZzuY5N8hLTHgzc1-uHm2d6IGTajNqN8O7kWwD-jqFx-RkHupA&redirect_url=%2F
  baseline: 302 -> paxmoneta.com
  canary  : 400 -> (none)
https://watchdogsecurity.cloudflareaccess.com/cdn-cgi/access/login/app-staging.watchdogsecurity.io?kid=976b1c9189fce6eb74ac94f13d288e20e35e142db185fc4020055a54c5b1a908&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJmNGM5MTJlZGI1NGI4ZTZlZmZjMGU5ODUxYzIyMGZkNjRiZTY1MDZkYzU2NTMzMTk5YTA5ZmE0MWM2ZjI4ZGIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6Ijk3NmIxYzkxODlmY2U2ZWI3NGFjOTRmMTNkMjg4ZTIwZTM1ZTE0MmRiMTg1ZmM0MDIwMDU1YTU0YzViMWE5MDgiLCJob3N0bmFtZSI6ImFwcC1zdGFnaW5nLndhdGNoZG9nc2VjdXJpdHkuaW8iLCJyZWRpcmVjdF91cmwiOiIvIiwic2VydmljZV90b2tlbl9zdGF0dXMiOmZhbHNlLCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsImV4cCI6MTc5MzAwOTA0NCwibmJmIjoxNzkzMDA4NzQ0LCJpYXQiOjE3OTMwMDg3NDQsImF1dGhfc3RhdHVzIjoiTk9ORSIsIm10bHNfYXV0aCI6eyJjZXJ0X2lzc3Vlcl9kbiI6IiIsImNlcnRfc2VyaWFsIjoiIiwiY2VydF9pc3N1ZXJfc2tpIjoiIiwiY2VydF9wcmVzZW50ZWQiOmZhbHNlLCJjb21tb25fbmFtZSI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJyZWFsX2NvdW50cnkiOiJERSIsImFwcF9zZXNzaW9uX2hhc2giOiJhMGFiOTY0ZjA0YTI3NGZhMzBlOWVjOWMwOWI1ZjZmYjU0MTdiZjM1NmViOGM3Y2QyMDVmZTdjMDJkZjlhZTU1In0.CRxkVyYsUIWU7H7ArMI-gXaVmMCUZVMm0bAjGzOCiqc7VhFa9Z46aRgPZSxV287Fs1d1Kx2ii637SOlj4mn2-9-oHEXU0jy1HVNaInkV2ojQpyB4uYhBI3vAgjTNUE_2dQsOANaIfqTO5PnG6hcCIUYdXDZxYKB6kCQrHXz50wRghqQkcUW9XoGBjbQp88WHNai_gwAk8S_UhN0IX503yfl1UGPHTSkOPendEK-Us_Vj880aGJjw47q3VHTexI4wihYQ62suHhlG1NDVmn4vvaNP10Vbt2k1lwWP1vgtTKxhW9NlroBIb8aYISt-3TuctIg78fkN2hXbAm41CcWEcA&redirect_url=%2F
  baseline: 302 -> app-staging.watchdogsecurity.io
  canary  : 400 -> (none)
https://woolichooks.cloudflareaccess.com/cdn-cgi/access/login/tracker.woolichooks.com?kid=a1b9f8095db801f5b78bb58dc29c72f32f451df699d9b55a1fcd0e3e7fb5d1c7&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4M2EwZDVjY2Y1NTZlOTA4ODBiYWRlY2ViZDg0N2QyYTgwOGQyODExYjBhOWI5NjcwMmFlMDRiZDBkZWQ5MGIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6ImExYjlmODA5NWRiODAxZjViNzhiYjU4ZGMyOWM3MmYzMmY0NTFkZjY5OWQ5YjU1YTFmY2QwZTNlN2ZiNWQxYzciLCJob3N0bmFtZSI6InRyYWNrZXIud29vbGljaG9va3MuY29tIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDcwNzMsIm5iZiI6MTc5MzAwNjc3MywiaWF0IjoxNzkzMDA2NzczLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiUEwiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiYzkwYWQ1YjY2ZjMxNzdmZDI0YWExMjczMTdmMmM2M2VmYTg0NzE3OGMxZGExMTdmMGFlMTY0YWFkMDA2MDMxYiJ9.mIAWgL79SJjAMbv9NbLyyhlStOnyV8jfotkHnCoHFaGUYMATjd3NRIEzbReVhHKI_RmRl-NoqBHbIh8EJiq0lk_bfiYM2kJAQehSs8xMDEl7_cCITMEQ19P1taA0QOoQVfuGqzeWmL5yjzXkOVoc5P5cvqe7i5ohzZBK12UeDLL90TCDeHENflwuZgqehKmQ5d1DKcNxYlLqnQKOVzJov3Y86uE_21FOKsE58SiMYCj1ucKj5XhZ0UPkriFn7P6JQHEsPcMaLSeAyHF3ptMU2rmt_FW-BFeKVzHln30azB6Gdptl77jUMgpeDiMd1YnTIaFWYuVGqR_S3DHavXCfQg&redirect_url=%2F
  baseline: 302 -> tracker.woolichooks.com
  canary  : 400 -> (none)
https://young-king-c7a5.cloudflareaccess.com/cdn-cgi/access/login/www.fensumo.co.uk?kid=675e568bec5a7cf2bae8a57fd381e2d66fef03bd41f9a1bc60aaa8d8c305630e&meta=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImFmZmUxMzhkYTE5YWUxZDQ0NTJlMWViNmUzM2ZiMDA0MzI3NmI3N2I5MWEwYzA0MWQ0MmI4MzZhODFlNWNjYzIifQ.eyJ0eXBlIjoibWV0YSIsImF1ZCI6IjY3NWU1NjhiZWM1YTdjZjJiYWU4YTU3ZmQzODFlMmQ2NmZlZjAzYmQ0MWY5YTFiYzYwYWFhOGQ4YzMwNTYzMGUiLCJob3N0bmFtZSI6Ind3dy5mZW5zdW1vLmNvLnVrIiwicmVkaXJlY3RfdXJsIjoiLyIsInNlcnZpY2VfdG9rZW5fc3RhdHVzIjpmYWxzZSwiaXNfd2FycCI6ZmFsc2UsImlzX2dhdGV3YXkiOmZhbHNlLCJleHAiOjE3OTMwMDc4NzMsIm5iZiI6MTc5MzAwNzU3MywiaWF0IjoxNzkzMDA3NTczLCJhdXRoX3N0YXR1cyI6Ik5PTkUiLCJtdGxzX2F1dGgiOnsiY2VydF9pc3N1ZXJfZG4iOiIiLCJjZXJ0X3NlcmlhbCI6IiIsImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY29tbW9uX25hbWUiOiIiLCJhdXRoX3N0YXR1cyI6Ik5PTkUifSwicmVhbF9jb3VudHJ5IjoiU0UiLCJhcHBfc2Vzc2lvbl9oYXNoIjoiMGZiNjc0NmI1Yjg4Mjc4MzYyZGFlOWFkYzQ5YmMxMjc0NjdmZmIzY2QzZDYyN2MyNzM3NTEyOTRhN2EyNzc0NiJ9.FqmmS5PxDJLPPRQSa7YqVDyNz_z3kTS5OaB8NaGRmnp1oMSCUr0elpUww5EeUYiY7TY93Dn__G-6w5nwIWCpiwSBthItPCXeBK3SM-ccsZVRzS7_G-PWi9ytkUI6Pb1W6I1ToL1VRnmLF6J9uKi1KJqmY-yTVEAvEoS1VuqiedIaUAJkWOik3LfCwZWyGLEat83imkqRBuSAAVwaBb4J00YuHlLI9lue0Y1q32kAaekWLJKSfrAOUFa9zhUrQt5MyU7olpu7mxm6Wco6VgrBmeahV6aOxlRlsJ3GQbZKir9IKzj3PJOD3RQ0v1BQa_c9MLFXG3BJoNVzIpBsc0fr4A&redirect_url=%2F
  baseline: 302 -> www.fensumo.co.uk
  canary  : 400 -> (none)

### hackerone / Spotify — 41
program: https://hackerone.com/spotify

https://accessibility.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Faccessibility.spotify.net%2F.env&IdP=http%3A%2F%2Fwww.okta.com%2Fexk9hq5vfzXYBHwPf1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://ads-preview.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fads-preview.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexkonq0xkhkFJ7Gsz1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://av.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fav.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5as17zi90SpYaO1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://amplifier.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Famplifier.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5aqir06rLQyyR01t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://ar.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Far.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5aruqy6gqMtjku1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://analytics.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fanalytics.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5armcwjpTVYLgW1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://blogit.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fblogit.spotify.net%2F2017%2F08%2F24%2Fsdet%2Dat%2Dspotify%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5as5asnJRiRJIA1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://confluence.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fconfluence.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5ard95aLEC9fBh1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://crema.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fcrema.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arulenzzsqjQc1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://creatives.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fcreatives.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arzvkzhBJUidr1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://cs.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fcs.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk77kh9k8B9uZNxd1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://experimentation.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fexperimentation.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk6n286pn2qGLpc01t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://design.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fdesign.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk7pynjrsTzg9BOO1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://encore.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fencore.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk9y60imqn8fJpsR1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://fraud.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Ffraud.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk87siwtw09r9FW51t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://goldilocks.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fgoldilocks.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexkatd1rwcf9BrM5J1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://glue.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fglue.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arkps7ilQJDyY1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://gwsa.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fgwsa.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk7dr5x3jtlwouqb1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://hackweek.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fhackweek.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5aqjrf3IkUuchd1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://innovation.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Finnovation.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arhefzChArHkA1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://hris.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fhris.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk6eo83z71yxLUsw1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://hr.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fhr.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk9i42xdrb5nAH1X1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://insights.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Finsights.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk6eo6xsyQVNfsnh1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://it-support.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fit%2Dsupport.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arrd8eCivurqr1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://intranet.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fintranet.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk6eoa2pqszcUIB61t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://ios-employee-build-redirect.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fios%2Demployee%2Dbuild%2Dredirect.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexkacvo8bep7O4UfP1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://it.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fit.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arj0mpBOfMcrp1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://legal.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Flegal.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5aqir74RY1bB731t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://key.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fkey.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5armcie3EiXcf11t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://nda.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fnda.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arc0e9zQ7S3eQ1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://netsuite.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fnetsuite.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5aqiwp3eXxHdWb1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://oldintranet.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Foldintranet.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk79lrqldMSujWSY1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://platforms.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fplatforms.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk7mb034qIiMM4uJ1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://patent.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fpatent.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arigydlAUvIDE1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://po.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fpo.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5as09i45Aslzax1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://security.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fsecurity.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5arkfm1xSZLVHj1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://search.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fsearch.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5as3k8vVP9Nptb1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://springfield.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fspringfield.spotify.net%2Frobots.txt&IdP=http%3A%2F%2Fwww.okta.com%2Fexk9yaaxkysC7fsQ61t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fspotify.net%2FAuth0%2FAdrianaMedia&IdP=http%3A%2F%2Fwww.okta.com%2Fexk6vfwgijPqP7VZg1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://start.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fstart.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk5argw4hbFSwpQl1t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)
https://writing.spotify.net/mellon/login?ReturnTo=https%3A%2F%2Fwriting.spotify.net%2F&IdP=http%3A%2F%2Fwww.okta.com%2Fexk9hq4izwdhS9yQ41t7
  baseline: 303 -> spotify.okta.com
  canary  : 400 -> (none)

### hackerone / Ping Identity — 33
program: https://hackerone.com/pingidentity

https://auth.pingone.com/5303eaca-978f-46c9-9db2-c74521c4075f/davinci/policy/1b818cff4b9d8d863b09c0d6c6ed9893/authorize?client_id=d762c769aca4042099de8aab4ab6ffdf&redirect_uri=https%3A%2F%2Fauth.pingone.com%2F5303eaca-978f-46c9-9db2-c74521c4075f%2Fdavinci%2Ftestrp&response_type=code&scope=openid
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/5303eaca-978f-46c9-9db2-c74521c4075f/davinci/policy/e3b0fb37e716150a5a60f8231302fe4f/authorize?client_id=d762c769aca4042099de8aab4ab6ffdf&redirect_uri=https%3A%2F%2Fauth.pingone.com%2F5303eaca-978f-46c9-9db2-c74521c4075f%2Fdavinci%2Ftestrp&response_type=code&scope=openid
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/4c706495-83c2-46eb-b1bf-31ac1380d9a5/davinci/policy/43bd0b33f5b4dfe6d848769dc0ba62b0/authorize?client_id=1035c99d35fd412571183938fe59fa7d&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fgrs.apps.gcpsk12.org&flowType=Account+Activate
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/5303eaca-978f-46c9-9db2-c74521c4075f/davinci/policy/565080a5f9166702867f1edb9e9df218/authorize?client_id=d762c769aca4042099de8aab4ab6ffdf&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fauth.pingone.com%2F5303eaca-978f-46c9-9db2-c74521c4075f%2Fdavinci%2Ftestrp
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/89f2ffa0-b606-4ba2-9649-290e20944e5f/davinci/policy/08f587f8b517ae3109edf863fdc97800/authorize?client_id=6dd6cbd8160b5b3e5dbacf4ea4fdd3e2&redirect_uri=https%3A%2F%2Fauth.pingone.com%2F89f2ffa0-b606-4ba2-9649-290e20944e5f%2Fdavinci%2Ftestrp&response_type=code&scope=openid
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/89f2ffa0-b606-4ba2-9649-290e20944e5f/davinci/policy/4851e45c9e94de6e8a237c392459d54d/authorize?client_id=6dd6cbd8160b5b3e5dbacf4ea4fdd3e2&redirect_uri=https%3A%2F%2Fauth.pingone.com%2F89f2ffa0-b606-4ba2-9649-290e20944e5f%2Fdavinci%2Ftestrp&response_type=code&scope=openid
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/89f2ffa0-b606-4ba2-9649-290e20944e5f/davinci/policy/21df618f01be6b489f0faa071565978c/authorize?client_id=6dd6cbd8160b5b3e5dbacf4ea4fdd3e2&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fauth.pingone.com%2F89f2ffa0-b606-4ba2-9649-290e20944e5f%2Fdavinci%2Ftestrp
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/dd073de0-0b96-43b0-9611-4e26b10dd00c/davinci/policy/6b17c0a539d93eca84ba1ead91353147/authorize?client_id=d77fb10ef6ebfb5babf12d961e1063e3&redirect_uri=https://auth.pingone.com/dd073de0-0b96-43b0-9611-4e26b10dd00c/rp/callback/openid_connect&state=0095c990-90f0-4f54-9853-adf0eb216624&response_type=code&scope=openid%20profile&nonce=0095c990-90f0-4f54-9853-adf0eb216624&transactionId=b3b11ace-762f-4f25-a3d0-447897e757ac
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/f96b6920-60b8-4fc0-9b8c-8e99855e51aa/davinci/policy/2828006bb76eee5fd5ee033bbb86f734/authorize?client_id=6b89f3bfe6e60d68ca3c51fb7191cc5a&redirect_uri=https%3A%2F%2Fauth.pingone.com%2Ff96b6920-60b8-4fc0-9b8c-8e99855e51aa%2Fdavinci%2Ftestrp&response_type=code&scope=openid
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/f96b6920-60b8-4fc0-9b8c-8e99855e51aa/davinci/policy/3d98b129537e6635d7e147bdd8abd2b2/authorize?client_id=6b89f3bfe6e60d68ca3c51fb7191cc5a&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fauth.pingone.com%2Ff96b6920-60b8-4fc0-9b8c-8e99855e51aa%2Fdavinci%2Ftestrp
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/f96b6920-60b8-4fc0-9b8c-8e99855e51aa/davinci/policy/067d1a15e10791140956fb0e77f2bb1f/authorize?client_id=6b89f3bfe6e60d68ca3c51fb7191cc5a&redirect_uri=https%3A%2F%2Fauth.pingone.com%2Ff96b6920-60b8-4fc0-9b8c-8e99855e51aa%2Fdavinci%2Ftestrp&response_type=code&scope=openid
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://auth.pingone.com/f51642b1-1e0d-4d1e-bbd1-73a35798b3cd/davinci/authorize?client_id=138ad816375cc81e55e4f10052e56828&redirect_uri=https://auth.pingone.com/f51642b1-1e0d-4d1e-bbd1-73a35798b3cd/rp/callback/openid_connect&state=034369c1-bb29-41d4-b39b-83e933be9238&response_type=code&scope=openid%20profile&acr_values=policyId-f866a3f18bb287baa97f2f0ba58fd1d1&nonce=034369c1-bb29-41d4-b39b-83e933be9238
  baseline: 302 -> auth.pingone.com
  canary  : 400 -> (none)
https://login.pingone.com/idp/directory/a/5ed69ab8-fa98-44cc-9b40-836014c9af74/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI05PqaavCNcfHKnRO8ptaaaUc31S-4KNltCEAcEHAoUnAGHijNIVeXqqw06JSh%2F&useragentid=8ec626c9
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/641c80ed-d432-4d49-90c6-46bb1a196f07/adpwdchange?useragentid=12fd8528&returnurl=https%3A%2F%2Flogin.pingone.com%2Fidp%2Fdirectory%2Fa%2F641c80ed-d432-4d49-90c6-46bb1a196f07%2Faduserlogin%2F%3Freturnurl%3Dhttps%253A%252F%252Fsso.connect.pingidentity.com%252Fsso%252Fopentoken%252FI03YCKFTbGbhTDcusl9DbiwPl_oe98AeGUs6XlnuBZXV5sAfv8efaHZ2Hg_qI7%252F%26useragentid%3D12fd8528
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/641c80ed-d432-4d49-90c6-46bb1a196f07/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0NJAt62rQEUKGWnJFAxdVzRVIyf9sc7Vfxr0Noftrdkd1JkXFKNlmh4qzXRzF%2F&useragentid=ce216dd8
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/62ca5e44-f29e-492f-91d7-712de75ec76f/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FIDbd562519a1334457c43698ec9642a595b783f98b4bcce02103%2F&useragentid=deb3bfa0
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/6a195f09-37f6-4db4-a591-254266608696/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FID0ac648d816a32c6e5a3370059d79f579b5d37999472d683d0300000163e384a3c4%2F&useragentid=b874b8a5
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/08ba9398-307c-4e94-b750-4f7639a6e165/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0x2uDUHrEjAy7IaFJT_usvGKmM-rEj0fsANMxTtIC1OiFdgyQKkRYUqNtViF7%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/38605767-2435-4ee6-a99f-4aec4fa4fa30/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FID8a0631569663565db72b46a5e97d03fb74f213694a345e6603%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/1df9f7fb-2a55-486d-bf23-6269d96a9488/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0C6gCTdZqdfjQSOAow22BjpXWnGHEit-SKtbcqN7l4gJ9F6sQND87mYAr4wKf%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/75cbbd10-f3cb-489f-bfbe-875a78bf8d54/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0s2iZkGiQ_jFwH1vAIvwinfR3OemJyK0bltQZJdQ9lt-dzKdlhDCHHLZBanC3%2F&useragentid=725c7f2c
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/7b8c4ae1-f6cc-4225-8a01-82afc12568fa/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0P9BUVqBqrsc91447-cJGYgvjioXUp6ypF1kNaUHFemgwrxjATgoYiNIOyNwy%2F&useragentid=237fa726
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/7b8c4ae1-f6cc-4225-8a01-82afc12568fa/adpwdchange?useragentid=c5be4fdf&returnurl=https%3A%2F%2Flogin.pingone.com%2Fidp%2Fdirectory%2Fa%2F7b8c4ae1-f6cc-4225-8a01-82afc12568fa%2Faduserlogin%2F%3Freturnurl%3Dhttps%253A%252F%252Fsso.connect.pingidentity.com%252Fsso%252Fopentoken%252FI0wDCoU268OjKzkGP70dsEAc21kB1cHjjr8yKuiWgF1hjvaSl1GErzfDE2cQwF%252F%26useragentid%3Dc5be4fdf
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/62c86e6a-888b-4c2d-9728-e2ac8bf7498c/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FIDacb8fd38b0dd998e0088935a04869812f4044dae111ad4fe03000001640b94a782%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/939f1379-7d43-4a81-97c9-8444a1549973/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0Lcbo31klQmbSIyysUQJCI3ugXUx056jZAtuXFzCd66K38zff5wDBBAiLmIpi%2F&useragentid=268abc53
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/7ac8616f-6c23-4857-97a1-dba95d3bbdfc/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FID606db5897c08dd8ac3ae0f9d6a6ee31bea5e64c5ace77c230300000164b86b63fb%2F&useragentid=bdac47ff
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/cf285737-5e52-4afd-b526-8740c0c947e6/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0v-lFvwU67p1cgP_xOomYlIVSfKUeCP_iLExqwnhfHIuOXEDp6MnhB_s6Y6VT%2F&useragentid=ddcc88fa
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/e3575f97-fcb8-4599-8eaf-c22eef472da1/adpwdchange?useragentid=f514da69&returnurl=https%3A%2F%2Flogin.pingone.com%2Fidp%2Fdirectory%2Fa%2Fe3575f97-fcb8-4599-8eaf-c22eef472da1%2Faduserlogin%2F%3Freturnurl%3Dhttps%253A%252F%252Fsso.connect.pingidentity.com%252Fsso%252Fopentoken%252FI0XxJG14nWVRlQBy3G9oBn04sX0f5oCGBDT_NDSFAYXbi6nOpQjl93Urc3pt2F%252F%26useragentid%3Df514da69
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/672003eb-85b1-448e-9065-0c705bc35f18/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FID12e2a4e10e87c0101b85d0c1b6ef3b29b14a385cac6648d403%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/e3575f97-fcb8-4599-8eaf-c22eef472da1/aduserlogin/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0T8jfaqESVjZjrw4aEUKP4h0ltojXHkGxWWoz2dL6iTLpFN193_ifEDRkj-DR%2F&useragentid=f514da69
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/e7306c8f-dd46-4ef9-9da6-116e667fb915/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI088R4yMcBi13CxbRgXkMJYXBa1TX_mOWpftb7w-aGhXtOORoehF3bcGdJeE9W%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/94adf2b0-d6c1-47c9-b06b-2634f91c7cfd/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0fEa5u6KN8gKYQNsZxCNxD2dRSV7ozUzfH01RP0IQlO1deG-oXZDAx5S3qSkB%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)
https://login.pingone.com/idp/directory/a/88ce516c-a773-4e78-b371-7a8b6f29547f/sso/?returnurl=https%3A%2F%2Fsso.connect.pingidentity.com%2Fsso%2Fopentoken%2FI0Bdvgo9I7KwpmKdIAdpro9M7MOtuCDD02QWb91Hk1Nsn0Jez-z12ujYD6Nu2X%2F
  baseline: 200 -> (none)
  canary  : 401 -> (none)

### hackerone / Amazon — 12
program: https://hackerone.com/amazonvrp

https://eu-north-1.signin.aws.amazon.com/oauth?client_id=arn%3Aaws%3Asignin%3A%3A%3Aconsole%2Fcanvas&code_challenge=_UVBOE8mnt8cOdgNkxLfo6rmF-maZwqrF0lP0N-ycoc&code_challenge_method=SHA-256&response_type=code&redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2Fconsole%2Fhome%3Fca-oauth-flow-id%3Dacff%26hashArgs%3D%26isauthcode%3Dtrue%26state%3DhashArgsFromTB_eu-north-1_936efec8c7f239e7
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://www.amazon.ae/-/ar/ap/register?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.ae%2F-%2Far%2F%25D8%25A5%25D9%2584%25D9%2583%25D8%25AA%25D8%25B1%25D9%2588%25D9%2586%25D9%258A%25D8%25A7%25D8%25AA-%25D8%25AC%25D8%25AF%25D9%258A%25D8%25AF-Prime-%25D8%25AA%25D8%25B4%25D8%25AD%25D9%2586-%25D9%2585%25D9%2586-%25D8%25A7%25D9%2584%25D8%25A5%25D9%2585%25D8%25A7%25D8%25B1%25D8%25A7%25D8%25AA%2Fs%2F%3F_encoding%3DUTF8%26language%3Dar%26rh%3Dn%253A11601326031%252Cp_n_condition-type%253A92070823031%252Cp_n_prime_domestic%253A20642115031%26ref_%3Dnav_newcust&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=aeflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 302 -> www.amazon.ae
  canary  : 404 -> (none)
https://www.amazon.ae/-/ar/ap/signin/ref=cart_empty_sign_in?openid.assoc_handle=aeflex&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.return_to=https%3A%2F%2Fwww.amazon.ae%2Fcart%3Fapp-nav-type%3Dnone%26dc%3Ddf
  baseline: 302 -> www.amazon.ae
  canary  : 404 -> (none)
https://www.amazon.ae/-/ar/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.ae%2F-%2Far%2F%25D8%25AC%25D9%258A%25D8%25B3-%25D8%25AD%25D9%2582%25D8%25A7%25D8%25A6%25D8%25A8-%25D8%25A8%25D8%25AA%25D8%25B5%25D9%2585%25D9%258A%25D9%2585-%25D8%25A7%25D9%2584%25D8%25A7%25D8%25AD%25D8%25B2%25D9%2585%25D8%25A9-%25D9%2584%25D9%2584%25D9%2586%25D8%25B3%25D8%25A7%25D8%25A1-%25D8%25A7%25D8%25B3%25D9%2588%25D8%25AF%2Fs%2F%3F_encoding%3DUTF8%26k%3D%25D8%25AC%25D9%258A%25D8%25B3%2520%25D8%25AD%25D9%2582%25D8%25A7%25D8%25A6%25D8%25A8%2520%25D8%25A8%25D8%25AA%25D8%25B5%25D9%2585%25D9%258A%25D9%2585%2520%25D8%25A7%25D9%2584%25D8%25A7%25D8%25AD%25D8%25B2%25D9%2585%25D8%25A9%2520%25D9%2584%25D9%2584%25D9%2586%25D8%25B3%25D8%25A7%25D8%25A1%2520%25D8%25A7%25D8%25B3%25D9%2588%25D8%25AF%26language%3Dar%26ref_%3Dnav_ya_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=aeflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&
  baseline: 302 -> www.amazon.ae
  canary  : 404 -> (none)
https://vendorcentral.amazon.com.br/ap/signin?openid.pape.preferred_auth_policies=SinglefactorWithPossessionChallenge&openid.return_to=https%3A%2F%2Fvendorcentral.amazon.com.br%2Fvendor%2Fmembers%2Fcost%2FdownloadFile%3FrequestId%3De606fe82-b503-44d8-a9a1-25dc18edae28&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amzn_vc_br_v2&openid.mode=checkid_setup&intercept=false&language=pt_BR&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=amzn_vc_br_auth&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 200 -> (none)
  canary  : 404 -> (none)
https://vendorcentral.amazon.co.jp/ap/signin?openid.pape.preferred_auth_policies=SinglefactorWithPossessionChallenge&openid.return_to=https%3A%2F%2Fvendorcentral.amazon.co.jp%2Fhz%2Fvendor%2Fmembers%2Fsupport%2Ftraining%2Fnode%2FG202145470%3FformAndDownloadTitleWsid%3Dvss-sup-hub-form-download-link-text%26katalScriptSrc%3D%253Cscript%2Bsrc%253D%2522https%253A%252F%252Fd1uznvntk80v7s.cloudfront.net%252Fkatal.assetloader.388cebfac1a0.min.js%2522%253E%253C%252Fscript%253E%26isProgressBarEnabled%3Dtrue&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amzn_vc_jp_v2&openid.mode=checkid_setup&intercept=false&language=ja_JP&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=amzn_vc_jp_auth&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 200 -> (none)
  canary  : 404 -> (none)
https://www.amazon.ca/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.ca%2Fyour-orders%2Forders%2Fref%3Dyo_surl&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amzn_retail_yourorders_ca&openid.mode=checkid_setup&language=en_CA&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 302 -> www.amazon.ca
  canary  : 404 -> (none)
https://www.amazon.de/ap/signin?openid.pape.max_auth_age=3600&openid.return_to=https%3A%2F%2Fwww.amazon.de%2Freview%2Fcreate-review&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amzn_scarface_mobile_de&openid.mode=checkid_setup&language=de_DE&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=login&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 200 -> (none)
  canary  : 404 -> (none)
https://www.amazon.in/ap/signin?openid.pape.max_auth_age=3600&openid.return_to=https%3A%2F%2Fwww.amazon.in%2Fapay-emi-dashboard&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amzn_emi_mobile&openid.mode=checkid_setup&language=en_IN&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 302 -> www.amazon.in
  canary  : 404 -> (none)
https://www.amazon.es/ap/signin?openid.pape.max_auth_age=1209600&openid.return_to=https%3A%2F%2Fwww.amazon.es%2Fcheckout%2Fp%2Fp-420-5297747-0664350%2Fpay%3FpipelineType%3DChewbacca%26hasWorkingJavascript%3D1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amazon_checkout_es&openid.mode=checkid_setup&language=es_ES&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 302 -> www.amazon.es
  canary  : 404 -> (none)
https://www.amazon.nl/ap/signin?openid.pape.preferred_auth_policies=Singlefactor&openid.pape.max_auth_age=900&openid.return_to=https%3A%2F%2Faccount.kep.amazon.nl%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=kpss_nl&openid.mode=checkid_setup&language=nl_NL&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=leto-ap&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 200 -> (none)
  canary  : 404 -> (none)
https://www.amazon.com.mx/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com.mx%2Fsubscriptions%2Fexternal%2Fentitlement%2Foffline%3FcontractId%3D523aa8e3-0598-3b02-aaa2-064072f31016%26reseller%3Damericamovilmx%26offerId%3Damericamovilmx_prime_mid_tier_15_days_efa9039a-13c8-438e-831b-25a57d4665e8%26language%3Des_US%26pageId%3Damericamovilmx_primelite%26fusePlanId%3Dae028153-abfd-46b3-bbb0-aba21038ddef%26et%3D57068e69-f90f-474d-96ce-37ad302fb823%26flowType%3DV2&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=amzn_fuse_mx&openid.mode=checkid_setup&ref_=et%3A57068e69-f90f-474d-96ce-37ad302fb823&language=es_MX&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=americamovilmx_primelite&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
  baseline: 200 -> (none)
  canary  : 404 -> (none)

### hackerone / Starbucks — 7
program: https://hackerone.com/starbucks

https://fr.starbucks.ca/account/signin?returnUrl=%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26source%3Doauth%26Timeout%3Dfalse%26AllowGuest%3Dfalse%26client_id%3DKJ3XcZs1GZPRwFKPr7vnlGkY9aAZ9lYG%26redirect_uri%3Dhttps%253A%252F%252Fwww.starbucksavie.ca%252Foauth
  baseline: 200 -> (none)
  canary  : 444 -> (none)
https://fr.starbucks.ca/account/signin?ReturnUrl=%2fcarte%2fmanage%2ftransfer
  baseline: 200 -> (none)
  canary  : 444 -> (none)
https://www.starbucks.ca/account/create?ReturnUrl=%2Faccount%2Fcard
  baseline: 200 -> (none)
  canary  : 444 -> (none)
https://www.starbucks.ca/account/create?returnUrl=%2Fcareers
  baseline: 200 -> (none)
  canary  : 444 -> (none)
https://www.starbucks.ca/account/logout?returnUrl=%2F
  baseline: 200 -> (none)
  canary  : 444 -> (none)
https://www.starbucks.ca/account/signout?ReturnUrl=%2Fcareers%2Fworking-at-starbucks%2Fbenefits-and-perks
  baseline: 200 -> (none)
  canary  : 444 -> (none)
https://www.starbucks.ca/account/signin?returnUrl=https%3A%2F%2Fwww.starbucks.ca%2Frewards
  baseline: 200 -> (none)
  canary  : 444 -> (none)

### bugcrowd / Cisco Meraki — 3
program: https://bugcrowd.com/ciscomeraki

https://id.cisco.com/oauth2/default/v1/authorize?response_type=code&scope=openid%20profile%20address%20offline_access%20cci_admemberOf%20email&client_id=cae-okta-web-gslb-ext-01-pwlo&state=KlKT0K_2NKKC7ZMOQ-bPMsgM2nM&redirect_uri=https%3A%2F%2Fe2e-verification-dedicated0-ext-prd-rcdn-02-app-test.cisco.com%2Fcb%2Fsso&nonce=yiLZYqxIxDSmTEkcS1NTjeQGbEPcJphPN_MMWtH-0SM&code_challenge=ExNXGMknVMZFmYzl4J_EYGr3C2zfWHmmPwYxfTNVI4E&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://sso-preview.test.security.cisco.com/oauth2/aus1l6qs5by07j31s0h8/v1/authorize?client_id=0oa27dhuwdr2KCPER0h8&code_challenge=70hQZ5Aw8yUTiCEH-__rcjdKcnPXW3AkmW2t_N1S3-0&code_challenge_method=S256&nonce=KKgU6wGcrpexzufraXabRMTcERiYwB3uz4EDNpQcfXHSoMChiR0VdbeS4kIRtRBD&redirect_uri=https%3A%2F%2Fcontrol.v3.dev.security.cisco.com%2Flogin%2Fcallback&response_type=code&state=cZMqUJUG8TwEY95E7s1yttlaSIk9UxZlGNVWl7Kdu3ZkQth4uWat04yUbcYLywV9&scope=email%20openid%20profile%20security-cloud%20security%3Aidentity-intelligence%20security%3Asecure-access%20security%3Axdr%20security%3Acdo%20security%3Amcd%20security%3Aduo%20feature-flag%20security%3Aenterprise%20security%3Acontext%20security%3Aai-defense%20security%3Ampe%20security%3Asecure-workload%20security%3Ahypershield%20offline_access%20security%3Aidr-manager%20security%3Asdwan%20security%3Atalos%20security%3Asecure-client-cm%20security%3Alinus&enterpriseId=
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://sso-preview.test.security.cisco.com/oauth2/ausshygdpj49MYUND0h7/v1/authorize?client_id=0oash0olxt5BCP1T80h7&redirect_uri=https%3A%2F%2Fbetadr-auth-api.cmd.cisco.com%2Fv1%2Fanswer&response_type=code&scope=openid+profile+email&state=3cbcf8ad-022e-4945-9361-c9c70f1cc7cc
  baseline: 200 -> (none)
  canary  : 400 -> (none)

### hackerone / LifeOmic — 2
program: https://hackerone.com/lifeomic

https://login.us.jupiterone.io/sign-up?client_id=4q82sm476uc343u9okk3k2gvph&redirect_uri=https%3A%2F%2Fcommunity.askj1.com%2Fentry%2Foauth2&scope=openid+email+profile&response_type=code&state=eyJ0YXJnZXQiOiJodHRwczpcL1wvY29tbXVuaXR5LmFza2oxLmNvbVwva2JcL2FydGljbGVzXC8xMDAzLWdvb2dsZS1jbG91ZC1pbnRlZ3JhdGlvbi13aXRoLWp1cGl0ZXJvbmUiLCJjaWQiOiI0cTgyc200NzZ1YzM0M3U5b2trM2syZ3ZwaCIsInRva2VuIjoiSUYxSEM5NjZYS0M2OFNNTzhEQU9NTEVTWktZUjhQRTQifQ%3D%3D
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://login.us.jupiterone.io/auth/vanilla?client_id=4q82sm476uc343u9okk3k2gvph&redirect_uri=https%3A%2F%2Fcommunity.askj1.com%2Fentry%2Foauth2&scope=openid+email+profile&response_type=code&state=eyJ0YXJnZXQiOiJodHRwczpcL1wvY29tbXVuaXR5LmFza2oxLmNvbVwvIiwiY2lkIjoiNHE4MnNtNDc2dWMzNDN1OW9razNrMmd2cGgiLCJ0b2tlbiI6IkxUSzYxVDFFT1paQjhSQUkwQjlBOERIQkM0UUs2U0U3In0%3D
  baseline: 302 -> login.us.jupiterone.io
  canary  : 400 -> (none)

### hackerone / Omise — 2
program: https://hackerone.com/omise

https://sso-idp.omise.co/realms/engagement/protocol/openid-connect/auth?client_id=dashboard&redirect_uri=https%3A%2F%2Fdashboard.omise.co%2Fv2&state=d4583803-2c2a-4df7-87d3-4bf75e118b89&response_mode=fragment&response_type=code&scope=openid&nonce=ba536efd-8c67-40fd-80ae-1808d085f0fa&ui_locales=en&code_challenge=8h5Eze3pxwVWBGeH4g40ws8cCy040opRm-_4IyKTDS0&code_challenge_method=S256
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://sso-idp.omise.co/realms/engagement/login-actions/reset-credentials?redirect_uri=https%3A%2F%2Fdashboard.omise.co%2Fv2&client_id=dashboard&tab_id=VJmltn5zThU
  baseline: 200 -> (none)
  canary  : 400 -> (none)

### bugcrowd / Indeed — 2
program: https://bugcrowd.com/indeed

https://id.indeed.tech/oauth2/ausjlql7024a0HDjl4x7/v1/authorize?state=https%3A%2F%2Fexperience.indeed.design%2Ffundamentals%2Fids%2Fifl-performance-guidelines&client_id=0oailtlrvoZonPzlg4x7&redirect_uri=https%3A%2F%2Fexperience.indeed.design%2Fcallback&response_type=code&scope=openid+offline_access
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://id.indeed.tech/oauth2/ausdemmtrnyZ8dG1J4x7/v1/authorize?state=qGB24h5iTGzsjoMIIqLfRqLAcONe5NYN&nonce=xkSMG34fNRxrghlMEdspboHGv0UmH6C8&response_type=code&scope=openid+email&client_id=0oadzusikoOfJyFkp4x7&redirect_uri=https%3A%2F%2Fadh.indeed.com%2Foidc%2Fcallback%2F
  baseline: 200 -> (none)
  canary  : 400 -> (none)

### bugcrowd / Trello — 2
program: https://bugcrowd.com/trello

https://trello.com/1/authorize?name=Card%20Done&expiration=never&scope=read%2Cwrite%2Caccount&key=5406e705c52442565420692f9a1dc706&callback_method=fragment&return_url=https%3A%2F%2Fapp.carddone.thundermodules.com%2Fauth-success.html&
  baseline: 200 -> (none)
  canary  : 400 -> (none)
https://trello.com/1/authorize?response_type=token&key=d26d90d17f78f98331402788309ca75d&redirect_uri=chrome-extension%3A%2F%2Fbablhonojcgncmcdjlijlghbjliiolee%2Flogin.html&callback_method=fragment&scope=read%2Cwrite%2Caccount&expiration=never&name=Trello%20Checklist
  baseline: 200 -> (none)
  canary  : 400 -> (none)

### hackerone / MongoDB — 1
program: https://hackerone.com/mongodb

https://corp.mongodb.com/oauth2/v1/authorize?client_id=0oa3e3dsu168G2pm3297&redirect_uri=https%3A%2F%2Flogin.corp.mongodb.com%2Flogin%2Fokta%2Fcallback&response_type=code&scope=openid+profile+email+groups&state=850e54bd-cd92-44dc-9136-80d285da505c
  baseline: 200 -> (none)
  canary  : 400 -> (none)

### hackerone / Vimeo — 1
program: https://hackerone.com/vimeo

https://www.vhx.tv/signup?return_to=https%3A%2F%2Fkungfury.vhx.tv%2Fupdates%23post-2203
  baseline: 200 -> (none)
  canary  : 429 -> (none)

### yeswehack / Alasco GmbH — 1
program: https://yeswehack.com/programs/alasco-gmbh-bug-bounty-program

https://login.alasco.de/authorize?client_id=ZvHMDABJ7Zza3B1dglpW9zvtSFQQvVUV&redirect_uri=https%3A%2F%2Fapp.alasco.de%2Fauth%2Fcomplete%2Fauth0%2F%3Fredirect_state%3DrOWBgmdULgeRq53peyaHYp4KiDKnkT1J&state=rOWBgmdULgeRq53peyaHYp4KiDKnkT1J&response_type=code&scope=openid+profile+email
  baseline: 302 -> (none)
  canary  : 403 -> (none)

### yeswehack / BlaBlaCar — 1
program: https://yeswehack.com/programs/bug-bounty-program-blablacar

https://newsroom.blablacar.com.br/wp-login.php?redirect_to=https%3A%2F%2Fnewsroom.blablacar.com.br%2Fwp-admin%2F&reauth=1
  baseline: 200 -> (none)
  canary  : 429 -> (none)

## Where the parameter changed the response without redirecting to us (16)

The identity provider fell back to its own error page instead of honouring the external URI. Not a redirect; listed because it proves the value is parsed.

### hackerone / Ping Identity — 5
program: https://hackerone.com/pingidentity

https://auth.pingone.com/73a6bbd8-8b1e-451f-8010-c13003afdaf0/as/authorize?redirect_uri=https%3A%2F%2Fconnectcare-test.steris.com%2Fcallback&rand=56810&prompt=none&response_type=code&client_id=7f8b3d7c-1024-4e80-ab3d-0142dd837c47
  baseline: 302 -> connectcare-test.steris.com
  canary  : 302 -> apps.pingone.com
https://auth.pingone.com/6784eeb7-4e13-4004-84b1-18f0170032db/as/authorize?response_type=code&client_id=4a6b2c0f-8099-43ea-9198-c4d1984eabf3&redirect_uri=https%3A%2F%2Fconnectcare-dev.steris.com%2Fcallback&rand=53561&prompt=none
  baseline: 302 -> connectcare-dev.steris.com
  canary  : 302 -> apps.pingone.com
https://auth.pingone.com/8c0122b0-010c-4b7f-8fd4-270575ff8ce5/as/authorize?response_type=id_token&client_id=378ab651-856b-4195-864b-94b38d811110&redirect_uri=https%3A%2F%2Fyalemedicine.cqs.symplr.com%2FAuthentication%2FOidcSsoSignIn&scope=openid%20profile%20email&state=oojzwixjsmvc5ihcwcmzp514&nonce=FSX2rVZwRwz3vSo&response_mode=query
  baseline: 302 -> auth.pingone.com
  canary  : 302 -> apps.pingone.com
https://auth.pingone.com/c387f975-2dcd-4f68-b4cb-081fc6ecaca3/as/authorize?acr_values=MerckUAT&response_type=token&client_id=cf977745-3a74-4d4d-8a95-d2e3648ee32e&redirect_uri=https%3A%2F%2Ffsi-unity-reactjs-uat-new.azurewebsites.net%2FssoRoute&scope=openid0profile
  baseline: 302 -> fsi-unity-reactjs-uat-new.azurewebsites.net
  canary  : 302 -> apps.pingone.com
https://auth.pingone.com/fe8139f0-2ed3-40da-bedd-659a874fd94a/as/authorize?redirect_uri=https%3A%2F%2Fauth.boeingservices.com%2Fsp%2FeyJpc3MiOiJodHRwczpcL1wvYXV0aC5waW5nb25lLmNvbVwvZmU4MTM5ZjAtMmVkMy00MGRhLWJlZGQtNjU5YTg3NGZkOTRhXC9hcyJ9%2Fcb.openid&code_challenge=Yz9nzjL6iBkIoKZMeUSwjPDo_LLcP3Dhkiy90_DBuVA&client_id=54c95a54-7f88-47e7-a1a3-e9c74db422de&scope=openid+profile+email+address+phone&state=ZkLNaUbxLiyLPWJmzpycUfv8DNIVel&nonce=lazch6gwmIz2acR71uHH8u&response_type=code&acr_values=hivebrite&code_challenge_method=S256
  baseline: 302 -> auth.boeingservices.com
  canary  : 302 -> apps.pingone.com

### intigriti / Visma Public — 5
program: https://app.intigriti.com/researcher/programs/visma/visma/detail

https://identity.internaltest.vismaonline.com/login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fx-client-ver%3D6.9.0.0%26client_id%3Dvisma.online.administration%26redirect_uri%3Dhttps%253A%252F%252Fadmin.internaltest.vismaonline.com%26response_type%3Did_token%2520token%26state%3DOpenIdConnect.AuthenticationProperties%253DzB1bAQc1GmbBN-5dtnYLWbkrwk16DHdVESaHsq9J1xQW2M2TIxPXXQ6hi3hNNok5zogPSsYLH1FdHyQCn7KzZGzm0g1wKN5CE0ttd2YyYNQEpzF9io87DpHNiOcrWCOAecgONuJsSTGjMvGou9EoE_Ltiq0eUl8AHmhEMogu_LxZ3vEO86B_tkkSv3Yr3DrNTmlu_7_S3YQvEcnaYi-Oh6aokvHBgUvDzWIvp40LD3vg123H-gJS61gMFgV-IcnbCoOfcw%26response_mode%3Dform_post%26nonce%3D638688827148242670.NzM5OGE1YjYtNzEwOC00OGI4LWE3YjYtODRlZjc0Y2EyMGI0NThkNmVkZjItMzRmNC00Mzc2LTk4NzItZmVhNTU5MzAxZjQ0%26x-client-SKU%3DID_NET472%26scope%3Dopenid%2520profile%2520email%2520roles%2520onlineroles%2520services%2520browserid%2520management%2520vonid%253Aidentity
  baseline: 302 -> vonidentity4-externalidp-int.azurewebsites.net
  canary  : 302 -> (none)
https://identity.vismaonline.com/login?returnUrl=~%2Fsignin%2Fredirectcallback
  baseline: 302 -> connect.visma.com
  canary  : 302 -> (none)
https://identity.vismaonline.com/login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dmyservicesclient%26redirect_uri%3Dhttps%253A%252F%252Fwww.vismaonline.com%26response_type%3Dcode%26scope%3Dopenid%2520profile%2520email%2520onlineid%2520offline_access%2520vonportalapi%2520customercountrycode%26nonce%3D494934f948aef4fc3ae3551214bfedd839dEiQWjz%26state%3D9adf480a64be2dbaf4c58b55b20e919aa7rfshnUT%26code_challenge%3DLtFZI5ikaYg_sbpTKE-q1xgvtlal2RzJgvw4SWLF93g%26code_challenge_method%3DS256
  baseline: 302 -> connect.visma.com
  canary  : 302 -> (none)
https://identity.stage.vismaonline.com/login?returnUrl=~%2Fsignin%2Fredirectcallback
  baseline: 302 -> connect.identity.stagaws.visma.com
  canary  : 302 -> (none)
https://identity.stage.vismaonline.com/login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dmyservicesclient%26redirect_uri%3Dhttps%253A%252F%252Fmyservices.stage.vismaonline.com%26response_type%3Dcode%26scope%3Dopenid%2520profile%2520email%2520onlineid%2520offline_access%2520vonportalapi%2520customercountrycode%26nonce%3D9580cce7221bf6ede9358ca0b0885f3eeewqrE0Xx%26state%3D8fd88ec5fb38f94dd045bbaf893706b39e8SbTrNW%26code_challenge%3DeY-6KrxMxcdDRN-UfIiJ3S22pv2G_krqQmMIE_XKcMI%26code_challenge_method%3DS256
  baseline: 302 -> connect.identity.stagaws.visma.com
  canary  : 302 -> (none)

### hackerone / Tide — 3
program: https://hackerone.com/tide

https://login-staging.tide.co/am/tide/oauth/authorize?client_id=524a54dd-c4f7-4144-8a54-ddc4f791449b&redirect_uri=https%3A%2F%2Fweb-staging.tide.co%2Fsilent-renew.html&response_type=code&scope=openid%20app%20full_profile&nonce=07a14e73ce9326e1f90b64b7af03168073Gsh0L56&state=57406cb4a5d03d034658c0b8bb1a444a43cKpzDdB&code_challenge=aex3B1D4_HcL29BR-7W8G0S5XooMFdKziOK9v0a3mig&code_challenge_method=S256&prompt=none
  baseline: 302 -> web-staging.tide.co
  canary  : 302 -> login-staging.tide.co
https://login-wip.tide.co/am/tide/oauth/authorize?client_id=TIDE-UNIVERSAL-APP&redirect_uri=https%3A%2F%2Fweb-wip.tide.co%2Fsilent-renew.html&response_type=code&scope=openid%20app%20full_profile&nonce=f79e3a64c5c5dc6bc8f6576264c7c269c30FvZiZz&state=382528a7dc3a1a1f9318ecc66d7d0cdfc81kfDwbq&code_challenge=51y94s3Z44YndUieWvOgwSTdFyZp-HTfuLrIDWpSid0&code_challenge_method=S256&prompt=none
  baseline: 302 -> web-wip.tide.co
  canary  : 302 -> login-wip.tide.co
https://login.tide.co/am/tide/oauth/authorize?response_type=code&client_id=af73d828-2760-416f-b3d8-282760c16f29&scope=openid&redirect_uri=https%3A%2F%2Fmemberconnect.tide.co%2Fen%2Foauth%2Fconnect%2Fservice%2Fgravitee&prompt=none
  baseline: 302 -> memberconnect.tide.co
  canary  : 302 -> login.tide.co

### bugcrowd / Seek — 2
program: https://bugcrowd.com/seek

https://authenticate.seek.com/authorize?client_id=9Y4DKSBERdQX4XSg4jDGqhFs39NoHnQ1&redirect_uri=https%3A%2F%2Fhk.employer.seek.com%2Foauth%2Fcallback%2F&scope=openid%20profile%20email%20offline_access&audience=https%3A%2F%2Fseek%2Fapi%2Ftalent&fragment=%2Foauth%2Flogin%3Flocale%3Dhk%26language%3Den%26da_cdt%3Dvisid_0197350cc730001035300ac127020506d006106500590-sesid_1748941719349-hbvid_accd0b0f_22e3_47be_95eb_face13eb1d46&ui_locales=en&JobseekerSessionId=1a55e6f9-e755-4720-95e5-297329c33534&language=en-HK&response_type=code&response_mode=query&state=ZlhWc3A5UXdzXy5aUGVYMmJXX0FaeFpYM0xpVVlISTJyUDZjUTlVdFNDZw%3D%3D&nonce=QnJSRXFLWmZYZXpnQm8weDVaMlhmUlNyR0s3SWRFQzZGakI3dmY0UkpMUQ%3D%3D&code_challenge=3R-vNglaIMmsPU-8uZ7tjXCxLt6FyFTE8YLyj80MLVE&code_challenge_method=S256&auth0Client=eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjIuMyJ9
  baseline: 302 -> (none)
  canary  : 302 -> seekcdn.com
https://authenticate.seek.com/v2/logout?client_id=8msSXVB0z0v7gN34Y5j0j5Sxn72KTFBB&returnTo=https%3A%2F%2Ftalent.seek.com.au%2F&auth0Client=eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjIuMyJ9
  baseline: 302 -> talent.seek.com.au
  canary  : 302 -> seekcdn.com

### hackerone / LocalTapiola — 1
program: https://hackerone.com/localtapiola

https://verkkopalvelu.lahitapiolarahoitus.fi/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dverkkopalvelu%26redirect_uri%3Dhttps%253A%252F%252Fverkkopalvelu.lahitapiolarahoitus.fi%26response_type%3Dcode%26scope%3Dopenid%2520profile%2520cvEventRecords%26nonce%3DN0.175285797828240281736536506337%26state%3D17365365038300.60972177067963250.7106311259901207%26code_challenge%3DkF_8fe_QG6u3pp1FoAHwsIStCMObJRh85SYFejsjwJE%26code_challenge_method%3DS256%26ui_locales%3Dfi-FI
  baseline: 302 -> (none)
  canary  : 302 -> verkkopalvelu.lahitapiolarahoitus.fi

## Archived value no longer valid, ours accepted (0)

## Unreachable (687)

These could not be tested (host dead, connection refused or TLS failure) — they remain untested, not clean.

-  291  hackerone / Vanilla
-  103  bugcrowd / Sophos
-   65  hackerone / Spotify
-   45  hackerone / Palantir Public
-   42  hackerone / Goldman Sachs
-   16  hackerone / Alibaba
-   13  bugcrowd / Just Eat Takeaway.com
-   11  hackerone / Kindred Group
-   10  hackerone / Epic Games
-    7  hackerone / Logitech
-    6  bugcrowd / Binance
-    5  hackerone / Starbucks
-    5  hackerone / Urban Company
-    4  hackerone / Acronis
-    4  hackerone / Fitbit
-    4  bugcrowd / Lime
-    4  bugcrowd / Western Union
-    3  hackerone / Bime
-    3  hackerone / eToro
-    3  bugcrowd / Cisco Meraki
-    3  intigriti / Visma Public
-    2  hackerone / Airbnb
-    2  hackerone / Allegro
-    2  hackerone / Cornershop
-    2  hackerone / Paddy Power Betfair
-    2  bugcrowd / Indeed
-    2  intigriti / Telenet
-    1  hackerone / Aiven
-    1  hackerone / De Volksbank
-    1  hackerone / GitHub
-    1  hackerone / Hilton Bounty
-    1  hackerone / Instacart
-    1  hackerone / LifeOmic
-    1  hackerone / Omise
-    1  hackerone / Ninja Kiwi
-    1  hackerone / Reddit
-    1  hackerone / Roblox
-    1  hackerone / Scopely
-    1  hackerone / Stripe
-    1  hackerone / Tide
-    1  hackerone / TTS Bug Bounty
-    1  hackerone / Unikrn
-    1  hackerone / Upserve
-    1  hackerone / PayPal
-    1  hackerone / Zomato
-    1  bugcrowd / Pornhub
-    1  bugcrowd / PlanetHoster
-    1  bugcrowd / Socrata
-    1  yeswehack / BlaBlaCar
-    1  yeswehack / HARMAN International
-    1  yeswehack / Telenor
-    1  yeswehack / Vfs
-    1  yeswehack / Ezviz
-    1  intigriti / Yahoo!
-    1  bugcrowd / Opera Public Bug Bounty

