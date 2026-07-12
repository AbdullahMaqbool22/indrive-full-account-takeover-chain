# Unauthenticated Account Takeover on cargo.indrive.com
### Hardcoded RSA-512 Signing Key + Missing Server-Side CAPTCHA Validation + Unthrottled OTP Brute-Force

![Severity](https://img.shields.io/badge/Severity-Critical-red)
![CVSS](https://img.shields.io/badge/CVSS%203.1-9.4-red)
![Status](https://img.shields.io/badge/Status-Reported-yellow)
![Platform](https://img.shields.io/badge/Platform-Web-blue)
![Program](https://img.shields.io/badge/Program-HackerOne-orange)

## Summary

Three chained vulnerabilities on `cargo.indrive.com` allow a fully automated, **unauthenticated account takeover** of any user, identified only by their phone number, in under 5 minutes with no victim interaction:

1. **Hardcoded RSA-512 private key** used to compute the `X-Signature` request-authentication header, exposed in the public JavaScript bundle — allowing anyone to forge valid signed requests.
2. **Server-side CAPTCHA bypass** — the `captcha` field on the OTP request endpoint is never validated against Google's reCAPTCHA API, so any arbitrary string is accepted.
3. **No rate limiting / lockout** on OTP verification — all 10,000 possible 4-digit codes can be brute-forced without restriction.

Chained together, an attacker can request an OTP for any phone number, bypass CAPTCHA entirely, and brute-force the 4-digit code to obtain a valid `access_token` / `refresh_token` pair — full account takeover.

---

## Timeline

| Event |
|-------|
| Vulnerability discovered during independent security research |
| Report submitted via HackerOne |
| Triaged by indrive security team Informational |
| Fix deployed / verified |



---

## CVSS 3.1 Scoring

| Metric | Value |
|--------|-------|
| Attack Vector | Network (N) |
| Attack Complexity | Low (L) |
| Privileges Required | None (N) |
| User Interaction | None (N) |
| Scope | Changed (C) |
| Confidentiality | High (H) |
| Integrity | High (H) |
| Availability | None (N) |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` |
| **Score** | **9.4 (Critical)** |

---

## Vulnerability Chain

```
┌──────────────────────────────┐
│ 1. Extract hardcoded RSA-512 │
│    key from public JS bundle │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 2. Forge valid X-Signature   │
│    → bypass CAPTCHA check    │
│    → trigger OTP SMS to any  │
│      target phone number     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 3. Brute-force 4-digit OTP   │
│    (10,000 combos, no        │
│    lockout, ~69s+ validity)  │
└──────────────┬───────────────┘
               │
               ▼
     Full Account Takeover
   (access_token + refresh_token)
```

---

## Vulnerability 1 — Hardcoded RSA-512 Private Key

**Location:** `cargo.indrive.com` JavaScript bundle, variable `m`, used by signing function `y(t)`.

The complete RSA private key JWK (`n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`) is shipped client-side and used with `crypto.subtle.sign` (RSASSA-PKCS1-v1_5 / SHA-256) to compute the `X-Signature` header required on API requests.

**Why it matters:**
- Any client-side secret is fully attacker-controlled — this is not a "hard to find" secret, it's parsed directly out of a public bundle.
- 512-bit RSA is also trivially factorable via GNFS even without the exposed private exponent, making this doubly broken.
- Full request forgery: an attacker can sign arbitrary payloads exactly as a legitimate client would.

**PoC:** See [`POC/extract_key.py`](POC/extract_key.py) and [`POC/request_otp.py`](POC/request_otp.py).

---

## Vulnerability 2 — reCAPTCHA Not Validated Server-Side

**Endpoint:** `POST /proxy/auth/request-code`

The `captcha` field is accepted as a free-form string with **no server-side call to Google's reCAPTCHA verification API**. Submitting a static placeholder string (e.g. `"x"`) is sufficient to pass validation and trigger a real SMS OTP send.

This defeats the entire purpose of CAPTCHA on this endpoint — it provides no protection against automated abuse.

---

## Vulnerability 3 — No Rate Limiting on OTP Verification

**Endpoint:** `POST /proxy/auth/check-code`

- No lockout after repeated failed attempts (tested 30 concurrent requests across 10 threads with zero throttling).
- No `429 Too Many Requests` returned at any point.
- No incremental backoff delay.
- Sustained throughput: **~7.8 requests/second**.
- OTP (4 digits = 10,000 combinations) confirmed still valid **69+ seconds** after issuance.

At measured throughput, exhausting the full keyspace is feasible well within the OTP validity window, especially with parallelized requests (PoC uses 50 worker threads).

**PoC:** See [`POC/bruteforce_otp.py`](POC/bruteforce_otp.py).

---

## Impact

- Complete, fully automated account takeover of any `cargo.indrive.com` user
- Attacker needs only the victim's **phone number** (frequently visible on public cargo/order listings)
- **Zero victim interaction** required
- Full attack chain completes in **under 5 minutes**
- Access gained upon takeover:
  - Order history
  - PII (name, address, phone number)
  - Saved payment method details
  - Ability to cancel or modify active orders

---

## Remediation

| Priority | Recommendation |
|----------|----------------|
| Critical / Immediate | Remove the hardcoded RSA private key from client-side JS — rotate the key pair immediately |
| Critical / Immediate | Validate reCAPTCHA tokens server-side on every `/proxy/auth/request-code` call via Google's verify API |
| Critical / Immediate | Enforce OTP attempt limits (e.g. 5 wrong attempts → 15 minute lockout per `auth_id`) |
| Short-term | Increase OTP length to 6 digits; reduce validity window to 2–3 minutes |
| Long-term | Redesign request-signing architecture — private keys must never exist in client-reachable code; move signing server-side or use a public/private key scheme where only the public key is exposed |

---

## Disclosure

This vulnerability was reported responsibly through indrive's official [HackerOne](https://hackerone.com/) bug bounty program. See [DISCLOSURE.md](DISCLOSURE.md) for the responsible disclosure statement and program details.

**No real user accounts were accessed during testing.** All proof-of-concept testing was performed against a test phone number (`+7 700 1234567`) explicitly used for validation purposes only, in line with authorized bug bounty testing guidelines.

---

## Researcher

**Abdullah Maqbool** — Penetration Testing Engineer, Certified CRTA / CRTOM / CASP / PenTest+
[LinkedIn](https://www.linkedin.com/in/abdullahmaqboolahmed/) · [Upwork Top 10%](https://www.upwork.com/freelancers/~01bfe8eb3bbb8b493b) · [TryHackMe Top 1%](https://tryhackme.com/p/trixycon)

---

## Disclaimer

This repository is published strictly for educational and responsible-disclosure purposes, after coordination with and authorization from the affected vendor. Do not use this information to access systems or accounts you do not own or have explicit authorization to test.
