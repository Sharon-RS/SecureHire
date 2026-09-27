# Stored XSS demonstration

## Purpose and isolation

Stored Cross-Site Scripting occurs when saved user-controlled content is later interpreted as markup or script. SecureHire demonstrates the risk with two isolated paths: normal marketplace reviews, which are always rendered with Jinja autoescaping, and a dedicated Security Lab record used to compare vulnerable and mitigated output.

The lab accepts only this harmless proof of concept:

```html
<script>alert("SecureHire XSS demo")</script>
```

The value is stored in `stored_xss_demo_entries`, one row per signed-in synthetic account. It is never copied into marketplace reviews, visible on marketplace pages, sent to another site, or written to `lab_runs`. Run records contain only the bounded status and selected effective mode. Lab routes use the existing centralized mode service; a request parameter, form field, cookie, or browser setting cannot select the implementation.

## Vulnerable and mitigated behavior

- **Vulnerable:** the isolated vulnerable renderer marks the approved stored value as safe HTML. On the gated lab result page the browser creates a script element and displays the harmless alert.
- **Mitigated:** the server HTML-escapes the same stored value for the page's HTML text-node context. The browser displays the tags as text and does not execute them.
- **Normal marketplace reviews:** always use automatic template escaping in every lab mode. A review body containing markup is displayed as text.

The core mitigation is output encoding for the destination context. Content Security Policy is defense in depth, not the fix. Because the default policy blocks inline script, only the Stored XSS result response gets a narrowly scoped `script-src 'self' 'unsafe-inline'` exception when the central gate makes vulnerable mode effective and the exact approved value is present. The exception is absent in mitigated mode and on all other routes.

## Safe demonstration steps

1. Sign in to the local SecureHire app with a synthetic account.
2. In the Security Lab dashboard, set Stored XSS to Vulnerable. This stored setting only becomes effective when `LAB_ENABLE=true`, the app is nonproduction, and the accepted socket peer is loopback.
3. Open `/security-lab/stored-xss` and submit the prefilled approved value.
4. The result section runs a local alert with the text `SecureHire XSS demo`.
5. Change the server-side Stored XSS setting to Mitigated and reload the lab page. The same stored value appears as escaped text.
6. Return the setting to Mitigated and set `LAB_ENABLE=false` when the demonstration is complete.

The page clearly identifies **ATTACK INPUT**, **RESULT**, and **MITIGATION** and reports the effective mode. There are no external targets, callbacks, exfiltration, filesystem operations, or command execution.

## Review feature and authorization

Marketplace reviews are permitted only after an accepted proposal. Either participant may publish one review of the other; the server derives reviewer and reviewee from the authenticated user and accepted proposal. A unique database constraint prevents duplicate reviews. Review bodies have bounded length and remain autoescaped on public gig detail pages, independent of the Stored XSS lab mode.

## Tests

`tests/test_stored_xss.py` verifies review authorization and rendering, the approved payload in both modes, the lab-enable/production/loopback gate, client-side mode tampering, user isolation, default CSP behavior, and payload-free lab-run records. `tests/test_security_lab.py` retains the centralized gate and admin/CSRF checks. The existing SQL Injection suite remains in place.
