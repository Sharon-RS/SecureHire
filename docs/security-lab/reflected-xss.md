# Reflected XSS demonstration

## Purpose and difference from Stored XSS

Reflected Cross-Site Scripting occurs when request input is returned in the same response and the browser interprets it as markup or script. The value is not retained for future visitors. Stored XSS saves a value and returns it later; SecureHire's Stored XSS lesson uses a separate per-user lab record, while this lesson processes a search value only for the current response.

The demo is available at `/security-lab/reflected-xss` and accepts ordinary synthetic search text or this exact harmless proof of concept:

```html
<script>alert("SecureHire Reflected XSS demo")</script>
```

Results come from a fixed set of synthetic local content. The demo does not query marketplace data, save submitted input, access credentials or browser storage, contact another host, redirect, or execute operating-system commands. The form uses POST with CSRF protection and ignores client-supplied mode parameters, fields, cookies, and headers.

## Data flow and implementations

1. An authenticated user submits a search value with a CSRF token.
2. Validation accepts ordinary synthetic search text or the one approved harmless proof of concept. This bounds the vulnerable path; output encoding remains the mitigation.
3. The route asks SecureHire's centralized mode service for effective mode. Its explicit lab flag, nonproduction environment, and loopback peer checks remain authoritative.
4. The validated input is returned in the same response. Separate functions under `app/services/demos/reflected_xss/` implement the vulnerable and mitigated renderers.
5. The result panel shows demonstration type, mode, reflection status, classification, synthetic match count, bounded lab-run status, and UTC timestamp. `lab_runs` stores only its existing mode/status columns, never the input.

Vulnerable mode marks only the exact approved proof of concept as HTML, causing a browser to create a script element and display the local alert. Ordinary search text is always escaped. Mitigated mode HTML-escapes the approved value for this HTML text-node context, so angle brackets appear as text and no script element is created. This is response-only reflection and is not stored.

## CSP

Output encoding is the primary mitigation. Normal marketplace routes and other Security Lab pages keep the default Content Security Policy. Only the Reflected XSS response with effective vulnerable mode and the exact approved proof of concept gets a response-scoped inline-script allowance. CSP is defense in depth and is not presented as the XSS fix.

## Safe local demonstration

1. Keep the application bound to `127.0.0.1` and sign in using a synthetic account.
2. Set `LAB_ENABLE=true` in the local `.env`, restart the app, and select Vulnerable for Reflected XSS on the Security Lab dashboard. Vulnerability mode also requires the development/testing environment and loopback socket peer.
3. Open `http://127.0.0.1:5000/security-lab/reflected-xss`. Submit `Python` to see normal synthetic search results, or submit the approved payload to see the local alert.
4. Select Mitigated and submit the same payload to see it displayed as text without the page-specific CSP exception.
5. Return Reflected XSS to Mitigated and set `LAB_ENABLE=false` when finished.

## Tests and verification

`tests/test_reflected_xss.py` covers normal search, output encoding, the approved input in both modes, lab gates, mode tampering, ordinary marketplace search isolation, other-page CSP isolation, and payload-free lab-run records. The full pytest suite also runs SQL Injection and Stored XSS tests. Automated HTTP checks verify response content and headers; if browser automation is unavailable, final visual confirmation of the harmless alert can be done manually in a local browser.
