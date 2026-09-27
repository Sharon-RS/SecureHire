# Clickjacking (UI Redressing)

## What Clickjacking is

Clickjacking (also known as UI Redressing, CWE-1021) is an attack where a malicious website loads an authenticated application page inside an invisible or transparent `<iframe>` and positions it directly beneath a deceptive decoy lure (such as a fake "Play Video" or "Claim Prize" button).

When an authenticated victim clicks what appears to be the decoy button, their click actually strikes the hidden underlying element on the framed application page, executing an action without their knowledge or informed consent.

In freelance marketplaces, vulnerable 1-click actions could include:
- Unintended proposal approvals or cancellations.
- Unintentional contract milestone sign-offs.
- Endorsing skills or submitting reviews.
- Altering profile settings or privacy preferences.

## Local synthetic scenario and isolation boundary

The page at `/security-lab/clickjacking` provides a localhost-only, educational demonstration modeling a 1-click synthetic freelance skill endorsement action (`/security-lab/clickjacking/target`).

In accordance with **AGENTS.md Rules 3, 4, 5, 6, and 8**:
- **Strict Endpoint Isolation:** The omission of anti-framing headers is strictly confined to the dedicated target endpoint (`/security-lab/clickjacking/target`) and only when the centralized lab gate is open and mode is set to `vulnerable`.
- **Global Header Preservation:** All unrelated routes (marketplace, authentication, administrative controls, other security lab modules) permanently enforce `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`. Unrelated routes are never weakened.
- **Harmless Synthetic Action:** The target action increments a synthetic endorsement counter stored in the local session. No real user accounts, credentials, financial transactions, or third-party websites are involved.
- **Controlled Same-Origin Simulation:** The demonstration operates entirely on localhost. No external websites or cross-origin framing requests are permitted.

## Vulnerable flow

When `clickjacking` mode is set to **Vulnerable** and all central gate conditions pass:

1. The target endpoint `/security-lab/clickjacking/target` omits `X-Frame-Options`.
2. The endpoint omits the `frame-ancestors 'none'` directive from `Content-Security-Policy`.
3. A local framing test page (`/security-lab/clickjacking/framing-test`) or the lab visualizer can embed the target endpoint inside an `<iframe>`.
4. In the visualizer, students adjust the opacity slider to see how an attacker positions a decoy lure ("Claim $100 Freelancer Bonus!") directly above the real button ("Endorse Freelancer Skill").
5. Clicking the button executes the synthetic endorsement, recording a `passed` lab-run status.

Effective vulnerable mode strictly requires:
- `LAB_ENABLE=true` in server configuration.
- Non-production environment (`APP_ENV=development` or `APP_ENV=testing`).
- Loopback socket peer (`127.0.0.1` or `::1`). Forwarded proxy headers are ignored.
- Server-side persisted mode set to `vulnerable` in `security_modes`.

Any missing or invalid condition immediately causes the application to fail closed into **Mitigated** mode.

## Mitigated flow

In **Mitigated** mode (default):

1. **Content-Security-Policy `frame-ancestors 'none'`:** The server sets `frame-ancestors 'none'`, which modern browsers interpret to block any framing of the target page, whether cross-origin or same-origin.
2. **`X-Frame-Options: DENY`:** The server sets `X-Frame-Options: DENY` as defense-in-depth for legacy user agents that do not support CSP Level 2.
3. **Browser Refusal:** When `/security-lab/clickjacking/target` is loaded in an `<iframe>`, the browser refuses to render the document, preventing any UI redressing attack.
4. **Permanent Global Protection:** All standard application routes retain their default anti-framing headers regardless of Security Lab mode changes.

## Safe classroom demonstration steps

1. Sign in to SecureHire as `admin@example.test`.
2. Open the Security Lab dashboard at `/security-lab`.
3. In Mitigated mode (default):
   - Open `/security-lab/clickjacking`.
   - Inspect the **Live HTTP Response Headers** table: observe `X-Frame-Options: DENY` and `CSP: frame-ancestors 'none'`.
   - In the visualizer, the browser refuses to load the framed target action.
   - Click "Open Standalone Framing Test Harness" -> The standalone iframe page displays the browser's framing refusal.
4. In Vulnerable mode:
   - Ensure `LAB_ENABLE=true` in `.env` and restart the server if needed.
   - On the Security Lab dashboard, set `Clickjacking` mode to `Vulnerable`.
   - Return to `/security-lab/clickjacking` (educational red warning banner is visible).
   - In the visualizer, the target page renders inside the iframe.
   - Move the opacity slider from 75% down to 0% to see the decoy button lure completely mask the underlying action.
   - Click the decoy button -> The click strikes the target action, incrementing the synthetic endorsement count.
   - Click "Reset endorsements" to restore the counter.
5. Return stored mode to `Mitigated` when finished.

## Test coverage

`tests/test_clickjacking.py` provides automated verification for:
- Mitigated mode delivery of `X-Frame-Options: DENY` on `/security-lab/clickjacking/target`.
- Mitigated mode delivery of `frame-ancestors 'none'` in `Content-Security-Policy`.
- Vulnerable mode omission of `X-Frame-Options` on the target endpoint when the central gate is open.
- Vulnerable mode omission of `frame-ancestors 'none'` on the target endpoint.
- Global security header preservation: Normal routes (`/`, `/marketplace/gigs`, `/auth/login`, `/security-lab`) preserve `X-Frame-Options: DENY` and `frame-ancestors 'none'` even when clickjacking is in vulnerable mode.
- Fail-closed gate behavior when `LAB_ENABLE=false`, request is non-loopback, or environment is production.
- CSRF protection on target endorsement action and reset endpoints.
- Bounded status recording in `LabRun` without attack payloads or tokens.
