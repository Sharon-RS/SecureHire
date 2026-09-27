# Authentication & Session Security (Session Fixation, Expiration, and Cookie Security)

## What Authentication & Session Security Weaknesses are

Authentication verifies who a user is, while session management maintains that authenticated state across stateless HTTP requests. When session handling is flawed, attackers can achieve **Account Takeover** without ever discovering, cracking, or guessing the victim's password.

This laboratory focuses on three high-impact session management weaknesses:

1. **Session Fixation (CWE-384):** The application fails to renew (rotate) the session identifier upon successful user login. An attacker pre-establishes a known session token on a shared kiosk, waiting for a victim to sign in. Because the server authenticates the user within the existing token, the attacker immediately gains full access to the victim's account.
2. **Insufficient Session Expiration on Logout (CWE-613):** The application instructs the browser to delete the session cookie on sign-out, but fails to revoke or invalidate the token in server storage. If an eavesdropper, proxy, or shared terminal attacker captures or preserves the token, replaying it restores authenticated access.
3. **Insecure Cookie Attributes (CWE-1004 / CWE-614):** Session cookies transmitted without `HttpOnly` can be stolen by cross-site scripting (XSS) via `document.cookie`, while missing `SameSite` flags leave sessions vulnerable to cross-site inclusion.

In freelance marketplaces, these weaknesses put contractor earnings, escrow disbursements, confidential project specifications, and private messages at risk.

## Local synthetic scenario and isolation boundary

The page at `/security-lab/auth-session` models a shared co-working or library kiosk scenario:
- **Synthetic Consultant:** Alex Rivers (`alex.freelancer@example.test`) with synthetic escrow balances and active proposals.
- **Trap Token:** Pre-authentication session token `PRE-AUTH-GUEST-SESSION-TOKEN-DEMO-001`.

In strict accordance with **AGENTS.md Rules 1–9** and project isolation constraints:
- **Completely Separate Synthetic Store:** The `auth_session` demonstration operates on a dedicated in-memory synthetic session store (`app/services/demos/auth_session/store.py`). Synthetic tokens **never** authenticate or modify Flask-Login, `current_user`, the real Flask session, or any normal SecureHire marketplace route.
- **Strictly Scoped Demonstration Cookie:** The demonstration cookie `securehire_demo_session` is scoped exclusively to `/security-lab/auth-session`. It has zero effect on other routes.
- **Permanent Protection on Real Application Session:** SecureHire's real session cookie (`session`) permanently enforces `HttpOnly=True` and `SameSite=Lax` across the application in both vulnerable and mitigated modes.
- **Clear Result Labeling:** When session fixation succeeds, the UI and evidence clearly label the outcome as **`SIMULATED ACCOUNT TAKEOVER`**, explicitly confirming that no real account or system was compromised.
- **Bounded Logging:** Lab execution records only bounded statuses (`passed` or `blocked`) in `LabRun`, never recording credentials, session secrets, or attack tokens.

## Vulnerable flow

When `auth_session` mode is set to **Vulnerable** and all central gate conditions pass:

1. **Step 1 (Pre-Auth Hold):** The attacker records the pre-authentication kiosk token (`PRE-AUTH-GUEST-SESSION-TOKEN-DEMO-001`).
2. **Step 2 (Victim Authentication):** When Alex Rivers logs in, the server intentionally **omits session rotation**, authenticating Alex into the pre-existing kiosk token.
3. **Step 3 (Simulated Account Takeover):** The attacker inspects the pre-auth token. The server accepts it as authenticated: **SIMULATED ACCOUNT TAKEOVER** is confirmed.
4. **Step 4 (Flawed Logout):** When Alex logs out, the server fails to invalidate the token server-side. Replaying the discarded token is accepted by the server.
5. **Cookie Security:** The synthetic demonstration cookie `securehire_demo_session` is emitted without `HttpOnly` and without `SameSite`.

Effective vulnerable mode strictly requires:
- `LAB_ENABLE=true` in server configuration.
- Non-production environment (`APP_ENV=development` or `APP_ENV=testing`).
- Loopback socket peer (`127.0.0.1` or `::1`). Forwarded proxy headers are ignored.
- Server-side persisted mode set to `vulnerable` in `security_modes`.

Any missing or invalid condition immediately causes the application to fail closed into **Mitigated** mode.

## Mitigated flow

In **Mitigated** mode (default):

1. **Session Rotation upon Login (CWE-384 Defense):** When Alex logs in, the server generates a brand new cryptographically random session token (`secrets.token_hex(16)`), binds Alex's session exclusively to the new token, and invalidates the pre-auth token.
2. **Fixation Defeated:** When the attacker attempts to use the pre-auth kiosk token, the server returns HTTP 401 with **`ACCESS DENIED (Session Invalid or Rotated)`**.
3. **Server-Side Logout Invalidation (CWE-613 Defense):** When Alex signs out, the server explicitly marks the session token as revoked and detaches authentication. Replaying discarded credentials returns HTTP 401 with **`SESSION REVOKED`**.
4. **Enforced Cookie Security:** The demonstration cookie sets `HttpOnly=True` and `SameSite=Lax`.

## Safe classroom demonstration steps

1. Sign in to SecureHire as `admin@example.test`.
2. Open the Security Lab dashboard at `/security-lab`.
3. In **Mitigated** mode (default):
   - Navigate to `/security-lab/auth-session`.
   - Click "Simulate Consultant Login". Notice a new rotated token (`AUTH-SESSION-...`) is issued.
   - Click "Inspect Attacker Token Access". Notice the result is **ACCESS DENIED**: Alex's account cannot be accessed via the pre-login token.
   - Click "Simulate Consultant Logout" and then "Replay Discarded Session Token". Notice the token is revoked server-side (HTTP 401).
4. In **Vulnerable** mode:
   - Ensure `LAB_ENABLE=true` in `.env`.
   - On `/security-lab`, change `auth_session` mode to **Vulnerable**.
   - Return to `/security-lab/auth-session` (notice educational red warning banner).
   - Click "Simulate Consultant Login". Notice the pre-auth token was reused without rotation.
   - Click "Inspect Attacker Token Access". Notice **SIMULATED ACCOUNT TAKEOVER**: the attacker gained full access to Alex's freelance account using only the pre-login kiosk token.
   - Click "Simulate Consultant Logout" and "Replay Discarded Session Token". Notice the discarded token remains active on the server.
   - Inspect the Cookie Comparison table to see the absence of `HttpOnly` and `SameSite` flags on the demo cookie.
5. Click "Reset Session Scenario" and return the stored mode to **Mitigated** when finished.

## Test coverage

`tests/test_auth_session.py` provides automated verification for:
- Mitigated mode session rotation upon login (issuing new token, invalidating pre-auth token).
- Mitigated mode rejection of pre-auth tokens (HTTP 401).
- Mitigated mode server-side session invalidation on logout.
- Mitigated mode `HttpOnly=True` and `SameSite=Lax` on `securehire_demo_session`.
- Vulnerable mode session fixation (reusing pre-auth token, confirming `SIMULATED ACCOUNT TAKEOVER`).
- Vulnerable mode stale session reuse after logout (replaying discarded token succeeds).
- Vulnerable mode omission of `HttpOnly` and `SameSite` on `securehire_demo_session`.
- Fail-closed gate behavior when `LAB_ENABLE=false`, request is non-loopback, or environment is production.
- **Explicit regression protections**: Normal `/auth/login` and `/auth/logout` routes retain `HttpOnly=True`, `SameSite=Lax`, and CSRF protection even when `auth_session` is Vulnerable.
- Real Flask-Login and `current_user` are never authenticated or modified by synthetic lab tokens.
- CSRF protection across all lab action endpoints.
- Bounded status recording in `LabRun` without sensitive token or credential disclosure.
