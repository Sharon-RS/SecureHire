# Cross-Site Request Forgery (CSRF)

## What CSRF is

Cross-Site Request Forgery (CSRF) occurs when a browser that is already authenticated is caused to send an unintended state-changing request to an application. Browsers automatically attach eligible cookies to requests. A malicious page can therefore attempt to make a user's browser submit an action using that user's existing SecureHire session.

Authentication and request integrity answer different questions. Authentication identifies the account associated with a request. It does not prove that the account holder intended the particular action. A CSRF token is an additional request-integrity check that lets the server verify that a state-changing form was issued by the application for the current session.

## Local synthetic scenario

The page at `/security-lab/csrf` demonstrates accepting one proposal owned by the synthetic buyer `buyer@example.test` for the synthetic freelancer `lab-freelancer-b@example.test`. The action uses a fixed fixture discovered from its seeded synthetic identity and marker. The endpoint accepts no proposal ID, user ID, mode, or target from the client. The proposal's parent gig is closed and reserved for this lab scenario.

The three requests use the same fixture:

1. Missing token: the form has no CSRF token field.
2. Invalid token: the form submits a fixed harmless invalid sentinel.
3. Valid token: the form submits the server-generated Flask-WTF token in a hidden field.

The actual token is never written to evidence or lab-run records. The page reports only `missing`, `invalid`, or `valid`. The fixture can be returned to Pending through a separate CSRF-protected reset form.

## Vulnerable flow

When the stored CSRF mode is Vulnerable and every central lab gate condition passes, the dedicated `/security-lab/csrf/run` endpoint records the token state, intentionally ignores a missing or invalid-token result, and accepts the fixed synthetic proposal. This missing validation is the intentional vulnerability demonstrated by the lab. The action does not invoke the normal marketplace route and cannot select or change arbitrary proposal records.

The effective vulnerable mode requires all of the following:

- `LAB_ENABLE=true` as a parsed server setting.
- The application environment is development or testing.
- The socket peer is loopback.
- The persisted CSRF mode is Vulnerable.

Any missing, invalid, or unavailable setting resolves to Mitigated. The app's localhost request guard also rejects non-loopback requests. The page displays a localhost-only warning whenever vulnerable mode is effective.

## Mitigated flow

In Mitigated mode the same endpoint invokes Flask-WTF's server-side validator. Missing and invalid tokens receive HTTP 400 and the fixture stays Pending. A valid token is accepted and changes only the fixture to Accepted. The browser's JavaScript does not decide whether a token is valid.

Server-side validation is required because a client can alter, bypass, or omit JavaScript checks. Flask-WTF verifies the submitted token against the server-side session context before the action is allowed. Normal marketplace proposal decisions continue through the global CSRF protection and their normal authorization checks in both Security Lab modes.

## Difference from XSS and IDOR/BOLA

- **CSRF** abuses a browser's authenticated session to submit an unintended action. The key mitigation demonstrated here is server-side request-integrity validation.
- **XSS** causes attacker-controlled content to execute as script in a victim's browser in the application's origin. Output encoding and appropriate content controls address that class of issue.
- **IDOR/BOLA** occurs when an application fails to authorize access to a requested object. The key mitigation is object-level authorization on the server.

These issues can interact, but they are different failures and need separate controls. A CSRF token does not replace object authorization, and XSS prevention does not replace CSRF validation.

## Security Lab administration stays protected

Only the dedicated CSRF demonstration run endpoint is exempt from Flask-WTF's global request hook so it can model token behavior safely. It checks the central effective mode and manually invokes Flask-WTF's server-side validator in both modes. Login, profile editing, normal proposal actions, Security Lab administration, mode changes, and fixture reset remain globally CSRF-protected. The client cannot directly select the effective mode.

The evidence shown by the page is bounded to effective mode, token-state label, HTTP result, state-change flag, before/after fixture states, expected and observed behavior, mitigation status, and a UTC timestamp. `lab_runs` stores only the vulnerability key, effective mode, result status, and timestamp; it has no token or request-payload column.

## Test coverage

`tests/test_csrf_demo.py` checks missing, invalid, and valid token behavior in both modes; normal proposal CSRF protection; the lab-enable, environment, and loopback gates; fixture-only state change; owner authorization; non-disclosure of raw tokens; and CSRF protection for lab administration, mode changes, reset, and login.
