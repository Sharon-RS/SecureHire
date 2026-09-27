# Security Misconfiguration (Verbose Error Disclosure, Exposed Diagnostics, and Insecure Headers)

## What Security Misconfiguration is

Security misconfiguration (OWASP Top 10 A05:2021) occurs when web applications, frameworks, web servers, or cloud infrastructure are configured with insecure default settings, verbose debug logging, or exposed administrative and diagnostic endpoints.

This laboratory focuses on three high-impact, realistic misconfiguration weaknesses:

1. **Information Exposure Through an Error Message (CWE-209):** When uncaught exceptions occur in production, disclosing full stack traces, source file paths, database connection parameters, and internal variables directly to clients. Attackers use this reconnaissance to map out software dependencies, framework versions, internal network paths, and table structures.
2. **Insertion of Sensitive Information into Debugging Code / Exposed Diagnostic Endpoints (CWE-215):** Internal debugging tools, metric dashboards, or status endpoints (such as `/debug-status`) left accessible to users or deployed in production expose internal service topologies, background worker identities, and connection pools.
3. **Configuration Weakness / Insecure Default Server Headers (CWE-16):** Emitting revealing server banners (`Server` and `X-Powered-By`) advertises exact software versions and runtime daemons, facilitating automated vulnerability scanning.

In a freelance marketplace, exposing database connection strings, worker hostnames, or payment escrow gateway internals enables targeted attacks against escrow ledgers, contract databases, and user payment credentials.

## Local synthetic scenario and isolation boundary

The page at `/security-lab/security-misconfiguration` models an escrow contract processing engine inside the SecureHire freelance marketplace:

- **Synthetic Escrow Gateway:** A simulated background calculation engine handling synthetic milestone contracts, rate conversions, and ledger locks.
- **Dedicated Synthetic Fixtures:** Defined in `app/services/demos/security_misconfiguration/synthetic_data.py`. All connection strings (`mysql://synthetic_escrow_app:...@synthetic-db.internal:3306`), hostnames (`mock-worker-02.synthetic-lab.internal`), file paths (`/srv/securehire/synthetic_lab/...`), and stack traces are purely synthetic mock fixtures.
- **No Real System or Secret Access:** No real host environment variables, real filesystem files, real database credentials, or application secret keys are ever accessed, read, or disclosed.
- **Controlled Error Simulation (No Interactive Debugger):** In strict accordance with **AGENTS.md Rule 6**, Flask's interactive debugger (`app.debug = True` or the Werkzeug PIN debugger) is **never enabled**. Unhandled error disclosure is demonstrated via a controlled synthetic response renderer.
- **Strict Authentication Boundary Preserved:** In accordance with Security Lab architectural requirements, `/security-lab/security-misconfiguration/debug-status` requires authentication (`@login_required`). It is never exposed as an unauthenticated or public route; the vulnerable diagnostic exposure is demonstrated only after the normal lab access check succeeds.
- **Protection of Normal Marketplace Routes:** SecureHire's normal error handlers (`errors/400.html`, `errors/403.html`, `errors/404.html`, `errors/500.html`) and normal application routes (`/`, `/marketplace/gigs`, `/auth/login`, etc.) remain completely sanitized, unaffected, and fully protected in both modes.
- **Bounded Logging:** Execution results recorded in `LabRun` store only bounded, structured status summaries without persisting attack payloads or sensitive traces.

## Vulnerable flow

When `security_misconfiguration` mode is set to **Vulnerable** and all central safety gate conditions are met:

1. **Verbose Escrow Gateway Exception (CWE-209):**
   - The user triggers an unhandled escrow failure (e.g. `divide_by_zero` in contract calculation, `invalid_currency`, or synthetic database connection timeout).
   - The server returns `HTTP 500` disclosing the full synthetic stack trace, synthetic internal source paths, and a table of disclosed synthetic environment variables (`MOCK_DB_DSN`, `MOCK_WORKER_HOST`, `PYTHON_VERSION`).
   - Insecure headers are emitted: `Server: SecureHire-Synthetic-Lab-Daemon/1.0` and `X-Debug-Mode: Enabled`.
2. **Exposed Diagnostic Status Endpoint (CWE-215 / CWE-16):**
   - After passing standard authentication, an authenticated user requests `GET /security-lab/security-misconfiguration/debug-status`.
   - The server returns `HTTP 200 OK` with JSON disclosing internal mock service topology, worker node IDs, synthetic connection pool strings, and `debug_mode: true`.
   - Revealing headers (`X-Debug-Mode: Enabled`, `X-Powered-By: SecureHire-Synthetic-Lab-Daemon/1.0`) are attached.

Effective vulnerable mode strictly requires:
- `LAB_ENABLE=true` in server configuration.
- Non-production environment (`APP_ENV=development` or `APP_ENV=testing`).
- Loopback socket peer (`127.0.0.1` or `::1`). Forwarded proxy headers are rejected.
- Server-side persisted mode set to `vulnerable` in `security_modes`.

Any missing or invalid condition immediately causes the application to fail closed into **Mitigated** mode.

## Mitigated flow

In **Mitigated** mode (default and fail-closed state):

1. **Sanitized Error Handling (CWE-209 Mitigation):**
   - Triggering an unhandled escrow error produces a user-friendly, sanitized `HTTP 500` response.
   - The response provides a unique, opaque incident correlation reference (e.g. `INCIDENT-REF-9A3F12`).
   - Zero stack traces, source file paths, database credentials, or environment parameters are returned to the client.
2. **Disabled Diagnostic Status Endpoint (CWE-215 Mitigation):**
   - Requesting `GET /security-lab/security-misconfiguration/debug-status` returns `HTTP 403 Forbidden` with `{"error": "Forbidden: Diagnostic endpoint is disabled in secure/production mode."}`.
   - Diagnostic data and telemetry remain hidden behind strict access controls.
3. **Hardened Response Headers (CWE-16 Mitigation):**
   - No `X-Debug-Mode`, `X-Powered-By`, or custom server banner headers are emitted.
   - Standard security headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`) are strictly enforced.

## Safe classroom demonstration steps

1. Sign in to SecureHire as `admin@example.test`.
2. Open the Security Lab dashboard at `/security-lab`.
3. In **Mitigated** mode (default):
   - Navigate to `/security-lab/security-misconfiguration`.
   - Under **Part 1: Unhandled Escrow Gateway Exception**, select "Escrow Calculation: Zero-Division Exception" and click **Trigger Escrow Exception**.
   - Verify the response displays a sanitized error message with an incident correlation reference (`INCIDENT-REF-XXXX`) and zero stack traces or environment parameters.
   - Under **Part 2: Internal Diagnostic Status Endpoint**, click **Open /debug-status Endpoint**.
   - Verify the response returns `HTTP 403 Forbidden` with an access-denied JSON message.
4. Switch `security_misconfiguration` to **Vulnerable** mode on the dashboard.
5. In **Vulnerable** mode:
   - Select and trigger the same escrow exception.
   - Observe the disclosed internal synthetic stack trace, synthetic environment table (`MOCK_DB_DSN`, `MOCK_WORKER_HOST`), and response headers (`Server: SecureHire-Synthetic-Lab-Daemon/1.0`, `X-Debug-Mode: Enabled`).
   - Open `/security-lab/security-misconfiguration/debug-status`.
   - Observe the `HTTP 200 OK` JSON response detailing internal mock infrastructure topology and debug flags.
6. Verify normal application isolation:
   - Navigate to `/non-existent-route` and verify SecureHire's standard sanitized `404 Not Found` template is rendered with no stack traces or server banners.

## Automated test coverage summary

The test suite in `tests/test_security_misconfiguration.py` validates:
- **Mitigated Mode:** Sanitized error page, opaque incident ID, no stack traces or env variables, HTTP 403 on `/debug-status`, absence of debug/server banner headers.
- **Vulnerable Mode:** Verbose synthetic stack traces, synthetic env parameters, HTTP 200 on `/debug-status` with synthetic topology JSON, presence of debug headers.
- **Fail-Closed Central Gate:** Verification that `LAB_ENABLE=false`, non-loopback IP (`198.51.100.2`), or `APP_ENV=production` forces mitigated behavior even when the stored database setting is `vulnerable`.
- **Authentication Boundary:** Verification that `/debug-status` requires authentication (`@login_required`), denying or redirecting unauthenticated requests.
- **Regression Protection:** Normal error handlers (`404`, `500`) and normal marketplace routes retain full security and standard headers regardless of the lab state.
- **CSRF Protection:** Form validation rejects missing CSRF tokens on state-changing lab submissions.
- **Lab Run Logging:** Structured entries are written to `LabRun` without persisting raw payloads or sensitive traces.
