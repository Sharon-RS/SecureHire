# SecureHire Project Rules

## 1. Project purpose

SecureHire is a localhost-only academic web application security laboratory built as a freelance marketplace.

## 2. Technology

- Python 3.12
- Flask
- Flask-SQLAlchemy
- MySQL
- HTML, CSS, and JavaScript
- Bootstrap

Keep the project compatible with this stack unless the project owner approves a change.

## 3. Security demonstrations

- The application intentionally contains isolated vulnerable implementations for educational demonstration.
- Every vulnerability must also have a mitigated implementation.
- Keep vulnerable demonstration code separate from mitigated code and clearly document the purpose of intentionally vulnerable code.
- Lab demonstration logic must not weaken unrelated production-style functionality.
- Do not silently remove an intentionally vulnerable demonstration.

## 4. Vulnerable-mode safety

- Vulnerable mode may be effective only when an explicit lab-enable flag is enabled, the application is running outside production, and the request originates from loopback/local access.
- Vulnerable mode defaults to off. Never expose vulnerable functionality publicly.
- Invalid or missing security settings must resolve to mitigated mode (fail closed).
- Security Lab settings must be changed server-side; never let a client-side flag directly control the mode.
- Keep the Security Lab administration interface protected independently of the vulnerability it demonstrates.

## 5. Security controls

- Use parameterized queries for database access by default. Any intentionally vulnerable query must be isolated to its demonstration and use bounded synthetic data.
- Always enforce object-level authorization in normal application features.
- Keep upload validation enabled by default.
- Keep path-traversal protection enabled by default.
- Keep CSRF protection for the Security Lab administration interface active even when the CSRF demonstration is in vulnerable mode.
- Do not let demonstration switches disable security controls on unrelated routes or features.

## 6. Demonstration isolation

- Use synthetic users and synthetic data, and harmless proof-of-concept payloads.
- Keep demonstration files inside dedicated fixture directories. Never access files outside designated lab directories.
- Never execute uploaded files.
- Never use real credentials or secrets.
- Never target external websites or systems.
- Do not send demonstration data or payloads to third parties.
- Do not enable Flask's interactive debugger; demonstrate error disclosure with a controlled error page instead.

## 7. Testing

Each vulnerability must have tests for:

- Vulnerable mode behavior, limited to the intended safe demonstration.
- Mitigated mode behavior.
- The lab-enable and local-access gate, including proof that it blocks vulnerable mode when disabled or unavailable.
- Expected security behavior, including relevant authorization decisions, response behavior, or security headers.

Use synthetic fixtures and an isolated test database. Never run tests against production or a developer's real/shared database. Fix regressions before proceeding with further changes.

## 8. Authentication and sensitive data

- Store password hashes, never plaintext passwords.
- Use secure session handling.
- Do not log credentials, session tokens, or raw attack payloads.
- Keep secrets out of source control, test fixtures, and demonstration output.

## 9. Development workflow and documentation

- Run automated tests after major changes and fix regressions before proceeding.
- Keep the README and security demonstration documentation synchronized with the implementation, including each vulnerability's vulnerable behavior, mitigation, expected evidence, and test coverage.
- Before adding or changing a demonstration, document its purpose, isolation boundary, mitigation, visible evidence, and tests.
- Do not implement beyond the currently agreed milestone. Planning or setup requests do not authorize application implementation.