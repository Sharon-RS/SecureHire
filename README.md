# SecureHire

SecureHire is a localhost-only academic freelance marketplace with a Security Lab framework. Milestone 5 adds an isolated Reflected XSS demonstration. SQL Injection, Stored XSS, and Reflected XSS have vulnerable and mitigated paths; the other seven vulnerability modules remain placeholders.

## Technology

- Python 3.12+
- Flask and Flask-SQLAlchemy
- Flask-Migrate
- MySQL (PyMySQL driver)
- Flask-WTF CSRF protection and Flask-Login
- Jinja, Bootstrap 5, HTML, CSS, and JavaScript
- pytest

## Base features

- Buyer, Freelancer, and Admin account roles.
- Registration, login, POST-only logout, profile viewing, and profile editing.
- Public profile cards show only display name, role, bio, and skills.
- Buyers can create, edit, and close their own gigs.
- Freelancers can search open gigs and submit one proposal per gig.
- Gig owners can review proposals and accept or reject a pending proposal.
- Participants in an accepted proposal can publish one public review of the other participant.
- Review identity and authorization are derived server-side; review text is always automatically escaped.
- Proposal details are visible only to the submitting Freelancer and the gig owner.
- Authorization is enforced on the server for every private resource and state change.

Normal security controls are enabled: password hashes, CSRF-protected forms, parameterized ORM queries, role and ownership checks, session cookie protections, loopback-only access, Jinja autoescaping, and security response headers.

## Folder structure

```text
app/
  blueprints/       HTTP routes for authentication, marketplace, and Security Lab
  forms/            Validated CSRF-protected forms
  models/           SQLAlchemy models for marketplace and Security Lab records
  repositories/     Read/query helpers
  services/         Account, marketplace, and centralized security-mode rules
  static/           Local styles/scripts and copied Bootstrap distribution
  templates/        Shared layout and page templates
instance/           Local-only runtime data (ignored by Git)
migrations/         Flask-Migrate/Alembic migrations
scripts/            Synthetic seed command and local Bootstrap asset copier
tests/              Isolated pytest tests
```

## Local setup (Windows PowerShell)

Use Python 3.12 or newer. Create and activate a virtual environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Install Bootstrap into the local Node dependency folder and copy its assets into Flask's static directory. The app serves these local copies; templates do not load a CDN.

```powershell
npm install
npm run assets
```

Copy the example environment file and replace placeholders with local values:

```powershell
Copy-Item .env.example .env
```

Set SECRET_KEY to a randomly generated value and DATABASE_URL to the local MySQL connection. SESSION_COOKIE_SECURE=false is for the built-in plain-HTTP loopback server; set it to true if serving local HTTPS.

Example local MySQL setup (run in a MySQL client; replace the placeholder password):

```sql
CREATE DATABASE securehire_dev CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'securehire_app'@'127.0.0.1' IDENTIFIED BY 'replace-with-a-local-password';
GRANT ALL PRIVILEGES ON securehire_dev.* TO 'securehire_app'@'127.0.0.1';
```

The example connection string in .env.example uses that database and user. Do not put a real password in source control.

## Database and seed data

After MySQL is configured in .env, apply migrations:

```powershell
python -m flask --app run_local:app db upgrade
```

Seed idempotent synthetic marketplace records:

```powershell
python -m scripts.seed_demo
```

The seed command reads SECUREHIRE_DEMO_PASSWORD from the local .env, hashes it before storage, and does not print it. For a local classroom demonstration, the synthetic accounts are:

| Role | Email |
|---|---|
| Admin | admin@example.test |
| Buyer | buyer@example.test |
| Freelancer | freelancer@example.test |

All three use the local-only value you assign to SECUREHIRE_DEMO_PASSWORD (for example, SecureHire-Demo-Only-2026!). These are synthetic development accounts, not production credentials.

## Run the application

```powershell
python run_local.py
```

Open http://127.0.0.1:5000. The launcher binds only to loopback and disables Flask debug mode. The request gate checks the socket peer address and an allowed Host value; forwarded proxy headers are ignored.

## Tests

Tests use a fresh in-memory SQLite database by default, separate from the development MySQL URL. To run them:

```powershell
python -m pytest
```

To exercise tests against MySQL, create a separate empty test database and set TEST_DATABASE_URL to that database. Never point it at securehire_dev or any shared/production database.

The test suite covers normal reviews, marketplace isolation, SQLi, Stored XSS, and Reflected XSS behavior, vulnerable-mode gates, authorization, CSRF, security headers, and payload-free lab-run records.

## Security Lab framework

The authenticated **Admin** account can open `/security-lab`. Buyers and freelancers cannot access the control dashboard or change modes. Authenticated users can run the SQL Injection, Stored XSS, and Reflected XSS demonstrations; the other module pages are placeholders.

After applying migrations and seeding synthetic accounts, sign in as `admin@example.test` using the local-only `SECUREHIRE_DEMO_PASSWORD` value. The dashboard starts with every module effectively **MITIGATED**. Mode selections are stored server-side and written to `security_audit_log`; each module is changed independently.

`LAB_ENABLE=false` is the default. A stored vulnerable setting remains effectively mitigated unless the server configuration explicitly enables the flag, the app environment is development or testing, and the accepted socket peer is loopback. Host, query, form, cookie, and proxy headers do not establish locality or select mode. Changing the setting requires an authenticated admin, a valid server-validated mode, and a CSRF token.

To exercise SQL Injection, set `LAB_ENABLE=true` in the local `.env`, restart the server, select Vulnerable for SQLi, and open its demonstration page. It uses only the dedicated synthetic fixture table and the approved harmless input. Return SQLi to Mitigated when finished. See [docs/security-lab/sql-injection.md](docs/security-lab/sql-injection.md).

To exercise Stored XSS, select Vulnerable for Stored XSS and open `/security-lab/stored-xss`. Submit the exact harmless value shown on the page; in effectively vulnerable mode, the isolated lab result displays the local alert. Set Stored XSS to Mitigated and reload to see the same stored value displayed as text. Normal marketplace reviews remain escaped in either mode. Set the stored mode back to Mitigated and `LAB_ENABLE=false` when finished. See [docs/security-lab/stored-xss.md](docs/security-lab/stored-xss.md) for isolation, behavior, evidence, and test coverage.

To exercise Reflected XSS, select Vulnerable for Reflected XSS and open `/security-lab/reflected-xss`. Submit the approved harmless local payload to see its response-only reflection; when vulnerable mode is effective, the page can display the local alert. Select Mitigated and submit the same input to see it encoded as text. The CSP exception is scoped to only the vulnerable response containing that approved input. Normal marketplace search stays secure in either mode. Return the stored setting to Mitigated and set `LAB_ENABLE=false` when finished. See [docs/security-lab/reflected-xss.md](docs/security-lab/reflected-xss.md).

## Security milestone boundary

Implemented demonstrations: SQL Injection, Stored XSS, and Reflected XSS. The remaining seven modules—IDOR/BOLA, CSRF, file upload, path traversal, clickjacking, authentication/session security, and security misconfiguration—remain placeholders. The Security Lab administration interface retains CSRF protection independently of the CSRF demonstration. Lab run records accept only bounded status values and do not store request payloads.
