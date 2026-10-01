# SecureHire Dependency Inventory & Reduction Analysis

## 1. Executive Summary

A comprehensive dependency audit was conducted on **SecureHire** using AST static import inspection, `pip check`, `pip list`, and `npm ls`.
The evaluation categorized all dependencies into direct runtime, test/development, transitive, frontend, and build tooling.

Each direct dependency was rigorously analyzed to determine whether it could be removed without compromising application security, functionality, or packaging integrity.

---

## 2. Comprehensive Dependency Inventory

### 2.1 Direct Runtime Dependencies (Python)
These packages are explicitly declared in `pyproject.toml` and `requirements.txt`:

| Package | Declared Version | Installed Version | Primary Role / Justification | Direct Import Locations |
| :--- | :--- | :--- | :--- | :--- |
| **Flask** | `>=3.0,<4.0` | 3.1.3 | Core WSGI application framework, request routing, template rendering, and error handling. | `app/__init__.py`, `app/blueprints/*/routes.py` |
| **Flask-Login** | `>=0.6,<1.0` | 0.6.3 | Session authentication, user loading, and access control decorators (`@login_required`). | `app/__init__.py`, `app/blueprints/auth/routes.py`, `app/blueprints/marketplace/routes.py` |
| **Flask-Migrate** | `>=4.0,<5.0` | 4.1.0 | Database schema migration orchestration via Alembic. | `app/__init__.py` |
| **Flask-SQLAlchemy** | `>=3.1,<4.0` | 3.1.1 | SQLAlchemy ORM integration, session lifecycle management, and connection pooling. | `app/extensions.py`, `app/models/__init__.py` |
| **Flask-WTF** | `>=1.2,<2.0` | 1.3.0 | Form handling and CSRF protection token validation. | `app/__init__.py`, `app/extensions.py`, `app/forms/*.py` |
| **PyMySQL** | `>=1.1,<2.0` | 1.2.3 | MySQL DBAPI driver for relational persistence on MySQL 8.0. | Configured via `DATABASE_URL` dialect (`mysql+pymysql://`) |
| **email-validator** | `>=2.1,<3.0` | 2.3.0 | Validates email syntax in authentication registration forms (`wtforms.validators.Email`). | `app/forms/auth.py` |
| **python-dotenv** | `>=1.0,<2.0` | 1.2.3 | Loads local `.env` configuration securely without committing secrets. | `run_local.py`, `app/config.py`, `scripts/seed_demo.py` |

### 2.2 Development & Test Dependencies
| Package | Declared Version | Installed Version | Primary Role / Justification |
| :--- | :--- | :--- | :--- |
| **pytest** | `>=8.0` | 9.1.1 | Test discovery and test runner for the 219 automated tests. |

### 2.3 Transitive Dependencies (Resolved by Pip)
- **`alembic` (1.20.0)**: Migrations engine underneath Flask-Migrate.
- **`blinker` (1.9.0)**: Fast signal dispatching used by Flask.
- **`click` (8.5.0)**: CLI creation framework powering Flask commands (`flask db upgrade`, `flask run`).
- **`dnspython` (2.8.0)**: DNS resolution helper used by `email-validator`.
- **`idna` (3.20)**: Internationalized domain name support required by `email-validator`.
- **`itsdangerous` (2.2.0)**: Cryptographic data signing used for Flask session cookies.
- **`Jinja2` (3.1.6)**: Safe templating engine with HTML autoescaping enabled.
- **`Mako` (1.4.3)**: Template engine used by Alembic for migration script generation.
- **`MarkupSafe` (3.0.3)**: HTML string escaping library for Jinja2 and Werkzeug.
- **`SQLAlchemy` (2.1.1)**: Core ORM and SQL abstraction underneath Flask-SQLAlchemy.
- **`typing_extensions` (4.16.0)**: Backported type annotations for SQLAlchemy and Alembic.
- **`Werkzeug` (3.1.9)**: WSGI utility library handling HTTP headers, password hashing (`generate_password_hash`), and routing.
- **`WTForms` (3.2.2)**: Form field definitions and validation logic.
- **`colorama`, `iniconfig`, `packaging`, `pluggy`, `pygments`**: Supporting utilities required by pytest.

### 2.4 Frontend Assets
- **`bootstrap` (^5.3.0)** (npm): CSS/JS framework. Compiled via `scripts/copy_bootstrap.mjs` into `app/static/vendor/bootstrap`. No Node.js runtime is required in production or Docker runtime.

### 2.5 Security and Quality Tooling
- **`bandit` (1.9.4)**: Static security scanner.
- **`flake8` (7.4.1)**: Linting and code smell detection.

---

## 3. Dependency Reduction Analysis

### 3.1 Candidate Evaluation

Each direct dependency was reviewed against three criteria:
1. Is it actually imported or used in the application?
2. Can its functionality be replaced by standard library modules without compromising security?
3. Would removal introduce regressions, vulnerabilities, or broken workflows?

| Candidate Dependency | Imports Verified? | Can It Be Removed? | Detailed Technical Reason |
| :--- | :---: | :---: | :--- |
| **`Flask`** | Yes (Core) | **No** | Core application foundation. |
| **`Flask-Login`** | Yes | **No** | Provides secure session management, strong session protection, and `@login_required` access control. Removing it would require rewriting session security from scratch. |
| **`Flask-Migrate`** | Yes | **No** | Required for deterministic, version-controlled schema migrations (`flask db upgrade`). Removing it breaks database schema initialization in Docker and local setups. |
| **`Flask-SQLAlchemy`** | Yes | **No** | Required for ORM query parameterization, connection lifecycle, and transaction rollback on error. |
| **`Flask-WTF`** | Yes | **No** | Central to SecureHire's CSRF defense. Protects all forms and the Security Lab administrative switcher. |
| **`PyMySQL`** | Yes | **No** | Required MySQL DBAPI driver. The application's target database is MySQL; removing it prevents connecting to MySQL. |
| **`email-validator`** | Yes | **No** | WTForms' `Email()` validator explicitly requires this package at runtime. Removing it triggers an unhandled `ImportError` on user registration. |
| **`python-dotenv`** | Yes | **No** | Used to load `.env` securely. While `os.environ` handles environment variables in Docker, local academic development requires `.env` loading without exposing secrets. |
| **`pytest`** | Yes | **No** | Essential for automated test execution (219 tests). |

### 3.2 Before & After Comparison Table

| Metric | Before Audit | After Audit | Change | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **Direct Runtime Dependencies** | 8 | 8 | 0 | All 8 direct dependencies are strictly required. Zero redundant direct dependencies exist. |
| **Direct Dev Dependencies** | 1 | 1 | 0 | `pytest` is required for verification. |
| **Total Direct Dependencies** | 9 | 9 | 0 | Highly compact and lean dependency footprint. |
| **Total Installed in Clean Venv** | 27 | 27 | 0 | Minimal transitive overhead. |
| **Frontend Dependencies** | 1 (`bootstrap`) | 1 (`bootstrap`) | 0 | Build-time only, zero runtime node dependencies. |
| **Automated Test Results** | 210 passed | 219 passed | +9 | All tests pass, including 9 new CR-01 verification tests. |
| **Security Scan Status** | 0 high, 0 med in app | 0 high, 0 med in app | 0 | All findings remain restricted to intentional demo fixtures. |

### 3.3 Academic Conclusion
In accordance with professional software engineering principles, **no dependencies were artificially stripped**. Removing packages such as `email-validator` or `python-dotenv` would either cause runtime crashes during form validation or impair the local-only secret management architecture. SecureHire maintains a direct, minimal, and fully justified dependency manifest.
