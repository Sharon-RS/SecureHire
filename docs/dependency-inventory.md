# SecureHire Dependency Inventory & Reduction Analysis

## 1. Executive Summary

A comprehensive dependency audit was conducted on **SecureHire** using AST static import inspection, `pip check`, `pip list`, and build-tooling analysis.
The evaluation categorized all dependencies into direct runtime, test/development, transitive, frontend, and build tooling.

In compliance with academic faculty requirements to reduce dependencies without compromising functionality, a genuine dependency reduction was identified, implemented, and fully validated:
- The frontend **`bootstrap` npm dependency** (`^5.3.0`), along with `package.json`, `package-lock.json`, `scripts/copy_bootstrap.mjs`, and the multi-stage Node.js Docker build stage were **completely eliminated**.
- The compiled Bootstrap assets (`bootstrap.min.css`, `bootstrap.bundle.min.js`, and `LICENSE`) were vendored directly into `app/static/vendor/bootstrap/`.
- All 219 automated tests, static security scans (Bandit/Flake8), Docker builds, and runtime container smoke tests pass with zero regressions.

---

## 2. Comprehensive Dependency Inventory (Current State)

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
- **Bootstrap 5.3.3**: Vendored locally in `app/static/vendor/bootstrap/` (`css/bootstrap.min.css`, `js/bootstrap.bundle.min.js`, `LICENSE`).
- **Node.js / npm Dependencies**: **0** (Removed).

---

## 3. Detailed Audit of the Bootstrap npm Dependency

The evaluation specifically investigated the 6 faculty questions regarding the frontend Bootstrap dependency:

1. **Is Bootstrap actually loaded from local static files?**
   - **Yes**. `app/templates/base.html` explicitly links:
     `<link rel="stylesheet" href="{{ url_for('static', filename='vendor/bootstrap/css/bootstrap.min.css') }}">`
     and
     `<script src="{{ url_for('static', filename='vendor/bootstrap/js/bootstrap.bundle.min.js') }}"></script>`.
   - The application does not load Bootstrap from an external CDN.

2. **Are the Bootstrap files already bundled/copied into `app/static`?**
   - **Yes**. `app/static/vendor/bootstrap/css/bootstrap.min.css` (232,111 bytes), `app/static/vendor/bootstrap/js/bootstrap.bundle.min.js` (80,496 bytes), and `app/static/vendor/bootstrap/LICENSE` (1,093 bytes) exist in the local project tree.

3. **Is npm only being used during development/build and not required by the application?**
   - **Yes**. Flask serves static files directly from `app/static/`. At runtime, neither Node.js nor npm is invoked.

4. **Can the project continue working without the bootstrap npm dependency?**
   - **Yes**. By committing the vendor assets directly to Git (vendoring), the application retains full styling and JavaScript interactivity without any dependency on npm or Node.js.

5. **Can `scripts/copy_bootstrap.mjs` be removed or simplified?**
   - **Yes**. `scripts/copy_bootstrap.mjs` was solely an artifact copying tool between `node_modules` and `app/static`. It has been safely removed.

6. **Can `package.json`/`package-lock.json` be removed if they are no longer required?**
   - **Yes**. With `bootstrap` removed, there are zero remaining npm dependencies. Both `package.json` and `package-lock.json` were safely deleted.

---

## 4. Verification and Dependency Reduction Record

| Metric | Before Audit & Reduction | After Audit & Reduction | Change |
| :--- | :---: | :---: | :---: |
| **Direct Runtime Dependencies (Python)** | 8 | 8 | 0 |
| **Direct Dev Dependencies (Python)** | 1 (`pytest`) | 1 (`pytest`) | 0 |
| **Frontend Build-time Dependencies (npm)** | 1 (`bootstrap` ^5.3.0) | 0 | **-1** |
| **Total Project Dependencies** | 10 | 9 | **-1** |
| **Build Configuration Files** | `package.json`, `package-lock.json`, `scripts/copy_bootstrap.mjs` | None (Removed) | **-3 files** |
| **Docker Build Architecture** | Multi-stage (`node:20-slim` + `python:3.12-slim`) | Single-stage (`python:3.12-slim`) | **-1 stage** |
| **Automated Test Suite** | 219 passed | 219 passed in 49.41s | Identical (0 regressions) |
| **Security Scanning (Bandit)** | 0 High, 0 Med in core app | 0 High, 0 Med in core app | Identical |
| **Flake8 Quality Scan** | 0 errors on marketplace files | 0 errors on marketplace files | Identical |
| **Docker Runtime Smoke Tests** | Not verified | **8/8 passed** on `localhost:5000` | Fully verified |
| **CI/CD Pipeline Compatibility** | Verified with Node installed | Verified with pure Python 3.12 | Streamlined |

### 4.1 Dependency Reduction Specification

- **Before**: 8 direct runtime dependencies, 1 development dependency, 1 frontend build-time dependency (10 total), 0 dependencies removed.
- **After**: 8 direct runtime dependencies, 1 development dependency, 0 frontend build-time dependencies (9 total), 1 dependency removed.
- **Removed**: `bootstrap` (^5.3.0 npm package), along with `package.json`, `package-lock.json`, and `scripts/copy_bootstrap.mjs`.
- **Reason**: Static distribution files were vendored directly into `app/static/vendor/bootstrap/`. Eliminating the Node.js/npm toolchain simplified the build process, reduced Docker image attack surface and build time, removed an entire Docker build stage, and removed potential npm supply-chain vulnerabilities without modifying any UI appearance, template logic, or application code.
- **Tests**: 219 passed in 49.41s.
- **Security scan**: Bandit 0 findings in core app; Flake8 0 errors.
- **Docker**: Single-stage `python:3.12-slim` image built cleanly; `docker compose up -d` launched `securehire-app-1` and `securehire-db-1` (healthy); 8/8 smoke tests passed on `http://localhost:5000`.
- **CI/CD**: `.github/workflows/ci.yml` passes cleanly on Python 3.12 with zero Node.js dependencies.
