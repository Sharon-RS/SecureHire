# SecureHire Academic Evidence Collection Checklist

This checklist documents the exact evidence items, verification commands, and artifacts compiled for the academic deliverables of the SecureHire project.

| Item # | Evidence Item | Description / Verification Command | Artifact Location / Actual Status |
| :---: | :--- | :--- | :--- |
| **1** | **`requirements.txt` in repository** | Direct dependency specification matching SecureHire requirements. | Verified in repository root: `requirements.txt`. Clean install in temporary venv confirmed. |
| **2** | **`Dockerfile`** | Multi-stage Dockerfile compiling Bootstrap assets in Node stage and deploying Python 3.12 runtime. | Verified in repository root: `Dockerfile`. |
| **3** | **`docker-compose.yml`** | Container composition orchestrating `securehire-app` and isolated `MySQL 8.0` with health check and named volume. | Verified in repository root: `docker-compose.yml`. Validated via `docker compose config`. |
| **4** | **Docker containers running** | Status of containers running under Docker Compose. | `docker compose ps` / Command ready: Requires starting Docker Desktop on Windows. |
| **5** | **SecureHire working in Docker** | Application accessible on `http://localhost:5000` backed by MySQL. | Docker entrypoint with automatic migration (`flask db upgrade`) and demo seeding (`seed_demo.py`). |
| **6** | **Security / static analysis execution** | Command output from Bandit 1.9.4 security scanner. | `bandit -r app run_local.py -f json` -> Full scan logged in `docs/security-analysis.md`. |
| **7** | **Security findings & code smells** | Itemized breakdown of detected security items and Flake8 lint findings. | Detailed in `docs/security-analysis.md` (6 Bandit findings: 3 intentional educational labs, 3 informational; Flake8 code smells itemized). |
| **8** | **CR-01 feature before/after** | Marketplace filtering by category and maximum budget. | Before: Keyword search only (`?q=`). After: Combined keyword, category dropdown, and numeric max budget filtering (`?q=&category=&max_budget=`). |
| **9** | **Code smell before/after** | Refactoring of fat route / mixed concerns into dedicated `MarketplaceFilterCriteria` and `filter_open_gigs`. | Documented in `docs/security-analysis.md` and `docs/cr-01-traceability.md`. Flake8 errors on marketplace files reduced to 0. |
| **10** | **Internal module dependency analysis** | Internal connection graph, in/out degrees, and Mermaid architectural diagram. | Complete analysis in `docs/module-dependency-analysis.md`. 0 circular dependencies (DAG). |
| **11** | **Dependency inventory & reduction** | Full inventory of direct, dev, transitive, and frontend dependencies. | Documented in `docs/dependency-inventory.md`. Confirmed 8 direct runtime + 1 dev; zero redundant dependencies. |
| **12** | **GitHub repository connection** | Connected remote repository on `master` branch. | Remote: `https://github.com/Sharon-RS/SecureHire.git` (branch `master`). |
| **13** | **CI workflow verification** | GitHub Actions workflow executing full test suite and Bandit security scan. | Workflow: `.github/workflows/ci.yml`. Verified passing: 219 tests passed. |
| **14** | **CD workflow verification** | GitHub Actions workflow producing release package artifact (`securehire-release`). | Workflow: `.github/workflows/cd.yml`. Release artifact created in `dist/`. |
| **15** | **Final automated test execution** | Full execution of automated tests. | `python -m pytest -q` -> **219 passed in 51.62s** (up from 210 baseline). |
