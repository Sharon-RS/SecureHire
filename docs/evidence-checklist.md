# SecureHire Academic Evidence Collection Checklist

This checklist documents the exact evidence items, verification commands, and artifacts compiled for the academic deliverables of the SecureHire project.

| Item # | Evidence Item | Description / Verification Command | Artifact Location / Actual Status |
| :---: | :--- | :--- | :--- |
| **1** | **`requirements.txt` in repository** | Direct dependency specification matching SecureHire requirements. | Verified in repository root: `requirements.txt`. Clean install in temporary venv confirmed. |
| **2** | **`Dockerfile`** | Single-stage lightweight Python 3.12 runtime using vendored Bootstrap static assets (zero Node.js build dependency). | Verified in repository root: `Dockerfile`. Built with `docker compose build`. |
| **3** | **`docker-compose.yml`** | Container composition orchestrating `securehire-app` and isolated `MySQL 8.0` with health check and named volume. | Verified in repository root: `docker-compose.yml`. Validated via `docker compose config`. |
| **4** | **Docker containers running** | Status of containers running under Docker Compose. | `docker compose ps` -> `securehire-app-1` (Up 10s, port `127.0.0.1:5000->5000`), `securehire-db-1` (Up 26s, status healthy). |
| **5** | **SecureHire working in Docker** | Application accessible on `http://localhost:5000` backed by MySQL. | Fully verified via `scripts/docker_smoke_test.py`: **8/8 passed** (Reachability, Marketplace, CR-01 Category, CR-01 Budget, DB Auth, Dashboard, Profile, Gig detail/proposals/reviews). Shut down safely with `docker compose down`. |
| **6** | **Security / static analysis execution** | Command output from Bandit 1.9.4 security scanner. | `bandit -r app run_local.py -f json` -> Full scan logged in `docs/security-analysis.md`. |
| **7** | **Security findings & code smells** | Itemized breakdown of detected security items and Flake8 lint findings. | Detailed in `docs/security-analysis.md` (6 Bandit findings: 3 intentional educational labs, 3 informational; Flake8 code smells itemized and resolved on marketplace files). |
| **8** | **CR-01 feature before/after** | Marketplace filtering by category and maximum budget. | Before: Keyword search only (`?q=`). After: Combined keyword, category dropdown, and numeric max budget filtering (`?q=&category=&max_budget=`). |
| **9** | **Code smell before/after** | Refactoring of fat route / mixed concerns into dedicated `MarketplaceFilterCriteria` and `filter_open_gigs`. | Documented in `docs/security-analysis.md` and `docs/cr-01-traceability.md`. Flake8 errors on marketplace files reduced to 0. |
| **10** | **Internal module dependency analysis** | Internal connection graph, in/out degrees, and Mermaid architectural diagram. | Complete analysis in `docs/module-dependency-analysis.md`. 0 circular dependencies (DAG). |
| **11** | **Dependency inventory & reduction** | Full inventory of direct, dev, transitive, and frontend dependencies. | Documented in `docs/dependency-inventory.md`. Removed `bootstrap` npm dependency (-1 dependency, -3 config files, -1 Docker build stage). Reduced from 10 to 9 total dependencies. |
| **12** | **GitHub repository connection** | Connected remote repository on `master` branch. | Remote: `https://github.com/Sharon-RS/SecureHire.git` (branch `master`). |
| **13** | **CI workflow verification** | GitHub Actions workflow executing full test suite and Bandit security scan. | Workflow: `.github/workflows/ci.yml`. Verified passing: 219 tests passed. |
| **14** | **CD workflow verification** | GitHub Actions workflow producing release package artifact (`securehire-release`). | Workflow: `.github/workflows/cd.yml`. Release artifact created in `dist/`. |
| **15** | **Final automated test execution** | Full execution of automated tests. | `python -m pytest -q` -> **219 passed in 49.41s** (up from 210 baseline, 100% pass rate). |
