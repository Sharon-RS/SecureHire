# Client Change Request CR-01: End-to-End Traceability Matrix

## 1. Traceability Flow Diagram

```
CR-01
  │
  ▼
Requirement Specification
  │
  ▼
Use Case: Marketplace Gig Filtering
  │
  ▼
Implementation Modules
  ├── app/services/marketplace.py (MarketplaceFilterCriteria, filter_open_gigs)
  ├── app/repositories/marketplace.py (search_open_gigs, distinct_open_categories)
  ├── app/blueprints/marketplace/routes.py (browse_gigs)
  └── app/templates/marketplace/gigs.html (Filter Form UI)
  │
  ▼
Security Controls
  ├── ORM Parameterization (Zero SQL Injection)
  ├── Input Sanitization & Bounds Checking (Category <= 80, Decimal bounds)
  └── Fail-Safe Error Handling (Graceful handling of non-numeric/negative inputs)
  │
  ▼
Automated Test Verification
  └── 9 Dedicated Test Cases (tests/test_marketplace.py) -> 219 Total Suite Passing
  │
  ▼
Static Security Scan
  └── Bandit 1.9.4 (0 findings in marketplace modules) & Flake8 (0 code smells)
  │
  ▼
Jira Issue Specification (Ready for backlog creation)
  │
  ▼
CI/CD Result
  └── GitHub Actions CI (219 passed) + CD Release Package Generation
  │
  ▼
Documentation Evidence
  └── docs/cr-01-traceability.md, docs/security-analysis.md, README.md
```

---

## 2. Requirement Specification

- **Change Request Identifier**: CR-01
- **Client Request Statement**:
  > *"Clients want to filter marketplace gigs by category and maximum budget so that they can narrow results to suitable freelance services."*
- **Scope**:
  Public and authenticated marketplace browse view (`/gigs`). Allows clients and freelancers to narrow open opportunities without altering underlying database schema or gig ownership rules.

---

## 3. Implementation Details

| Layer | File Path | Implementation Details |
| :--- | :--- | :--- |
| **Service Layer** | `app/services/marketplace.py` | Added `MarketplaceFilterCriteria` dataclass with factory `.from_params()` that safely parses `q`, `category`, and `max_budget`. Added `filter_open_gigs()` service function. |
| **Repository Layer** | `app/repositories/marketplace.py` | Updated `search_open_gigs(query, category, max_budget)` with parameterized SQLAlchemy `.filter()` conditions. Added `distinct_open_categories()` helper. |
| **Presentation Layer** | `app/blueprints/marketplace/routes.py` | Refactored `browse_gigs()` route to delegate criteria extraction to the service layer and pass categories to the view. |
| **Template Layer** | `app/templates/marketplace/gigs.html` | Enhanced filter UI with keywords search, category dropdown, numeric max budget input, filter and clear buttons, and active filter summaries. |

---

## 4. Security Controls Enforced

1. **SQL Injection Defense (CWE-89)**:
   - Filter criteria are never concatenated into raw SQL strings.
   - All parameters (`term`, `category`, `max_budget`) are passed directly through SQLAlchemy ORM parameter binding (`statement.filter(Gig.category == cat)` and `statement.filter(Gig.budget <= max_budget)`).
2. **Input Validation and Length Bounds**:
   - `q`: Trimmed and capped at 100 characters (`MAX_SEARCH_QUERY_LENGTH`).
   - `category`: Trimmed and capped at 80 characters (`MAX_CATEGORY_FILTER_LENGTH`).
   - `max_budget`: Parsed using Python's `Decimal` type; checked against `MIN_BUDGET_BOUND` (`0.00`) and `MAX_BUDGET_BOUND` (`99,999,999.99`).
3. **Graceful Fail-Safe Handling**:
   - Invalid, negative, or unparseable budget inputs (e.g. `"-50"`, `"abc"`, SQLi payloads) do not throw unhandled exceptions or expose internal stack traces; they resolve safely to `None` and the search proceeds without budget restriction.
4. **State and Authorization Invariance**:
   - The browsing feature is read-only (`GET /gigs`). It does not modify application state or weaken role-based access control.

---

## 5. Automated Test Cases

The following 9 test cases were added to `tests/test_marketplace.py`, bringing the verified test count to **219 passed**:

1. `test_cr01_filter_gigs_no_filters`: Verifies that browsing without parameters returns all open gigs.
2. `test_cr01_filter_gigs_by_category`: Verifies exact category filtering.
3. `test_cr01_filter_gigs_by_max_budget`: Verifies numeric budget upper-bound filtering.
4. `test_cr01_filter_gigs_combined_category_and_budget`: Verifies intersection of category and max budget filters.
5. `test_cr01_filter_gigs_invalid_category`: Verifies safe empty-state response when an unknown category is requested.
6. `test_cr01_filter_gigs_invalid_or_negative_budget`: Verifies negative or non-numeric budget parameters are handled gracefully.
7. `test_cr01_filter_gigs_large_budget`: Verifies handling of extreme values without database numeric overflow errors.
8. `test_cr01_filter_gigs_sqli_input_treated_as_data`: Verifies SQL injection payloads in category and budget fields are treated strictly as data.
9. `test_cr01_normal_marketplace_behavior_regression_protection`: Verifies combined keyword, category, and budget searches, ensuring no regressions.

---

## 6. Jira-Ready Issue Specification

```text
Issue Type: Story
Summary: Filter marketplace gigs by category and maximum budget (CR-01)
Component: Marketplace, Search & Filtering

Description:
As a prospective client or freelancer browsing SecureHire,
I want to filter open marketplace gigs by category and maximum budget,
So that I can quickly find project opportunities matching my criteria.

Acceptance Criteria:
1. The marketplace search bar includes inputs for Keywords, Category, and Maximum Budget.
2. The category input provides a dropdown populated with active marketplace categories.
3. The budget filter restricts results to open gigs with budget <= maximum budget.
4. Supplying both category and maximum budget restricts results to their intersection.
5. Invalid, non-numeric, or negative budgets are gracefully handled without leaking internal errors.
6. SQL injection attempts are completely neutralized by ORM parameter binding.
7. Clearing filters resets the board to show all open gigs.

Security Requirements:
- Use SQLAlchemy ORM parameter binding for all dynamic filter criteria.
- Enforce length and numeric boundary validation on all filter inputs.
- Keep the browse route strictly read-only (GET).

Test Plan:
- Unit/integration tests covering no-filters, category, budget, combined filters, boundary conditions, and SQLi payload resilience.
```
