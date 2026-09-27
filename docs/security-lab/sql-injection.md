# SQL Injection demonstration

## Purpose

This first vulnerability module demonstrates how inserting a search value into SQL text can change the meaning of a read-only gig search. It runs at the authenticated Security Lab page and uses only synthetic fixture gigs.

## Isolation boundary

- The vulnerable query reads only security_lab_gig_fixtures, a dedicated table seeded with three synthetic rows by the SQLi migration.
- The query is a single SELECT with a static limit of 20. The lab route provides no write operation.
- The search form accepts ordinary ASCII search terms or the exact harmless proof of concept: ' OR '1'='1. Other SQL punctuation is rejected before either query path runs.
- Vulnerable code lives in app/services/demos/sqli/vulnerable.py and is called only after the central server-side mode service resolves SQLi as vulnerable.
- The normal marketplace uses its existing ORM repository and is not affected by the lab mode.

## Demonstration behavior

Search for Python to see synthetic title/category matches. In vulnerable mode, the approved proof of concept changes the interpolated title/category conditions and matches all three synthetic rows. The unsafe implementation is intentionally limited to the fixture table and result cap.

## Mitigation

Mitigated mode is the default and uses SQLAlchemy ORM comparisons, which bind the submitted value as literal data. The approved proof of concept then matches no title or category. The unsafe SELECT and safe ORM implementation are separate modules.

The effective vulnerable mode still requires the existing persisted SQLi setting, LAB_ENABLE=true, a development or testing application environment, and a loopback socket peer. Missing or invalid settings resolve to mitigated mode. The form cannot change the mode.

## Visible evidence

After a search, the page displays the submitted value with HTML escaping, effective mode, result count, expected and observed behavior, mitigation state, and bounded lab-run status. It does not render SQL text. The lab_runs record stores only the existing bounded result vocabulary; it has no payload column and never stores the submitted search string.

## Tests

The isolated SQLite tests cover normal mitigated search, literal handling of the proof of concept, vulnerable behavior with every gate condition met, disabled and production gates, non-loopback rejection, server-only mode selection, input allowlisting, CSRF, read-only fixture behavior, payload-free records, and unchanged marketplace search. Run the full suite with python -m pytest.
