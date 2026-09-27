# IDOR / BOLA demonstration

## Purpose and isolation

The demo uses two seeded synthetic freelancer accounts and two proposal rows in a dedicated, closed synthetic gig. The canonical page is /security-lab/idor. The selectable proposal IDs are built server-side from that fixture and cannot reference ordinary marketplace proposals. The page is read-only and exposes only a bounded projection of fixture fields.

The authenticated requester comes from Flask-Login’s server-side session. The browser cannot choose the requester identity or the effective security mode. The vulnerable route is available only through the centralized mode service: the stored IDOR/BOLA mode must be Vulnerable, LAB_ENABLE must be explicitly true, the environment must be development or testing, and the accepted socket peer must be loopback. The application’s local Host and peer checks also remain active. Invalid or missing gate settings resolve to Mitigated.

## Vulnerable behavior

The isolated vulnerable implementation accepts a proposal ID from the fixture allowlist and reads that proposal without comparing its freelancer owner to the authenticated requester. With Freelancer A signed in, selecting Freelancer B’s fixture returns bounded synthetic proposal fields with HTTP 200.

The vulnerable function is in app/services/demos/idor_bola/vulnerable.py. Its fixture allowlist is a safety boundary for the demonstration; the missing object-owner check is the intentional vulnerability.

## Mitigation

The separate implementation in app/services/demos/idor_bola/mitigated.py checks proposal.freelancer_id against the authenticated session user ID before returning any proposal fields. A cross-user lab request receives HTTP 403 and no proposal contents. A requester can read their own fixture proposal.

The normal marketplace route /proposals/<id> retains its existing authorization check for the submitting freelancer and gig owner in either lab mode. The demo does not modify proposal data or weaken marketplace behavior.

## Visible evidence

After a request, the page shows the effective mode, requester persona, selected fixture owner, authorization decision, HTTP result, and bounded lab-run status. Successful reads also show the limited synthetic proposal projection. Denied requests explicitly report that proposal contents were not returned. Lab-run records contain only the module, mode, and bounded result status; they do not store target IDs or request payloads.

## Setup

1. Configure the local MySQL database and apply the existing migrations.
2. Set a synthetic SECUREHIRE_DEMO_PASSWORD in the local .env.
3. Run python -m scripts.seed_demo. The command idempotently creates Freelancer B and the two fixture proposals.
4. Sign in as freelancer@example.test or lab-freelancer-b@example.test.
5. Open http://127.0.0.1:5000/security-lab/idor.
6. For the vulnerable comparison only, set LAB_ENABLE=true, restart the local server, and set IDOR / BOLA to Vulnerable on the administrator Security Lab dashboard. Return the stored mode to Mitigated and the flag to false after the demonstration.

The demo reuses the existing gigs and proposals schema, so this milestone adds no migration.

## Test coverage

tests/test_idor_bola.py covers fixture isolation, vulnerable cross-user reads, mitigated denials, own-object access, disabled/invalid/production/non-loopback gates, client-supplied identity and mode tampering, read-only behavior, CSRF, server-side mode administration, and proof that normal marketplace proposal authorization remains active while lab mode is vulnerable.
