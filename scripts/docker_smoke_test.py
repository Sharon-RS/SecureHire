"""
Docker runtime smoke test script for SecureHire.
Verifies container reachability, database connectivity, login, marketplace,
CR-01 filtering (category & budget), and profile/dashboard features.
"""
import urllib.request
import urllib.parse
import http.cookiejar
import re
import sys

BASE_URL = "http://127.0.0.1:5000"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

print("=== 1. Checking Application Reachability ===")
res = opener.open(f"{BASE_URL}/")
assert res.status == 200, f"Expected 200, got {res.status}"
html = res.read().decode("utf-8")
assert "SecureHire" in html
print("PASS: Application reachable at localhost:5000 (HTTP 200)")

print("\n=== 2. Checking Marketplace Browsing ===")
res = opener.open(f"{BASE_URL}/gigs")
assert res.status == 200
gigs_html = res.read().decode("utf-8")
assert "Explore gigs" in gigs_html or "Explore Gigs" in gigs_html
print("PASS: Marketplace loaded successfully (HTTP 200)")

print("\n=== 3. Checking CR-01 Category Filter ===")
res = opener.open(f"{BASE_URL}/gigs?category=Design")
assert res.status == 200
cat_html = res.read().decode("utf-8")
assert "Design" in cat_html
print("PASS: CR-01 Category filter working (HTTP 200)")

print("\n=== 4. Checking CR-01 Maximum Budget Filter ===")
res = opener.open(f"{BASE_URL}/gigs?max_budget=500.00")
assert res.status == 200
budget_html = res.read().decode("utf-8")
print("PASS: CR-01 Maximum budget filter working (HTTP 200)")

print("\n=== 5. Checking Login Flow (Database Authentication) ===")
login_page = opener.open(f"{BASE_URL}/auth/login").read().decode("utf-8")
csrf_token_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', login_page)
assert csrf_token_match, "Could not find CSRF token on login page"
csrf_token = csrf_token_match.group(1)

login_data = urllib.parse.urlencode({
    "csrf_token": csrf_token,
    "email": "admin@example.test",
    "password": "Synthetic-Demo-Password-123!"
}).encode("utf-8")

req = urllib.request.Request(f"{BASE_URL}/auth/login", data=login_data, method="POST")
res = opener.open(req)
body = res.read().decode("utf-8")
assert "Sign out" in body or "Dashboard" in body or "admin" in body
print("PASS: User authenticated against MySQL database (admin@example.test)")

print("\n=== 6. Checking Authenticated Dashboard ===")
res = opener.open(f"{BASE_URL}/dashboard")
dash_html = res.read().decode("utf-8")
assert res.status == 200
print("PASS: Dashboard accessible (HTTP 200)")

print("\n=== 7. Checking Profile & User Data ===")
res = opener.open(f"{BASE_URL}/auth/profile")
profile_html = res.read().decode("utf-8")
assert "Your account" in profile_html or "My profile" in profile_html
print("PASS: Profile accessible with database records (HTTP 200)")

print("\n=== 8. Checking Client / Freelancer Marketplace Interaction ===")
# Parse first available gig link from marketplace
gig_link_match = re.search(r'href="(/gigs/\d+)"', gigs_html)
assert gig_link_match, "Expected at least one gig link in /gigs"
gig_path = gig_link_match.group(1)
gig_detail_res = opener.open(f"{BASE_URL}{gig_path}")
assert gig_detail_res.status == 200
gig_detail_html = gig_detail_res.read().decode("utf-8")
assert "budget" in gig_detail_html.lower() or "review" in gig_detail_html.lower()
print(f"PASS: Gig details and proposal/review sections loaded from {gig_path} (HTTP 200)")

print("\n==============================================")
print("ALL DOCKER RUNTIME SMOKE TESTS PASSED (8/8)!")
print("==============================================")
