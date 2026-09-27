# Path Traversal

## What Path Traversal is

Path Traversal (also known as Directory Traversal or Dot-Dot-Slash, CWE-22) occurs when an application uses user-supplied input to construct a file path without adequate sanitization, canonicalization, and boundary verification.

In freelance marketplaces, applications frequently display public documents, contract templates, sample invoices, or platform guidelines. If an application allows untrusted input to specify filesystem paths:

1. **Information Disclosure:** An attacker can supply dot-dot-slash traversal sequences (`../`, `..\`, or URL-encoded equivalents) to traverse outside the designated document directory and access sensitive server configuration files, source code, credentials, or private client contracts.
2. **System File Exposure:** On unhardened servers, traversal can reach host operating system files (e.g., `C:\Windows\System32\...` or `/etc/passwd`), exposing operating system state or configuration details.
3. **Arbitrary File Access & Overwrite:** When paired with write operations, traversal can allow arbitrary file creation or modification, potentially leading to remote code execution.

## Local synthetic scenario and isolation boundary

The page at `/security-lab/path-traversal` demonstrates path traversal in a controlled freelance document viewer scenario.

In accordance with **AGENTS.md Rule 6**:
- **Dedicated Lab Directory:** All demonstration files reside strictly inside `instance/lab_fixtures/path_traversal/`. The lab creates two subdirectories:
  - `public/`: The intended public documents directory containing legitimate files (`freelancer_guidelines.txt`, `sample_invoice.txt`, `terms_of_service.txt`).
  - `restricted/`: An internal directory containing synthetic confidential files (`synthetic_server_config.ini`, `confidential_contract.txt`).
- **Zero OS File Access Policy:** The application **never accesses arbitrary OS files**. Real Windows system files (such as `win.ini` or system DLLs) and Unix system files (`/etc/passwd`) are never opened or exposed.
- **Hard Laboratory Safety Boundary:** Even in vulnerable mode, the service verifies that resolved paths remain strictly within `lab_fixtures_root`. Any attempt to escape the lab fixtures root is blocked with a controlled error.
- **Harmless Synthetic Data:** All fixture documents and internal configuration files contain purely synthetic demonstration text. No real credentials, tokens, or system configurations are used.

## Vulnerable flow

When the stored `path_traversal` mode is **Vulnerable** and every central lab gate condition passes, the endpoint demonstrates unvalidated path concatenation:

1. The server accepts a user-supplied relative path (e.g. `../restricted/synthetic_server_config.ini`).
2. The server naively joins the input to the public directory (`public_dir / requested_path`).
3. The server intentionally omits directory containment validation (`is_relative_to(public_dir)`).
4. The traversal sequence `../` escapes `public/` and resolves to the sibling `restricted/` directory.
5. The hard lab boundary confirms the target is still inside `lab_fixtures_root` (ensuring host OS files are never reached).
6. The server reads the synthetic restricted fixture and displays its content, demonstrating how unauthorized files are exposed.

Effective vulnerable mode strictly requires:
- `LAB_ENABLE=true` in server configuration.
- Non-production environment (`APP_ENV=development` or `APP_ENV=testing`).
- Loopback socket peer (`127.0.0.1` or `::1`). Forwarded proxy headers are ignored.
- Server-side persisted mode set to `vulnerable` in `security_modes`.

Any missing or invalid condition immediately causes the application to fail closed into **Mitigated** mode.

## Mitigated flow

In **Mitigated** mode, the server enforces a robust four-pillar defense architecture:

1. **Path Canonicalization:** The application normalizes separators and resolves symbolic links and dot-dot components using `Path.resolve()` to obtain the unambiguous absolute target path.
2. **Strict Directory Containment Check:** The server verifies that the resolved path is strictly contained within the intended base directory using Python 3.12's `target_path.is_relative_to(public_dir)`. If the target is not relative to `public/`, the request is immediately rejected with HTTP 400.
3. **Input Sanitization & Normalization:**
   - Null bytes (`\x00`) are rejected immediately.
   - Absolute drive paths (e.g. `C:\...`) and root-relative paths (`/`, `\`) are disallowed.
   - Backslashes (`\`) and forward slashes (`/`) are normalized.
4. **Bounded Reading & Error Handling:** File reads are capped at 8 KB to prevent memory exhaustion, and non-existent files return a standard HTTP 404 response without revealing internal directory paths.

## Safe classroom demonstration steps

1. Sign in to SecureHire as `admin@example.test`.
2. Open the Security Lab dashboard at `/security-lab`.
3. In Mitigated mode (default):
   - Open `/security-lab/path-traversal`.
   - Select the **Legitimate Public File** preset (`freelancer_guidelines.txt`) -> Server verifies containment in `public/`, displays the guidelines, and reports `PASSED`.
   - Select the **Forward-Slash Traversal** preset (`../restricted/synthetic_server_config.ini`) -> Server canonicalizes the path, detects it escapes `public/`, rejects with HTTP 400, and reports `BLOCKED`.
   - Select the **Windows Backslash Traversal** preset (`..\restricted\synthetic_server_config.ini`) -> Server rejects the backslash traversal with HTTP 400 and reports `BLOCKED`.
   - Select the **Host OS Escape Attempt** (`../../../../Windows/win.ini`) -> Server rejects the escape with HTTP 400.
4. In Vulnerable mode:
   - Ensure `LAB_ENABLE=true` in `.env` and restart the server if needed.
   - On the Security Lab dashboard, set `Path Traversal` mode to `Vulnerable`.
   - Return to `/security-lab/path-traversal` (educational red warning banner is visible).
   - Select the **Forward-Slash Traversal** preset -> Server executes the naive join, accesses `restricted/synthetic_server_config.ini`, displays the file preview, and reports `PASSED` (vulnerability demonstrated).
   - Select the **Host OS Escape Attempt** (`../../../../Windows/win.ini`) -> The hard laboratory boundary halts the request, returning a controlled error explaining that arbitrary OS file access is strictly prohibited.
5. Return stored mode to `Mitigated` when finished.

## Test coverage

`tests/test_path_traversal.py` provides automated verification for:
- Mitigated mode acceptance of legitimate public files (`freelancer_guidelines.txt`, `sample_invoice.txt`, `terms_of_service.txt`).
- Mitigated mode rejection of forward-slash traversal (`../restricted/synthetic_server_config.ini`).
- Mitigated mode rejection of Windows backslash traversal (`..\restricted\synthetic_server_config.ini`).
- Mitigated mode rejection of nested traversal sequences (`....//restricted/...`).
- Mitigated mode rejection of absolute Windows drive paths (`C:\Windows\...`) and leading root slashes.
- Mitigated mode rejection of null-byte injection (`sample.txt\x00.ini`).
- Safe handling of non-existent files (HTTP 404).
- Vulnerable mode traversal allowing read of synthetic restricted fixtures when the central gate is open.
- Hard laboratory safety boundary blocking attempts to escape the lab fixtures root to reach host OS files in both modes.
- Fail-closed gate behavior when `LAB_ENABLE=false`, request is non-loopback, or environment is production.
- CSRF protection on document view and fixture reset endpoints.
- Bounded status recording in `LabRun` without file payloads or raw attack strings.
- Fixture isolation: Synthetic fixtures never touch or expose real system files.
