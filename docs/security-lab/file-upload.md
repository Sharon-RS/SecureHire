# Unrestricted File Upload

## What Unrestricted File Upload is

Unrestricted File Upload occurs when an application accepts files from users without adequate validation of file type, extension, contents, size, or destination path.

In freelance marketplaces, users frequently upload resumes, portfolio samples, design mockups, and gig deliverable attachments. If an application allows untrusted users to upload arbitrary files to a web-accessible directory:

1. **Remote Code Execution (RCE):** An attacker can upload a server-side executable script (such as `.php`, `.py`, `.sh`, or `.exe`). When the web server interprets the script upon request, the attacker achieves arbitrary command execution on the host server.
2. **Stored Cross-Site Scripting (XSS):** An attacker can upload an HTML or SVG file containing JavaScript markup. When viewed or served by the browser in the application's origin, the script executes in the victim's session context.
3. **Denial of Service (DoS):** An attacker can upload excessively large files or recursive archives to exhaust server storage or processing capacity.

## Local synthetic scenario and isolation boundary

The page at `/security-lab/file-upload` demonstrates file upload handling in a controlled freelance portfolio and project attachment context.

In accordance with **AGENTS.md Rule 6**:
- **Zero Execution Policy:** The server **never executes uploaded files**. No interpreter, subshell, or `eval`/`exec` is ever invoked on uploaded content.
- **Dedicated Lab Directory:** Uploaded files are strictly confined to `instance/lab_uploads/user_{user_id}/`. They are never written to the web root (`app/static/`), application source directories (`app/`), or template folders (`app/templates/`).
- **Path Traversal Protection:** Base-name sanitization (`os.path.basename`) and directory containment checks remain permanently active in both modes, ensuring demonstration files cannot escape the user's isolated folder.
- **Harmless Demonstration Payloads:** The demonstration provides approved harmless test cases (valid text, minimal PNG, benign PHP comment, benign Python print statement, and disguised extensions). No destructive or malicious code is included.

## Vulnerable flow

When the stored `file_upload` mode is **Vulnerable** and every central lab gate condition passes, the endpoint demonstrates unvalidated file acceptance:

1. The server bypasses file extension allowlisting, accepting dangerous extensions like `.php`, `.py`, `.sh`, `.exe`, and `.html`.
2. Content-type and magic-byte inspections are omitted.
3. The raw base filename and user-controlled extension are preserved on disk.
4. The file is saved in the user's isolated lab folder (`instance/lab_uploads/user_{user_id}/`).
5. The page displays evidence explaining how an attacker would achieve RCE or Stored XSS in an unhardened web environment where the server maps that extension to an interpreter.

Effective vulnerable mode strictly requires:
- `LAB_ENABLE=true` in server configuration.
- Non-production environment (`APP_ENV=development` or `APP_ENV=testing`).
- Loopback socket peer (`127.0.0.1` or `::1`). Forwarded proxy headers are ignored.
- Server-side persisted mode set to `vulnerable` in `security_modes`.

Any missing or invalid condition immediately causes the application to fail closed into **Mitigated** mode.

## Mitigated flow

In **Mitigated** mode, the server enforces a robust six-pillar defense-in-depth architecture:

1. **Strict Extension Allowlisting:** Only approved, necessary file extensions are accepted: `.pdf`, `.png`, `.jpg`, `.jpeg`, and `.txt`. All other extensions (including executable scripts and HTML markup) are rejected with HTTP 400.
2. **File Signature (Magic Bytes) Verification:** Pure-Python signature inspection verifies binary headers (e.g. `\x89PNG\r\n\x1a\n` for PNG, `\xff\xd8\xff` for JPEG, `%PDF-` for PDF, and UTF-8 decodability without binary null bytes for text). This blocks extension-disguise attacks (such as `shell.php.png`).
3. **File Size Capping:** Upload sizes are capped at 512 KB (`MAX_FILE_SIZE_BYTES`) to prevent disk exhaustion.
4. **Server-Controlled Storage Naming:** The original user-supplied filename is never used on disk. The server generates a random UUID (e.g., `4f9e3b1c8a2d.pdf`), preventing directory traversal, overwriting existing files, and predictable resource enumeration.
5. **Non-Executable Private Storage:** Files are stored strictly inside `instance/lab_uploads/`, which is outside the web server's static document root and cannot be executed as code.
6. **Safe Download Headers:** The download endpoint serves files with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, preventing the browser from rendering or executing active content.

## Safe classroom demonstration steps

1. Sign in to SecureHire as `admin@example.test`.
2. Open the Security Lab dashboard at `/security-lab`.
3. In Mitigated mode (default):
   - Open `/security-lab/file-upload`.
   - Submit the **Benign Text Document** sample -> Server accepts the upload, assigns a UUID filename, and reports `PASSED`.
   - Submit the **Harmless PHP Script** sample -> Server rejects the upload with HTTP 400 ("Disallowed extension '.php'") and reports `BLOCKED`.
   - Submit the **Disguised Extension** sample -> Server inspects magic bytes, detects the MIME mismatch, rejects with HTTP 400, and reports `BLOCKED`.
4. In Vulnerable mode:
   - Ensure `LAB_ENABLE=true` in `.env` and restart the server if needed.
   - On the Security Lab dashboard, set `Unrestricted File Upload` mode to `Vulnerable`.
   - Return to `/security-lab/file-upload` (educational red warning banner is visible).
   - Submit the **Harmless PHP Script** sample -> Server accepts the file, saves `harmless_poc.php` in the isolated directory, and displays educational risk evidence.
   - Click "Clear uploaded file" -> Synthetic upload is safely removed from disk.
5. Return stored mode to `Mitigated` when finished.

## Test coverage

`tests/test_file_upload.py` provides automated verification for:
- Mitigated mode acceptance of valid `.txt`, `.png`, `.jpg`, and `.pdf` files.
- Mitigated mode rejection of dangerous extensions (`.php`, `.py`, `.html`, `.exe`, `.sh`).
- Mitigated mode rejection of magic-byte mismatches (disguised scripts).
- Mitigated mode rejection of oversized files (> 512 KB) and zero-byte files.
- UUID renaming on disk in mitigated mode.
- Vulnerable mode acceptance of dangerous extensions when the central gate is open.
- Fail-closed gate behavior when `LAB_ENABLE=false`, request is non-loopback, or environment is production.
- Strict isolation and path traversal protection (`os.path.basename` enforcement).
- Non-execution of uploaded files and safe download attachment headers (`nosniff`).
- CSRF protection on upload and reset endpoints.
- User isolation: users cannot access or delete other users' uploaded demonstration files.
- Bounded status recording in `LabRun` without file payloads or raw file data.
