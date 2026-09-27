"""Unrestricted File Upload demonstration services for the Security Lab."""

from dataclasses import dataclass
from typing import Final

ALLOWED_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
)

MAX_FILE_SIZE_BYTES: Final[int] = 512 * 1024  # 512 KB

# Minimal valid 1x1 transparent PNG bytes for harmless demonstration
MINIMAL_PNG_BYTES: Final[bytes] = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?"
    b"\x00\x05\xfe\x02\xfe\xa76\x81\x84\x00\x00\x00\x00IEND\xaeB`\x82"
)


@dataclass(frozen=True)
class DemonstrationSample:
    key: str
    label: str
    filename: str
    content: bytes
    declared_content_type: str
    description: str


DEMONSTRATION_SAMPLES: Final[tuple[DemonstrationSample, ...]] = (
    DemonstrationSample(
        key="benign_doc",
        label="Benign Text Document (sample.txt)",
        filename="sample_portfolio.txt",
        content=(
            b"SecureHire Synthetic Freelancer Portfolio\n"
            b"Specialization: Web Application Security & Cloud Architecture\n"
            b"Summary: Experienced security consultant and backend developer.\n"
        ),
        declared_content_type="text/plain",
        description="A legitimate plain-text portfolio document conforming to all validation rules.",
    ),
    DemonstrationSample(
        key="benign_img",
        label="Benign Image (sample.png)",
        filename="sample_diagram.png",
        content=MINIMAL_PNG_BYTES,
        declared_content_type="image/png",
        description="A legitimate PNG image file with a valid PNG signature.",
    ),
    DemonstrationSample(
        key="harmless_php",
        label="Harmless PHP Script (harmless_poc.php)",
        filename="harmless_poc.php",
        content=(
            b"<?php\n"
            b"// SecureHire Security Lab: Educational Harmless File Upload PoC\n"
            b"// In an unhardened web environment, executable scripts allow Remote Code Execution (RCE).\n"
            b"echo 'SecureHire Harmless File Upload Demo';\n"
            b"?>\n"
        ),
        declared_content_type="application/x-php",
        description="Demonstrates an attempt to upload a server-side executable PHP script.",
    ),
    DemonstrationSample(
        key="harmless_py",
        label="Harmless Python Script (harmless_script.py)",
        filename="harmless_script.py",
        content=(
            b"# SecureHire Security Lab: Educational Harmless File Upload PoC\n"
            b"# In an unhardened web environment, executable scripts allow server compromise.\n"
            b"print('SecureHire Harmless File Upload Demo')\n"
        ),
        declared_content_type="text/x-python",
        description="Demonstrates an attempt to upload a Python automation script.",
    ),
    DemonstrationSample(
        key="disguised_ext",
        label="Disguised Extension (shell.php.png)",
        filename="harmless_poc.php.png",
        content=(
            b"<?php\n"
            b"// Harmless PHP disguised with a .png extension to bypass extension-only checks.\n"
            b"echo 'Disguised PHP';\n"
            b"?>\n"
        ),
        declared_content_type="image/png",
        description="Demonstrates a script disguised with an allowed image extension; fails magic-byte checks.",
    ),
)

SAMPLE_MAP: Final[dict[str, DemonstrationSample]] = {
    sample.key: sample for sample in DEMONSTRATION_SAMPLES
}
