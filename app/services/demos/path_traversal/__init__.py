"""Path Traversal demonstration services for the Security Lab."""

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class TraversalPreset:
    key: str
    label: str
    path: str
    category: str  # "legitimate", "traversal", "hard_boundary"
    description: str


DEFAULT_DOCUMENT: Final[str] = "freelancer_guidelines.txt"
MAX_FILE_READ_BYTES: Final[int] = 8192  # 8 KB reading cap for demonstration safety

SYNTHETIC_PUBLIC_FIXTURES: Final[dict[str, str]] = {
    "freelancer_guidelines.txt": (
        "=== SecureHire Freelancer Guidelines ===\n"
        "1. Professional Communication: Always communicate through platform channels.\n"
        "2. Deliverable Quality: Adhere to scope specifications agreed upon in proposals.\n"
        "3. Milestone Completion: Submit work promptly for buyer review.\n"
        "4. Platform Safety: Never share personal financial credentials or offline payment links.\n"
        "Document Version: 2026.1 (Public Document)\n"
    ),
    "sample_invoice.txt": (
        "=== SecureHire Platform Invoice (Sample) ===\n"
        "Invoice ID: INV-2026-0042\n"
        "Client: Synthetic Client Corp\n"
        "Freelancer: Jane Doe (Security Consultant)\n"
        "Services Rendered: Academic Web Security Assessment\n"
        "Amount: $1,200.00 USD\n"
        "Status: Paid (Public Billing Receipt Sample)\n"
    ),
    "terms_of_service.txt": (
        "=== SecureHire Terms of Service ===\n"
        "Welcome to SecureHire, an academic web application security laboratory.\n"
        "Use of this platform is restricted to educational demonstration purposes.\n"
        "All marketplace transactions, gigs, and user accounts are synthetic.\n"
        "Document Classification: Public / Educational\n"
    ),
}

SYNTHETIC_RESTRICTED_FIXTURES: Final[dict[str, str]] = {
    "synthetic_server_config.ini": (
        "[synthetic_server_configuration]\n"
        "# HARLESS DEMONSTRATION FIXTURE - NOT REAL PRODUCTION SECRETS\n"
        "environment = synthetic-laboratory\n"
        "lab_internal_host = 10.0.4.88\n"
        "lab_secret_token = synthetic-lab-dummy-key-9f8e7d6c\n"
        "audit_database = securehire_synthetic_audit\n"
        "debug_log_level = verbose\n"
        "notice = 'Confidential synthetic server configuration reached via path traversal.'\n"
    ),
    "confidential_contract.txt": (
        "=== SecureHire Synthetic Confidential Contract ===\n"
        "CLASSIFICATION: RESTRICTED INTERNAL RECORD\n"
        "Parties: SecureHire Marketplace & Strategic Enterprise Client\n"
        "Scope: Proprietary Codebase Security Review and Penetration Testing\n"
        "Retainer Amount: $75,000.00 (Synthetic Demonstration Record)\n"
        "Notice: This file should never be accessible from the public document repository.\n"
    ),
}

TRAVERSAL_PRESETS: Final[tuple[TraversalPreset, ...]] = (
    TraversalPreset(
        key="legitimate_public",
        label="Legitimate Public File (freelancer_guidelines.txt)",
        path="freelancer_guidelines.txt",
        category="legitimate",
        description="A legitimate request for a document residing directly in the public repository.",
    ),
    TraversalPreset(
        key="traversal_unix",
        label="Forward-Slash Traversal (../restricted/synthetic_server_config.ini)",
        path="../restricted/synthetic_server_config.ini",
        category="traversal",
        description="Standard dot-dot-slash sequence escaping public/ into the restricted fixture folder.",
    ),
    TraversalPreset(
        key="traversal_win",
        label="Windows Backslash Traversal (..\\restricted\\synthetic_server_config.ini)",
        path=r"..\restricted\synthetic_server_config.ini",
        category="traversal",
        description="Windows-style backslash traversal sequence targeting internal server configuration.",
    ),
    TraversalPreset(
        key="traversal_nested",
        label="Nested Traversal Sequence (....//restricted/synthetic_server_config.ini)",
        path="....//restricted/synthetic_server_config.ini",
        category="traversal",
        description="Nested traversal sequence commonly used to bypass naive non-recursive string stripping.",
    ),
    TraversalPreset(
        key="traversal_contract",
        label="Confidential Contract (../restricted/confidential_contract.txt)",
        path="../restricted/confidential_contract.txt",
        category="traversal",
        description="Traversal reaching a restricted synthetic client contract file.",
    ),
    TraversalPreset(
        key="traversal_os_escape",
        label="Host OS Escape Attempt (../../../../Windows/win.ini)",
        path="../../../../Windows/win.ini",
        category="hard_boundary",
        description="Attempts to escape the lab fixtures root entirely. Both modes block this to ensure zero host OS exposure.",
    ),
)

PRESET_MAP: Final[dict[str, TraversalPreset]] = {
    preset.key: preset for preset in TRAVERSAL_PRESETS
}
