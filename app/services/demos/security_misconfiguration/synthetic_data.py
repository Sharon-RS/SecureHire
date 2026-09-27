"""Synthetic data fixtures for the isolated Security Misconfiguration demonstration.

All values, connection strings, error messages, and tracebacks defined here are
entirely synthetic mock fixtures created strictly for educational demonstration.
No real host environment variables, system files, database credentials, or secret keys
are accessed or exposed.
"""

from typing import Any, Final


SYNTHETIC_LAB_NOTICE: Final[str] = (
    "NOTICE: ALL DIAGNOSTIC DATA AND STACK TRACES SHOWN ARE SYNTHETIC LAB FIXTURES "
    "DESIGNED FOR CWE-209 / CWE-215 / CWE-16 EDUCATIONAL DEMONSTRATIONS ONLY."
)

# Synthetic environment and topology disclosure fixtures
SYNTHETIC_ENV_FIXTURES: Final[dict[str, str]] = {
    "APP_ENVIRONMENT": "synthetic-laboratory-sandbox",
    "SYNTHETIC_FIXTURE_LABEL": "SYNTHETIC LAB FIXTURE - NOT A REAL SYSTEM",
    "MOCK_WORKER_HOST": "mock-worker-02.synthetic-lab.internal",
    "MOCK_INTERNAL_IP": "10.244.15.82",
    "MOCK_DB_DSN": "mysql://synthetic_escrow_app:synthetic_fixture_token_abc123@synthetic-db.internal:3306/synthetic_escrow_ledger",
    "MOCK_REDIS_CACHE": "redis://:synthetic_redis_demo@synthetic-cache.internal:6379/0",
    "MOCK_UPSTREAM_GATEWAY": "https://api-sandbox.synthetic-payments.internal/v1/escrow",
    "FRAMEWORK_VERSION": "Flask/3.0.0 (Synthetic Mock Runtime)",
    "PYTHON_VERSION": "Python 3.12.0 (Synthetic Lab Container)",
}

# Synthetic stack traces for controlled CWE-209 demonstration
SYNTHETIC_STACK_TRACES: Final[dict[str, list[str]]] = {
    "divide_by_zero": [
        "Traceback (most recent call last):",
        '  File "/srv/securehire/synthetic_lab/gateway.py", line 104, in process_escrow_transaction',
        "    fee = calculate_escrow_fee(amount=escrow_amount, rate=contract_rate)",
        '  File "/srv/securehire/synthetic_lab/escrow_calc.py", line 42, in calculate_escrow_fee',
        "    fee_percentage = (base_rate / contract_rate) * 100.0",
        "ZeroDivisionError: float division by zero (contract_rate=0.0)",
    ],
    "invalid_currency": [
        "Traceback (most recent call last):",
        '  File "/srv/securehire/synthetic_lab/gateway.py", line 118, in process_escrow_transaction',
        "    converted = convert_escrow_amount(amount=escrow_amount, currency=currency_code)",
        '  File "/srv/securehire/synthetic_lab/currency_converter.py", line 88, in convert_escrow_amount',
        "    rate = FX_RATES_SYNTHETIC_TABLE[currency]",
        "KeyError: 'Unsupported synthetic currency code: XYZ. Allowed: [USD, EUR, GBP]'",
    ],
    "connection_timeout": [
        "Traceback (most recent call last):",
        '  File "/srv/securehire/synthetic_lab/gateway.py", line 75, in acquire_ledger_lock',
        "    conn = db_pool.acquire_synthetic_connection(timeout_ms=3000)",
        '  File "/srv/securehire/synthetic_lab/db_pool.py", line 115, in acquire_synthetic_connection',
        "    raise SyntheticTimeoutError('Connection pool exhausted waiting for synthetic-db.internal:3306')",
        "SyntheticTimeoutError: [Errno 110] Connection pool exhausted (active_conns=50, max=50) to synthetic-db.internal:3306",
    ],
}

SYNTHETIC_ERROR_TITLES: Final[dict[str, str]] = {
    "divide_by_zero": "ZeroDivisionError in Escrow Calculation Engine",
    "invalid_currency": "Unhandled KeyError in Payment Conversion Gateway",
    "connection_timeout": "SyntheticTimeoutError in Escrow Ledger Database Pool",
}

SYNTHETIC_ERROR_MESSAGES: Final[dict[str, str]] = {
    "divide_by_zero": "ZeroDivisionError: float division by zero in calculate_escrow_fee (contract_rate=0.0).",
    "invalid_currency": "KeyError: 'Unsupported synthetic currency code: XYZ. Allowed currencies: [USD, EUR, GBP]'.",
    "connection_timeout": "SyntheticTimeoutError: Connection pool exhausted after 3000ms connecting to synthetic-db.internal:3306.",
}

# Synthetic debug status payload for CWE-215 demonstration
SYNTHETIC_DEBUG_STATUS_PAYLOAD: Final[dict[str, Any]] = {
    "disclaimer": SYNTHETIC_LAB_NOTICE,
    "system_status": "ONLINE (SYNTHETIC LAB MODE)",
    "debug_mode": True,
    "environment": SYNTHETIC_ENV_FIXTURES["APP_ENVIRONMENT"],
    "node_id": SYNTHETIC_ENV_FIXTURES["MOCK_WORKER_HOST"],
    "internal_ip": SYNTHETIC_ENV_FIXTURES["MOCK_INTERNAL_IP"],
    "runtimes": {
        "python": SYNTHETIC_ENV_FIXTURES["PYTHON_VERSION"],
        "framework": SYNTHETIC_ENV_FIXTURES["FRAMEWORK_VERSION"],
    },
    "synthetic_connections": {
        "database": SYNTHETIC_ENV_FIXTURES["MOCK_DB_DSN"],
        "cache": SYNTHETIC_ENV_FIXTURES["MOCK_REDIS_CACHE"],
        "payment_upstream": SYNTHETIC_ENV_FIXTURES["MOCK_UPSTREAM_GATEWAY"],
    },
    "synthetic_service_metrics": {
        "active_simulated_contracts": 14,
        "escrow_vault_state": "SYNTHETIC_SIMULATION_ACTIVE",
        "mock_queue_depth": 0,
    },
}
