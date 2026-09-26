"""Local request boundary checks."""

from ipaddress import ip_address
from urllib.parse import urlsplit


def is_loopback_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    if getattr(parsed, "ipv4_mapped", None):
        parsed = parsed.ipv4_mapped
    return parsed.is_loopback


def is_allowed_local_host(host_header: str, allowed_hosts: tuple[str, ...]) -> bool:
    try:
        hostname = urlsplit(f"//{host_header}").hostname
    except ValueError:
        return False
    if not hostname:
        return False
    return hostname.lower() in {host.lower() for host in allowed_hosts}
