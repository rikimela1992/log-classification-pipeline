"""Versioned public taxonomy and zero-shot label descriptions."""

from __future__ import annotations

TAXONOMY_VERSION = "1"

SUBSYSTEM_LABELS = (
    "ai-ml",
    "auth",
    "compute",
    "firewall",
    "media",
    "network",
    "nvr-cctv",
    "storage",
    "vpn",
    "wifi-ap",
)

SEVERITY_LABELS = (
    "error",
    "info",
    "routine",
    "security_event",
    "warning",
)

SUBSYSTEM_CANDIDATES = {
    "ai-ml": "artificial intelligence or machine learning",
    "auth": "authentication identity or access control",
    "compute": "compute operating system or application runtime",
    "firewall": "firewall traffic filtering or packet policy",
    "media": "media playback streaming or transcoding",
    "network": "general network connectivity or routing",
    "nvr-cctv": "video surveillance camera or recorder",
    "storage": "storage filesystem disk or backup",
    "vpn": "virtual private network tunnel",
    "wifi-ap": "wireless access point or Wi-Fi",
}

SEVERITY_CANDIDATES = {
    "error": "an error or failure",
    "info": "an informational status update",
    "routine": "a routine expected operation",
    "security_event": "a security-relevant event",
    "warning": "a warning requiring attention",
}
