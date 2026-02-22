"""
Models/Finding.py — Finding dataclass for confirmed XSS vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
    """Represents a confirmed XSS vulnerability finding."""

    url: str
    """Page URL where the injection was performed."""

    parameter: str
    """Input field name / selector or URL parameter (prefixed with ``?``)."""

    payload: str
    """XSS payload string that triggered detection."""

    detection_method: str
    """One of: ``alert-dialog``, ``dom-mutation``, ``interactsh-oob``."""

    test_id: str
    """Short unique ID correlating this attempt across logs."""

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    """ISO-8601 UTC timestamp of discovery."""

    severity: str = "High"
    """Severity rating (always High for confirmed XSS)."""
