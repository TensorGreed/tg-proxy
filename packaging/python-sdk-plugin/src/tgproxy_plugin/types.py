"""Data types exposed to plugin authors.

These mirror the Go-side api.Scanner / api.Redactor contract and the proto
schema in pkg/plugin/proto.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


class Severity:
    """Severity levels match the proto enum and Go api.Severity."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Direction:
    """Whether the scanned body is a request or a response."""
    REQUEST = 0
    RESPONSE = 1


@dataclass
class Hints:
    """Metadata about the HTTP exchange the scanned body belongs to."""
    content_type: str = ""
    url: str = ""
    method: str = ""
    direction: int = Direction.REQUEST


@dataclass
class Finding:
    """A single sensitive-data match.

    ``start`` and ``end`` are byte offsets into the slice passed to your
    scanner. ``end`` is exclusive. Slicing data[start:end] must reproduce
    the matched substring — the redactor downstream uses these offsets
    directly.
    """
    type: str
    severity: int
    start: int
    end: int
    confidence: float = 1.0
    scanner: str = ""
    metadata: Optional[Dict[str, str]] = field(default=None)
