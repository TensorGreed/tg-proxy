"""Bridge between Presidio's AnalyzerEngine and tg-proxy's Scanner contract.

This module is import-safe even when presidio_analyzer isn't installed —
the heavy import is deferred until build_scanner() is called. That lets
unit tests exercise the pure-Python helpers (severity_for,
char_to_byte_map, _to_finding) without paying the spaCy model load.
"""
from __future__ import annotations

import os
from typing import Callable, List, Optional

from tgproxy_plugin import Finding, Hints, Severity


# Map Presidio entity types to tg-proxy severity levels. The defaults
# lean conservative — financial and government-issued IDs are CRITICAL,
# contact info is MEDIUM, generic identity (name / place / date) is LOW.
# Customize at the tg-proxy config layer by filtering on the
# `pii.presidio.<entity_type>` finding type if you want different policy.
SEVERITY_MAP = {
    # Financial / banking
    "CREDIT_CARD":       Severity.CRITICAL,
    "IBAN_CODE":         Severity.CRITICAL,
    "US_BANK_NUMBER":    Severity.CRITICAL,
    "CRYPTO":            Severity.CRITICAL,
    # Government identifiers
    "US_SSN":            Severity.CRITICAL,
    "US_PASSPORT":       Severity.CRITICAL,
    "US_DRIVER_LICENSE": Severity.CRITICAL,
    "US_ITIN":           Severity.CRITICAL,
    "UK_NHS":            Severity.CRITICAL,
    "AU_TFN":            Severity.CRITICAL,
    "AU_ACN":            Severity.CRITICAL,
    "AU_ABN":            Severity.CRITICAL,
    "AU_MEDICARE":       Severity.CRITICAL,
    # Medical
    "MEDICAL_LICENSE":   Severity.HIGH,
    # Contact info
    "EMAIL_ADDRESS":     Severity.MEDIUM,
    "PHONE_NUMBER":      Severity.MEDIUM,
    "IP_ADDRESS":        Severity.MEDIUM,
    "URL":               Severity.LOW,
    # Identity (lower-stakes by default; tighten if context warrants)
    "PERSON":            Severity.LOW,
    "LOCATION":          Severity.LOW,
    "NRP":               Severity.LOW,  # nationality / religion / political group
    "DATE_TIME":         Severity.LOW,
}


def severity_for(entity_type: str) -> int:
    """Return the tg-proxy Severity for a Presidio entity type, defaulting
    to LOW for unknown types.
    """
    return SEVERITY_MAP.get(entity_type, Severity.LOW)


def char_to_byte_map(text: str) -> List[int]:
    """For each Unicode code-point index in text, the byte offset where
    that code point starts when text is encoded as UTF-8. Length is
    len(text)+1; the last entry is the total UTF-8 byte length.

    Presidio reports offsets in characters (code points). tg-proxy's
    Finding offsets are bytes. For ASCII bodies these are identical; for
    multibyte UTF-8 we use this map to translate.
    """
    out = [0]
    pos = 0
    for ch in text:
        pos += len(ch.encode("utf-8"))
        out.append(pos)
    return out


def _to_finding(
    entity_type: str,
    score: float,
    start_byte: int,
    end_byte: int,
) -> Finding:
    return Finding(
        type=f"pii.presidio.{entity_type.lower()}",
        severity=severity_for(entity_type),
        start=start_byte,
        end=end_byte,
        confidence=float(score),
        scanner="presidio",
    )


def build_scanner(model_name: Optional[str] = None) -> Callable[[bytes, Hints], List[Finding]]:
    """Construct the scan callable for serve_scanner.

    model_name overrides the spaCy NER model. Default is whatever Presidio
    picks (currently `en_core_web_lg`, ~700MB resident). Override via the
    TGPROXY_PRESIDIO_MODEL environment variable when launched by tg-proxy.

    The Presidio import is local so a caller can `import tgproxy_presidio`
    in a context where Presidio isn't installed and only fail at engine-
    build time, not at module-import time.
    """
    if model_name is None:
        model_name = os.environ.get("TGPROXY_PRESIDIO_MODEL", "")

    from presidio_analyzer import AnalyzerEngine

    if not model_name:
        engine = AnalyzerEngine()
    else:
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model_name}],
        })
        engine = AnalyzerEngine(nlp_engine=provider.create_engine())

    def scan(data: bytes, _hints: Hints) -> List[Finding]:
        # Presidio operates on Unicode strings; if the body isn't valid
        # UTF-8 we'd rather report nothing than mis-locate offsets.
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return []

        # ASCII fast path — byte index == char index, so skip the map.
        ascii_only = len(text) == len(data)
        cb_map = None if ascii_only else char_to_byte_map(text)

        results = engine.analyze(text=text, language="en")

        findings: List[Finding] = []
        for r in results:
            if cb_map is None:
                start, end = r.start, r.end
            else:
                start, end = cb_map[r.start], cb_map[r.end]
            findings.append(_to_finding(r.entity_type, r.score, start, end))
        return findings

    return scan
