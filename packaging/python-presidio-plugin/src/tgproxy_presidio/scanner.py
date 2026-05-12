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


# DEFAULT_ENTITIES is the curated set of Presidio entity types enabled
# when the caller doesn't override. Each one earned its place by being
# either (a) high-value PII that regex can't reliably catch (PERSON,
# LOCATION, NRP) or (b) high-stakes identifiers Presidio detects with
# strong-context recognizers (financial, government IDs, contact info).
#
# Entities deliberately NOT in the default:
#
#   - DATE_TIME: Presidio's regex recognizer fires at score 0.85 on bare
#     integers (`10485760`, `4096`) and common words (`Tuesday`,
#     `morning`, `the same day`). Too noisy for production traffic.
#   - US_BANK_NUMBER, US_DRIVER_LICENSE: regex-only, weak context filter,
#     trips on long digit strings.
#   - US_ITIN: same recognizer family as the above two.
#
# Opt back in via the `entities` argument to build_scanner() or the
# TGPROXY_PRESIDIO_ENTITIES env var (comma-separated). Set "*" to enable
# every Presidio recognizer with no filter.
DEFAULT_ENTITIES = (
    # Identity (NER-driven, model-dependent)
    "PERSON",
    "LOCATION",
    "NRP",
    # Contact info
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IP_ADDRESS",
    "URL",
    # Financial
    "CREDIT_CARD",
    "IBAN_CODE",
    "CRYPTO",
    # Government IDs (high-confidence recognizers)
    "US_SSN",
    "US_PASSPORT",
    "UK_NHS",
    "AU_TFN",
    "AU_ACN",
    "AU_ABN",
    "AU_MEDICARE",
    # Medical
    "MEDICAL_LICENSE",
)


def _entities_from_env() -> Optional[List[str]]:
    """Parse TGPROXY_PRESIDIO_ENTITIES into a list, or return None for
    "use the default set." A literal `*` value means "let Presidio
    report every entity it knows about" — wire to None on the analyze
    call but disable our own filter.
    """
    raw = os.environ.get("TGPROXY_PRESIDIO_ENTITIES", "").strip()
    if not raw:
        return None
    if raw == "*":
        return []  # sentinel: pass entities=None to engine.analyze
    return [e.strip().upper() for e in raw.split(",") if e.strip()]


def build_scanner(
    model_name: Optional[str] = None,
    entities: Optional[List[str]] = None,
) -> Callable[[bytes, Hints], List[Finding]]:
    """Construct the scan callable for serve_scanner.

    model_name overrides the spaCy NER model. Default is whatever Presidio
    picks (currently `en_core_web_lg`, ~700MB resident). Override via the
    TGPROXY_PRESIDIO_MODEL environment variable when launched by tg-proxy.

    entities filters which Presidio entity types are reported. None means
    use DEFAULT_ENTITIES (a curated subset that excludes recognizers
    known to be noisy on non-prose bodies — DATE_TIME, US_BANK_NUMBER,
    US_DRIVER_LICENSE, US_ITIN). An empty list means pass entities=None
    to Presidio, i.e. every recognizer the engine has fires. A non-empty
    list overrides the default with exactly that set. Override via
    TGPROXY_PRESIDIO_ENTITIES (comma-separated, or `*` for all).

    The Presidio import is local so a caller can `import tgproxy_presidio`
    in a context where Presidio isn't installed and only fail at engine-
    build time, not at module-import time.
    """
    if model_name is None:
        model_name = os.environ.get("TGPROXY_PRESIDIO_MODEL", "")
    if entities is None:
        entities = _entities_from_env()
        if entities is None:
            entities = list(DEFAULT_ENTITIES)

    # entities == [] means "let Presidio report everything" — we don't
    # pass an entities filter to analyze() in that case. Otherwise we
    # pin the list.
    entities_arg: Optional[List[str]] = entities if entities else None

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

        results = engine.analyze(text=text, language="en", entities=entities_arg)

        findings: List[Finding] = []
        for r in results:
            if cb_map is None:
                start, end = r.start, r.end
            else:
                start, end = cb_map[r.start], cb_map[r.end]
            findings.append(_to_finding(r.entity_type, r.score, start, end))
        return findings

    return scan
