"""Console entry point: build the Presidio-backed scanner and serve it
over the tg-proxy plugin protocol.

tg-proxy invokes this via the `external.command` config knob:

    scanners:
      - name: presidio
        enabled: true
        external:
          command: ["python", "-m", "tgproxy_presidio"]
          handshake_timeout_seconds: 30

Two environment variables tune behavior at launch time:

    TGPROXY_PRESIDIO_MODEL      spaCy model to load (default: whatever
                                Presidio picks, typically en_core_web_lg).
                                Useful values: en_core_web_sm | _md | _lg.
    TGPROXY_PRESIDIO_ENTITIES   Comma-separated list of Presidio entity
                                types to report. Default is a curated
                                subset (see scanner.DEFAULT_ENTITIES) that
                                excludes recognizers known to fire on
                                non-prose bodies (DATE_TIME, bank/DL
                                numbers). Use "*" to opt every recognizer
                                back in.

The first invocation loads spaCy + the NER model and takes 5–10 seconds
to become ready; subsequent scans run at ~10–50 ms per request body
depending on body size.
"""
from __future__ import annotations

from tgproxy_plugin import serve_scanner

from .scanner import build_scanner


def main() -> None:
    serve_scanner("presidio", build_scanner(), version="0.1.0")


if __name__ == "__main__":
    main()
