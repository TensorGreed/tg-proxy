"""Console entry point: build the Presidio-backed scanner and serve it
over the tg-proxy plugin protocol.

tg-proxy invokes this via the `external.command` config knob:

    scanners:
      - name: presidio
        enabled: true
        external:
          command: ["python", "-m", "tgproxy_presidio"]
          handshake_timeout_seconds: 30

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
