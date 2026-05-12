"""tgproxy-presidio: Microsoft Presidio scanner plugin for tg-proxy.

Run as a tg-proxy plugin via tg-proxy config:

    scanners:
      - name: presidio
        enabled: true
        external:
          command: ["python", "-m", "tgproxy_presidio"]
          handshake_timeout_seconds: 30

The 30-second handshake timeout accommodates Presidio's startup cost
(spaCy NLP model load — typically 5–10 seconds the first time).
"""

from .scanner import build_scanner, severity_for

__all__ = ["build_scanner", "severity_for"]
__version__ = "0.1.0"
