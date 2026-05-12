"""tg-proxy plugin SDK for Python.

Write a scanner or redactor as a callable and call :func:`serve_scanner` or
:func:`serve_redactor` from your script's ``__main__``. tg-proxy will spawn
the script as a subprocess and talk to it over gRPC.

    from tgproxy_plugin import serve_scanner, Finding, Severity

    def scan(data: bytes, hints) -> list[Finding]:
        out = []
        needle = b"TOKEN"
        i = 0
        while True:
            j = data.find(needle, i)
            if j < 0:
                break
            out.append(Finding(
                type="my.token",
                severity=Severity.HIGH,
                start=j,
                end=j + len(needle),
                confidence=1.0,
                scanner="my-scanner",
            ))
            i = j + len(needle)
        return out

    if __name__ == "__main__":
        serve_scanner("my-scanner", scan)
"""
from .types import Direction, Finding, Hints, Severity
from .server import serve_scanner, serve_redactor

__all__ = [
    "Direction",
    "Finding",
    "Hints",
    "Severity",
    "serve_scanner",
    "serve_redactor",
]

__version__ = "0.0.0"
