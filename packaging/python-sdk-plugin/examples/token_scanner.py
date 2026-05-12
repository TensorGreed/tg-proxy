"""Example scanner that flags every occurrence of the literal "TOKEN".

Run via tg-proxy by adding to your config:

    scanners:
      - name: token-marker
        enabled: true
        external:
          command: ["python", "/path/to/this/file.py"]
"""
from tgproxy_plugin import Finding, Hints, Severity, serve_scanner


def scan(data: bytes, _hints: Hints) -> list[Finding]:
    out: list[Finding] = []
    needle = b"TOKEN"
    i = 0
    while True:
        j = data.find(needle, i)
        if j < 0:
            break
        out.append(Finding(
            type="example.token",
            severity=Severity.HIGH,
            start=j,
            end=j + len(needle),
            confidence=1.0,
            scanner="token-marker",
        ))
        i = j + len(needle)
    return out


if __name__ == "__main__":
    serve_scanner("token-marker", scan)
