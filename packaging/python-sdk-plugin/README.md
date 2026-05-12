# tgproxy-plugin

Python SDK for writing [tg-proxy](https://github.com/TensorGreed/tg-proxy)
scanner and redactor plugins.

```
pip install tgproxy-plugin
```

## Write a scanner

```python
from tgproxy_plugin import serve_scanner, Finding, Severity, Hints

def scan(data: bytes, hints: Hints) -> list[Finding]:
    out = []
    needle = b"INTERNAL-ONLY"
    i = 0
    while True:
        j = data.find(needle, i)
        if j < 0:
            break
        out.append(Finding(
            type="custom.internal_marker",
            severity=Severity.HIGH,
            start=j,
            end=j + len(needle),
            confidence=1.0,
            scanner="internal-marker",
        ))
        i = j + len(needle)
    return out

if __name__ == "__main__":
    serve_scanner("internal-marker", scan)
```

Then in your tg-proxy config:

```yaml
scanners:
  - name: internal-marker
    enabled: true
    external:
      command: ["python", "/path/to/my_scanner.py"]
```

## Write a redactor

```python
from tgproxy_plugin import serve_redactor, Finding

def redact(data: bytes, findings: list[Finding]) -> bytes:
    # Apply your own redaction logic, using the byte-precise offsets
    # in each finding.
    out = bytearray(data)
    for f in findings:
        out[f.start:f.end] = b"X" * (f.end - f.start)
    return bytes(out)

if __name__ == "__main__":
    serve_redactor("xxx-replacer", redact)
```

## What you get

- ``Finding`` dataclass with byte-precise ``start`` / ``end`` offsets.
- ``Severity`` and ``Direction`` int constants matching the Go enum.
- ``Hints`` dataclass with the request URL, method, content type, and
  direction (request vs response).
- ``serve_scanner(name, fn)`` / ``serve_redactor(name, fn)`` — pump-handle
  for the gRPC server. Block until tg-proxy shuts the plugin down.

The protocol is hashicorp/go-plugin gRPC; the Python SDK takes care of the
handshake, magic-cookie check, port selection, and graceful shutdown.

See the upstream repo for the protocol definition (`pkg/plugin/proto/plugin.proto`).
