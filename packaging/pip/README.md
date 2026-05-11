# tg-proxy

Lightweight network proxy with built-in scanners (PII, secrets, code) and
pluggable in-flight redaction.

## Install

```
pip install tg-proxy
```

This pulls a prebuilt binary wheel matching your OS and CPU. Supported:

| OS      | Architectures |
|---------|---------------|
| Linux   | x86_64, aarch64 |
| macOS   | x86_64, arm64 |
| Windows | amd64, arm64 |

If `pip` reports no matching wheel for your platform, install the Go binary
directly:

```
go install github.com/TensorGreed/tg-proxy/cmd/tg-proxy@latest
```

## Use

```
tg-proxy --help
tg-proxy ca generate
tg-proxy -config config.example.yaml
```

See the upstream repo at https://github.com/TensorGreed/tg-proxy for full
documentation.
