# tg-proxy

> Lightweight scanning, redacting network proxy. PII out, secrets out, agents safer in.

[![CI](https://github.com/TensorGreed/tg-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/TensorGreed/tg-proxy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/TensorGreed/tg-proxy.svg)](https://pkg.go.dev/github.com/TensorGreed/tg-proxy)

`tg-proxy` is a forward HTTP(S) proxy that sits between any process and its network destinations, **inspects request and response bodies for sensitive data**, and **redacts in flight** before forwarding. It works at the OS level via `HTTP_PROXY`/`HTTPS_PROXY` and is small enough to drop inline between AI components — agent → LLM, agent → RAG, agent → MCP, agent → agent.

```
┌─────────┐    plain or TLS     ┌──────────┐   scan ▸ redact ▸ forward    ┌──────────┐
│ client  │ ───────────────────▶│ tg-proxy │ ───────────────────────────▶ │ upstream │
└─────────┘                     └──────────┘                              └──────────┘
                                  scanners + redactor   ◀── pluggable ──▶ your code
```

## Why

Most "AI safety" or "DLP" tooling sits at the application layer (SDK middleware) or far downstream (egress firewall). `tg-proxy` aims for the gap in between — a single binary you can put on an OS, in a sidecar, or in a Docker network and have it observe and rewrite whatever HTTP traffic flows through.

It is **not** a WAF, **not** a substitute for at-rest encryption, **not** an exfiltration audit log. It is a small, fast piece of infrastructure that lets you write scanners and redactors in any language and apply them to live traffic.

## Features

- **Two interception modes**
  - Explicit `HTTP_PROXY` / `HTTPS_PROXY` — zero kernel privileges, every common HTTP client honors it.
  - MITM on `CONNECT` — terminates client TLS with an on-the-fly leaf certificate signed by your own CA so HTTPS bodies are scanned, then re-encrypts to the upstream.
- **Built-in scanners**: `pii` (emails, US SSNs, US phones, IPv4, Luhn-validated credit cards), `secrets` (AWS/GitHub/Stripe/OpenAI/Anthropic/Slack/Google tokens, JWTs, PEM private keys), `sqli` (UNION SELECT, tautologies, statement chaining, time-based blind, `xp_cmdshell`, schema recon), and `code` (Python/JS/Go/C/Java/shell/SQL DDL signatures — useful for spotting proprietary code leaking into LLM prompts).
- **Pluggable scanners and redactors** with byte-precise `Start`/`End` offsets — write your own redactor that gets the exact ranges to act on.
- **CA management built in**: `tg-proxy ca generate | install | uninstall | path` handles the trust store on Linux, macOS, and Windows.
- **Single static binary**, ~10 MB, CGO-free, ships on linux/macOS/Windows × amd64/arm64.
- **Distributed five ways**: `go install`, apt `.deb`, `pip install tg-proxy`, `npm install -g tg-proxy`, prebuilt archives.
- **Concurrent scanning** — scanners fan out across goroutines, errors collected with `errors.Join`, fail-open by default.
- **Streaming** — Server-Sent Events, HTTP/1.1 chunked, and HTTP/2 streams flow through a sliding-window scanner so LLM SSE responses stay incremental to the client while still being redacted.
- **CI matrix** on linux/macos/windows with `-race`, golangci-lint, GoReleaser snapshot build, pip and npm package smoke builds, and a coverage gate.

## Install

| Method | Command |
|---|---|
| Go | `go install github.com/TensorGreed/tg-proxy/cmd/tg-proxy@latest` |
| apt | `sudo apt install ./tg-proxy_X.Y.Z_amd64.deb` *(downloaded from the GitHub Release)* |
| pip | `pip install tg-proxy` |
| npm | `npm install -g tg-proxy` |
| Archive | Download from [Releases](https://github.com/TensorGreed/tg-proxy/releases), unpack, run. |

Supported platforms: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64.

## Quick start

```sh
# 1. Run the proxy with built-in defaults (no MITM, scans plain HTTP only).
tg-proxy

# 2. Point a client at it.
export HTTP_PROXY=http://127.0.0.1:8080
curl http://httpbin.org/anything?email=alice@example.com
# Response body comes back with the email redacted as [REDACTED].
```

### Scanning HTTPS too

```sh
# 1. Generate a root CA — written to your user config dir.
tg-proxy ca generate

# 2. Install it into the OS trust store (admin/sudo required).
sudo tg-proxy ca install

# 3. Flip mitm on in config.example.yaml: tls.mitm: true
#    and set tls.ca.cert_path / tls.ca.key_path to what `ca generate` wrote.
tg-proxy -config config.example.yaml

# 4. Now HTTPS works the same way.
export HTTPS_PROXY=http://127.0.0.1:8080
curl https://httpbin.org/anything?email=alice@example.com
```

When you're done:

```sh
sudo tg-proxy ca uninstall
```

## Configuration

A complete annotated example lives at [`config.example.yaml`](config.example.yaml). Run with `tg-proxy -config <path>`; with no flag, sensible defaults are used.

The most important knobs:

```yaml
listen: "127.0.0.1:8080"
limits:
  max_body_size: 10485760    # bytes; bigger bodies error with 413 until streaming lands
tls:
  mitm: true                 # terminate client TLS so HTTPS bodies can be scanned
  ca:
    cert_path: ~/.config/tg-proxy/ca.crt
    key_path:  ~/.config/tg-proxy/ca.key
scanners:
  - name: pii
    enabled: true
redactor:
  name: mask
  config:
    placeholder: "[REDACTED]"
```

## Pluggability

Scanners and redactors implement two small interfaces in [`pkg/api`](pkg/api):

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, data []byte, hints Hints) ([]Finding, error)
}

type Redactor interface {
    Name() string
    Redact(ctx context.Context, data []byte, findings []Finding) ([]byte, error)
}

type Finding struct {
    Type, Scanner string
    Severity      Severity
    Start, End    int        // byte offsets into the scanned slice; End is exclusive
    Confidence    float32
    Metadata      map[string]any
}
```

The `Start` and `End` offsets are the contract that lets you bring your own redactor — your code gets the exact byte ranges of every finding and decides what to do (mask, hash, tokenize, audit, drop the request, ...). See [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-scanner) for a worked example.

### Plugins in any language

If you'd rather write your scanner or redactor in another language, point tg-proxy at a subprocess that speaks the gRPC protocol in [`pkg/plugin/proto/plugin.proto`](pkg/plugin/proto/plugin.proto):

```yaml
scanners:
  - name: my-secrets
    enabled: true
    external:
      command: ["python", "/etc/tg-proxy/plugins/secret_scanner.py"]
```

A Python SDK that hides all the gRPC plumbing is published as `tgproxy-plugin` on PyPI — see [`packaging/python-sdk-plugin/`](packaging/python-sdk-plugin/) for the source and a worked example. The Go SDK lives in [`pkg/plugin/`](pkg/plugin/).

## How it works

```
HTTP_PROXY mode             MITM mode
-----------------           --------------------------------------
client ─► CONNECT host:443  client ─► CONNECT host:443
proxy  ─► dial host:443     proxy  ─► reply 200, terminate TLS with
proxy  ─► splice bytes               leaf cert signed by tg-proxy CA
                            proxy  ─► dial host:443 over TLS
                            proxy  ─► bridge HTTP through pipeline
                            pipeline: scan ▸ redact ▸ forward
```

Bodies are buffered up to `limits.max_body_size`, fanned out across all enabled scanners concurrently, their findings merged (sorted, overlapping ranges coalesced), and passed once through the configured redactor. The rewritten body goes upstream, the response is processed the same way in reverse.

## Roadmap

- [x] **M1** — Explicit proxy, scanner + redactor framework, PII scanner, mask redactor, apt + `go install`.
- [x] **M2** — MITM with on-the-fly CA, OS trust-store install/uninstall, `tg-proxy ca` subcommands.
- [x] **M3** — pip wheels + npm packages, all distribution channels wired into the release pipeline.
- [x] **M4** — Streaming bodies (SSE, chunked, HTTP/2) with sliding-window scanning so long-running LLM responses scan in flight.
- [x] **M5** — gRPC-based external plugin host (HashiCorp `go-plugin`) with a Python SDK so scanners and redactors can be written in any language. (Node SDK is a follow-up.)
- [x] **M6 (scanners)** — Built-in `secrets`, `sqli`, and `code` scanners. Prometheus metrics and hot config reload are still pending.
- [ ] **M7** — Linux transparent mode via `SO_ORIGINAL_DST` + SNI sniffing for OS-level redirect without `HTTPS_PROXY`.

## Project status

`tg-proxy` is pre-1.0. The CLI surface, config schema, and Go API are all candidates to change before v1.0 is cut. The Scanner/Redactor interfaces in `pkg/api` are intentionally tiny precisely so they can stabilize early — most evolution will happen elsewhere.

## Contributing

Open to PRs. Start at [CONTRIBUTING.md](CONTRIBUTING.md) — it covers the dev setup, conventions, and how to add a new scanner or redactor.

For security issues, see [SECURITY.md](SECURITY.md) — please do not file public issues for vulnerabilities.

## License

[MIT](LICENSE).
