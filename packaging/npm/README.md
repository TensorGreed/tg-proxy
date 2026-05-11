# tg-proxy

Lightweight network proxy with built-in scanners (PII, secrets, code) and
pluggable in-flight redaction.

## Install

```
npm install -g tg-proxy
# or with pnpm/yarn
pnpm add -g tg-proxy
yarn global add tg-proxy
```

npm installs this package plus one of the platform-specific helper packages
(`tg-proxy-linux-x64`, `tg-proxy-darwin-arm64`, …). Only the matching one
ships the prebuilt binary, so install is fast.

Supported platforms:

| OS      | Architectures        |
|---------|----------------------|
| Linux   | x64 (amd64), arm64   |
| macOS   | x64 (Intel), arm64   |
| Windows | x64 (amd64), arm64   |

On unsupported platforms the install succeeds but the shim prints an error
on first run. Build from source via Go in that case:

```
go install github.com/TensorGreed/tg-proxy/cmd/tg-proxy@latest
```

## Use

```
tg-proxy --help
tg-proxy ca generate
tg-proxy -config config.example.yaml
```

See https://github.com/TensorGreed/tg-proxy for full documentation.
