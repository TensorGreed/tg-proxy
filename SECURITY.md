# Security Policy

`tg-proxy` is a security tool — it sees plaintext network traffic and holds private CA key material. Vulnerabilities here are unusually load-bearing, so we treat reports seriously and want to make reporting them easy.

## Supported versions

`tg-proxy` is pre-1.0. Only the **latest tagged release** receives security fixes. Once v1.0 ships this policy will move to a published support window.

| Version                     | Security fixes |
|-----------------------------|----------------|
| Latest tagged release       | Yes |
| Any previous tagged release | No  |
| `main` branch               | Best effort |

If you need an older release patched (vendored fork, regulated environment), please reach out before relying on it.

## Reporting a vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Two preferred channels:

1. **GitHub private security advisory** (preferred). Visit
   <https://github.com/TensorGreed/tg-proxy/security/advisories/new>
   and open a draft advisory. Only project maintainers see it. This automatically links the conversation to a CVE process if the fix warrants one.
2. **Email**: `security@tensorgreed.io` *(this is the project's placeholder address; please update it in `SECURITY.md`, `.goreleaser.yaml`, and any other publishing manifests before going public).* If possible, encrypt the message with the maintainer's GPG key (advertised in the GitHub security advisory page once configured).

Please include:

- A clear description of the vulnerability and its impact.
- Reproduction steps or a proof-of-concept. Even a curl-style trace helps.
- The affected version (`tg-proxy -version`), OS, and any relevant config (please scrub real secrets).
- Whether you intend to disclose publicly, and on what timeline.

## What we'll do

- We aim to **acknowledge** your report within **3 business days**.
- We aim to **triage and confirm or refute** within **10 business days**.
- We aim to **ship a fix and a coordinated disclosure** within **90 days** of triage, faster when active exploitation is likely. We may request a longer embargo for severe, hard-to-fix issues; we'll talk to you first.
- Credit is given by default in the changelog and advisory unless you ask to remain anonymous.

We do not currently run a paid bug bounty.

## Scope

In scope:

- Vulnerabilities in the proxy itself: bypasses of body scanning, leak paths around redaction, TLS handshake issues, MITM cert validation flaws, panics or DoS from crafted bodies, path traversal or symlink issues in the `ca` subcommand, privilege issues in OS trust-store install scripts, prompt-injection-style escape of finding offsets.
- Vulnerabilities in the official distribution: `.deb` package, pip wheels, npm packages, GoReleaser release pipeline (compromised artifact, missing signature, etc.).
- Vulnerabilities in the public Go API in `pkg/api` that could affect plugins.

Out of scope:

- Behaviors that depend on `tls.upstream_insecure: true` or running with MITM disabled (`tls.mitm: false`) for HTTPS — these are documented escape hatches, not security boundaries.
- Vulnerabilities in upstream Go standard library, `golang.org/x/...`, `gopkg.in/yaml.v3`, or `github.com/stretchr/testify`. Please report those to their respective projects; we'll bump the dependency once a fix is available.
- The classic regex false-positive / false-negative trade-off in the built-in PII scanner. The PII scanner is best-effort and explicitly not a compliance tool; pattern improvements are welcome via normal PRs.
- Trust-store install commands failing on unusual or non-standard OS configurations.

## Non-vulnerability disclosures

If you spot a security-relevant concern that doesn't rise to the level of a vulnerability (a hardening suggestion, a missing test, a default that should be tighter), file a normal public issue or PR.

## Threat model in brief

`tg-proxy` is meant to run as a trusted process. Its threat model assumes:

- The host running `tg-proxy` is trusted; the CA private key is protected by file permissions and the running user.
- Clients route traffic through `tg-proxy` intentionally.
- The `tg-proxy ca install` command is run by an administrator who understands they are adding a root CA to the OS trust store.

It is **not** designed to be safe against:

- An attacker with read access to the CA key file.
- An attacker who controls the upstream and the proxy's network path simultaneously.
- Misconfigurations that disable upstream TLS verification on untrusted networks.

If your deployment falls outside these assumptions, please reach out and we'll either tighten the defaults or document the gap explicitly.
