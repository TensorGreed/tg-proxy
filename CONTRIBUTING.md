# Contributing to tg-proxy

Thanks for considering a contribution. This document covers what you need to know to get a working dev environment, the project conventions, and the most common contribution patterns — adding a new scanner or redactor.

## Code of Conduct

Participation in this project is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to abide by its terms.

## Reporting bugs and proposing features

- Search [existing issues](https://github.com/TensorGreed/tg-proxy/issues) first.
- For bugs, include the version (`tg-proxy -version`), OS, exact steps to reproduce, and the config (with secrets scrubbed).
- For features, open an issue describing the use case before sending a PR — large changes are easier to land when their shape has been discussed.

For security vulnerabilities, **do not file a public issue**. See [SECURITY.md](SECURITY.md).

## Development environment

Required:

- **Go 1.25** or later (`go version`). Older toolchains will be auto-fetched via the `toolchain` directive when `GOTOOLCHAIN=auto`.
- **make** — most workflows are one command away (`make test`, `make lint`, ...). Optional but convenient.

Optional, only needed when working on the packaging wrappers:

- **Python 3.8+** with `pip install build wheel` — for the pip wheel builder under `packaging/pip/`.
- **Node.js 18+** — for the npm wrapper under `packaging/npm/`.

Recommended:

- `golangci-lint` 1.61+. Install with `go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0` or via your package manager.
- `goreleaser` (only needed for release engineering): `go install github.com/goreleaser/goreleaser/v2@latest`.

## Build, test, lint

```sh
make build         # produces bin/tg-proxy
make test          # go test -race -coverprofile=coverage.out ./...
make cover         # function-by-function coverage report
make lint          # golangci-lint
make cover-check   # fails if total coverage drops below 80%
```

The coverage threshold defaults to 80%. The gap above 80% is statements that can't be exercised without spawning a subprocess (`main`/`run`), without admin privileges (OS trust-store shell-outs), or without mocking `crypto/rand`.

## Coding conventions

We aim for code that is easy to skim and behaves predictably under load. The conventions below are the result of past lessons; please follow them in new code.

- **No surrounding cleanup.** A bug fix doesn't need a refactor; a refactor doesn't need new features. Keep diffs scoped.
- **Comments explain *why*, not *what*.** Don't restate what the code does. Do explain a hidden constraint, a subtle invariant, a known surprise, or the rationale for an unusual choice.
- **No premature abstractions.** Three similar lines are better than a helper that hides them.
- **Trust internal boundaries.** Validate at the edges (user input, network, files). Don't pepper internal functions with defensive checks.
- **Errors propagate.** Use `fmt.Errorf("...: %w", err)` to wrap with context. Avoid swallowing errors silently.
- **Concurrency primitives:** prefer `errors.Join` and `sync.WaitGroup` over channel-as-mutex tricks; reach for `golang.org/x/sync/singleflight` only when you've measured the cost.
- **Tests live next to the code** they test. Test files use the package's name (white-box testing) unless they really need to test only the exported API.

`go vet`, `golangci-lint`, and the coverage gate all run in CI. PRs that don't pass them will be asked to fix the issue at the root, not paper over with `//nolint` unless there's a clear justification.

## Repository layout

```
cmd/tg-proxy/           # CLI entry point, ca subcommand
internal/
  ca/                   # root CA, leaf cert factory, OS trust-store installers
  config/               # YAML config + validation
  pipeline/             # scan fan-out + redactor application
  proxy/                # HTTP(S) server, MITM bridge, single-conn listener
  redactor/             # redactor framework + built-in mask
  scanner/              # scanner framework + built-in PII (regex)
pkg/api/                # public types (Scanner, Redactor, Finding, ...)
packaging/
  pip/                  # Python wrapper + per-platform wheel builder
  npm/                  # Node wrapper + per-platform package builder
.github/workflows/      # CI (test + lint) and Release (goreleaser + pip + npm)
.goreleaser.yaml        # build matrix, archives, .deb via nfpm
config.example.yaml     # annotated config
```

Anything under `internal/` is private to this module. Plugins import only `pkg/api`.

## Adding a scanner

Scanners satisfy [`api.Scanner`](pkg/api/scanner.go):

```go
package myscan

import (
    "context"
    "regexp"

    "github.com/TensorGreed/tg-proxy/pkg/api"
)

const Name = "myscan"

type Scanner struct{}

func New() *Scanner    { return &Scanner{} }
func (*Scanner) Name() string { return Name }

func (*Scanner) Scan(_ context.Context, data []byte, _ api.Hints) ([]api.Finding, error) {
    var out []api.Finding
    for _, idx := range pattern.FindAllIndex(data, -1) {
        out = append(out, api.Finding{
            Type:       "myscan.thing",
            Severity:   api.SeverityHigh,
            Start:      idx[0],
            End:        idx[1],
            Confidence: 0.9,
            Scanner:    Name,
        })
    }
    return out, nil
}

var pattern = regexp.MustCompile(`...`)
```

Constraints worth re-reading:

- `Start` and `End` are **byte offsets** into the slice passed to `Scan`. `End` is exclusive. Slicing `data[f.Start:f.End]` must reproduce the matched substring — the mask redactor and any custom redactor rely on this.
- `Scan` must be **safe for concurrent use** — the pipeline fans bodies out across all enabled scanners in parallel.
- Use Go's `regexp` package (RE2). It is linear-time and not vulnerable to catastrophic backtracking, so it's safe on attacker-controlled bodies.
- Return `nil, nil` if there's nothing to flag. Allocating an empty slice is fine but wasteful.

Wire it into [`cmd/tg-proxy/main.go`](cmd/tg-proxy/main.go)'s `buildScanners` to make it discoverable by config:

```go
if err := reg.Register(myscan.New()); err != nil { return nil, err }
```

Test patterns to follow are in [`internal/scanner/pii/pii_test.go`](internal/scanner/pii/pii_test.go) — every detector has an offset-precision test that asserts `input[f.Start:f.End]` equals the expected substring.

## Adding a redactor

Redactors satisfy [`api.Redactor`](pkg/api/redactor.go):

```go
func (r *MyRedactor) Redact(_ context.Context, data []byte, findings []api.Finding) ([]byte, error) {
    // 1. Skip invalid findings (Start<0, End>len, Start>=End).
    // 2. Sort by Start, then End desc, so coalescing is deterministic.
    // 3. Merge overlapping ranges if your redaction is monotonic
    //    (re-redacting an already-redacted span shouldn't double up).
    // 4. Build the new buffer in one pass.
    ...
}
```

The mask redactor at [`internal/redactor/mask/mask.go`](internal/redactor/mask/mask.go) is a fully-worked reference. Tests in `mask_test.go` cover overlapping, adjacent, out-of-order, and invalid findings — your redactor should handle those too.

Only one redactor runs per pipeline; the user picks it by `redactor.name` in config. Register yours in `buildRedactor` in [`cmd/tg-proxy/main.go`](cmd/tg-proxy/main.go).

## Pull requests

- Branch from `main`; one logical change per PR. Smaller is easier to review.
- Run `make test lint cover-check` locally before pushing. CI will run the same plus the cross-platform matrix and packaging smoke builds.
- Write a clear PR description: what changes, why, and any tradeoffs you considered. A linked issue is a plus.
- We don't enforce a strict commit message format, but a short imperative subject (50 chars) + a body explaining *why* is the norm. Squash-merge is the default.

## Releases

Releases are tag-driven. Pushing a tag matching `v*` triggers the [release workflow](.github/workflows/release.yml), which runs goreleaser, builds platform wheels and npm packages, and publishes everything. Maintainers can cut a release with:

```sh
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

Before tagging, please verify the CI snapshot build on `main` is green and the `pip-wrapper` / `npm-wrapper` jobs uploaded artifacts that look right.

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
