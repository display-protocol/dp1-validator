# Development guide

This document is for people working on dp1-cli itself: layout, tooling, and how to verify changes.

**Coding agents:** see [AGENTS.md](AGENTS.md), [`.cursor/rules/`](.cursor/rules/), [`.cursor/agents/reviewer.md`](.cursor/agents/reviewer.md), [`prompts/code-review.md`](prompts/code-review.md), and [`prompts/code-review.delta.md`](prompts/code-review.delta.md).

## Prerequisites

- Go **1.24** or newer (`go version`)
- **`golangci-lint`** v2.x on your PATH (same family as CI; see [.golangci.yml](.golangci.yml))
- Optional: **Node.js** with `npx` for `markdownlint-cli2` (also run in `make lint`)

## Getting started

```bash
git clone https://github.com/display-protocol/dp1-cli.git
cd dp1-cli
go mod download
go test ./... -race -count=1
```

If tests pass, you can iterate locally with:

```bash
go build -o dp1 .
./dp1 version
```

## Project structure

```text
dp1-cli/
├── main.go                 # Entry: delegates to cmd.Execute
├── cmd/                    # Cobra commands and wiring
├── internal/
│   ├── config/           # ~/.dp1/config.yaml load/save
│   ├── feed/             # HTTP client for POST /api/v1/{resource}
│   ├── input/            # Read JSON: file, URL, stdin, base64
│   ├── output/           # Human vs --json success/error shapes
│   ├── jsonsign/         # Append multi-signatures; preserve unknown fields
│   ├── signkey/          # Resolve private key: flag → env → config
│   ├── verify/           # Signature verification after validation
│   ├── create/           # Interactive drafts
│   ├── ask/, fields/     # Prompts and field helpers for create
│   └── uuid/             # ID generation for drafts
└── docs/                  # Architecture, CLI design, coding standards
```

Normative behavior for commands and flags is documented in [docs/cli_design.md](docs/cli_design.md). DP-1 rules live in **dp1-go**; avoid duplicating spec logic in this repo.

## Verification

### Tests

```bash
go test ./... -race -count=1 -timeout=5m
```

Some packages include integration-style tests (for example under `cmd/`); they should remain deterministic and offline-friendly without extra services.

### Lint and format

```bash
make lint        # golangci-lint + markdownlint on Markdown
make fmt         # gofmt
make fmt-imports # goimports via golangci-lint fmt
make vet
```

### Local CI-style gate

```bash
make check       # lint + race tests
```

## Configuration in development

The CLI reads **`~/.dp1/config.yaml`**. For local runs you can rely on env instead of editing the file:

| Variable | Purpose |
| -------- | ------- |
| `DP1_PRIVATE_KEY` | Hex Ed25519 key for `sign` commands |
| `DP1_FEED_URL` | Feed base URL for `publish` |

See [docs/cli_design.md](docs/cli_design.md) for precedence (flags override env override config).

## Workflow for changes

1. Branch from the default integration branch (`main` or `develop`, per repo practice).
2. Keep the change scoped; prefer tests for new behavior or regressions.
3. Update [docs/cli_design.md](docs/cli_design.md) (and [docs/architecture.md](docs/architecture.md) if boundaries move) when user-visible behavior or contracts change.
4. Run **`make check`** before opening a PR.
5. Use the pull request template and link related issues.

## Code style

- Follow [docs/go_coding_standards.md](docs/go_coding_standards.md).
- Prefer explicit errors and `%w` wrapping.
- Use `context.Context` on I/O paths that support cancellation (HTTP client, requests).

## Debugging tips

- **`dp1 config show`** — Inspect merged config (defaults applied).
- **`dp1 playlist validate <source> --json`** — Stable errors on validation failures.
- Publish failures surface feed `error` / `message` fields when the server returns JSON (see `internal/feed.APIError`).

## Further reading

- [DP-1 specification](https://github.com/display-protocol/dp1)
- [dp1-go](https://github.com/display-protocol/dp1-go)
