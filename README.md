# dp1-cli

[![Lint](https://github.com/display-protocol/dp1-cli/actions/workflows/lint.yaml/badge.svg)](https://github.com/display-protocol/dp1-cli/actions/workflows/lint.yaml)
[![Tests](https://github.com/display-protocol/dp1-cli/actions/workflows/test.yaml/badge.svg)](https://github.com/display-protocol/dp1-cli/actions/workflows/test.yaml)

> Command-line tool for [DP-1](https://github.com/display-protocol/dp1) playlists, playlist-groups, and channels—validate, sign, verify, and publish via a compatible feed API.

dp1-cli wraps [dp1-go](https://github.com/display-protocol/dp1-go) for schema validation and Ed25519 multi-signatures. Use it locally or in CI to work with JSON documents before or after they live on a server.

## Requirements

- Go **1.24** or newer (see `go.mod`)

## Install

From a clone:

```bash
go build -o dp1 .
```

Or install with a stable module version:

```bash
go install github.com/display-protocol/dp1-cli@latest
```

## Quick start

Initialize config and optional signing key:

```bash
./dp1 init
./dp1 key generate --save-config
```

Validate a playlist:

```bash
./dp1 playlist validate ./playlist.json
```

Machine-readable output:

```bash
./dp1 playlist validate ./playlist.json --json
```

Publish a validated document to a feed (URL from flag, env, or `~/.dp1/config.yaml`; documents are authenticated by their embedded signature):

```bash
export DP1_FEED_URL="https://your-feed.example"
./dp1 playlist publish ./playlist.json
```

## Documentation

- **[docs/quickstart.md](docs/quickstart.md)** — Minimal first run: validate a sample playlist end-to-end
- **[docs/cli_design.md](docs/cli_design.md)** — Commands, flags, env vars, and JSON output
- **[docs/architecture.md](docs/architecture.md)** — Package layout and design boundaries
- **[docs/go_coding_standards.md](docs/go_coding_standards.md)** — Style and testing expectations
- **[DEVELOPMENT.md](DEVELOPMENT.md)** — Contributing, project structure, and verification

## Contributing

1. Open an issue or discussion to align on larger changes when useful.
2. Branch from `main` or `develop`, keep commits focused.
3. Run **`make check`** (lint + race tests) before pushing.
4. Open a pull request using the repository template and describe behavior changes and spec ties (DP-1 / dp1-go) when relevant.

## License

See the `LICENSE` file in this repository when present.
