# Architecture

dp1-cli is a **command-line tool** for working with [DP-1](https://github.com/display-protocol/dp1) documents locally: validate JSON against embedded schemas ([dp1-go](https://github.com/display-protocol/dp1-go)), verify and append Ed25519 signatures, interactively draft playlists/channels/groups, and **create** resources on a compatible feed HTTP API.

**Design philosophy:** keep transport thin, push protocol correctness to dp1-go, and isolate UX (prompts, colors, JSON output) from signing and validation.

```text
Operator → dp1-cli → dp1-go (validate / sign / verify)
         ↘ HTTP POST → Feed API (/api/v1/...)  [optional]
```

---

## Target package layout

| Area | Packages | Role |
| ---- | -------- | ---- |
| **Entry** | `main`, `cmd` | Cobra commands, flags, wiring; no business rules beyond orchestration. |
| **Configuration** | `internal/config` | `~/.dp1/config.yaml`: signing keys, default feed URL, output defaults. |
| **Feed client** | `internal/feed` | Minimal HTTP client: resolve base URL, `POST /api/v1/{playlists,playlist-groups,channels}`, map error bodies. |
| **Input** | `internal/input` | Load JSON from file path, `http(s)` URL (GET uses bounded timeout and honors command cancellation), stdin (`-`), or inline base64. |
| **Output** | `internal/output` | Human-readable vs machine JSON for success and error reporting. |
| **Signing helpers** | `internal/jsonsign`, `internal/signkey` | Add or refresh multi-signatures (same **kid**/**role** replaces an existing entry); preserve unknown fields; resolve private key (flag → env → config). |
| **Verification** | `internal/verify` | Signature checks after schema validation (v1.1+ multi-sig and legacy paths). |
| **Interactive create** | `internal/create`, `internal/ask`, `internal/fields` | Guided drafts and field validation for `create` subcommands. |
| **Identifiers** | `internal/uuid` | UUID generation where the CLI assigns new document ids in drafts. |

---

## Boundary rules

- **`cmd`:** Parses CLI args, calls internal packages, prints results. Avoid embedding DP-1 rules that belong in dp1-go (schema shapes, JCS, digest rules).
- **dp1-go:** Source of truth for `ParseAndValidate*` and low-level `sign` APIs; the CLI must not fork canonicalization.
- **`internal/feed`:** HTTP only—no document mutation beyond sending bytes the operator prepared.
- **`internal/config`:** File I/O and merge with defaults only—no network.

---

## Dependency direction

- **`cmd` →** (`config`, `feed`, `input`, `output`, `create`, `verify`, `jsonsign`, `signkey`, …).
- **`internal/feed` →** `config` (for default URL/key resolution only).
- **`internal/signkey` →** `config` (cached load for private key fallback).
- **Avoid cycles:** keep shared structs in small packages (`output`, `config`) rather than importing `cmd` from libraries.

---

## Configuration and credentials

- **Config directory:** `~/.dp1/` (mode `0700` when created). **`dp1 init`** ensures the directory and writes `config.yaml` if missing.
- **Defaults:** when keys are absent in the file, `internal/config` merges defaults (including a stock `feed.url` for convenience—override for your deployment).
- **Private key resolution (signing):** `--private-key` flag → `DP1_PRIVATE_KEY` → `signing.private_key` in config. See [`cli_design.md`](cli_design.md).
- **Feed URL (publish):** `--feed-url` → `DP1_FEED_URL` → `feed.url` in config.

---

## Typical flows

### Validate locally

```text
dp1 playlist validate <source>
  → input.ReadSource
  → dp1.ParseAndValidatePlaylist
  → stdout (human or --json)
```

`<source>` is described in [`cli_design.md`](cli_design.md).

### Sign then verify

```text
dp1 playlist sign playlist.json
  → jsonsign (add signature; same kid/role replaces prior entry; preserve unknown fields)
dp1 playlist verify playlist.json
  → ParseAndValidate + verify.Run
```

### Publish to a feed

```text
dp1 playlist publish <source>
  → read bytes → ParseAndValidate* → POST /api/v1/playlists
  → expect HTTP 201; print server JSON body on success
```

The wire format and status codes follow the feed service; for [dp1-feed-v2](https://github.com/display-protocol/dp1-feed-v2), see its HTTP documentation and OpenAPI.

---

## Observability

- **Logging:** there is no long-running daemon—human mode prints results on **stdout** and errors on **stderr**; **`--json`** emits structured success and error objects on **stdout** (see `internal/output`).
- **Machine output:** global **`--json`** for scripts and CI.
- **HTTP:** feed client sets `User-Agent: dp1-cli/1.0` and a bounded request timeout (see `internal/feed`).

---

## Technology stack

- Go, Cobra, dp1-go, YAML config, optional colorized stdout/stderr.

---

## Build and install

### Local binary

```bash
go build -o dp1 .
./dp1 version
```

### Makefile (recommended checks)

```bash
make check   # lint + race tests (similar spirit to CI)
```

See repository `Makefile` for `build`, `test`, `lint`, and related targets.

---

## Further reading

- [DP-1 Specification](https://github.com/display-protocol/dp1)
- [CLI design](cli_design.md) (commands, flags, env vars, JSON output contract)
- [Go coding standards](go_coding_standards.md)
- [DEVELOPMENT.md](../DEVELOPMENT.md) (contributing and verification)

---

## Contributing

Prefer small, reviewable changes. See [DEVELOPMENT.md](../DEVELOPMENT.md) and run `make check` before opening a PR.
