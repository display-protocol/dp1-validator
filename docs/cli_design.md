# CLI design

**Normative contract for this repo:** the implemented Cobra commands and flags under `cmd/`, plus stable JSON shapes from `internal/output`. When behavior changes, update **this document** and any affected tests.

**Companion:** [`docs/architecture.md`](architecture.md) describes packages and data flow; this document is the **operator-facing** surface (commands, configuration, env vars, output). For building and testing the CLI, see [`DEVELOPMENT.md`](../DEVELOPMENT.md).

**Related:** If you use [dp1-feed-v2](https://github.com/display-protocol/dp1-feed-v2), its HTTP API (including OpenAPI) defines server-side semantics for **`publish`**; the CLI assumes a compatible feed unless noted below.

---

## Global behavior

- **Binary name:** `dp1` (when built with `go build -o dp1 .`).
- **Machine output:** **`--json`** (persistent flag on the root command). When set, success and error objects are JSON-encoded to **stdout** (errors are still JSON to stdout for easy piping—mirror human mode by checking the `ok` field where applicable).

---

## Config file

- **Path:** `~/.dp1/config.yaml` (see `dp1 config path`).
- **Initialization:** `dp1 init` creates `~/.dp1` and writes the default file if missing.
- **Keys writable via `dp1 config set`:**  
  `signing.private_key`, `signing.public_key`, `feed.url`, `defaults.output_format` (`human` or `json`).
- **View merged config:** `dp1 config show` (defaults applied for missing fields). Human mode prints YAML; **`--json`** emits **`ConfigShowOK`** (see JSON shapes).

---

## Environment variables

| Variable | Used for |
| -------- | -------- |
| **`DP1_PRIVATE_KEY`** | Hex Ed25519 private key (seed or expanded) for `sign` subcommands when `--private-key` and config are unset. |
| **`DP1_FEED_URL`** | Base URL for `publish` when `--feed-url` and `feed.url` are unset (non-empty flag wins). |

Precedence for the feed URL is implemented in `internal/feed.ResolveBaseURL`: **flag → env → config** (URL must be non-empty after resolution). Published documents are authenticated by their embedded signature, so no API key is sent.

---

## Input sources (`<source>`)

Commands that take **`<source>`** (`validate`, `verify`, `publish`) load JSON via `internal/input.ReadSource`:

| Form | Meaning |
| ---- | ------- |
| **`-`** or **empty** | Read **stdin**. |
| **`http://` / `https://`** | Fetch with GET (bounded client timeout; follows command cancellation / signal-driven shutdown; `User-Agent: dp1-cli/1.0`). |
| **File path** | Read bytes from disk. |
| **Other non-file string** | If valid standard base64, decode; otherwise treat as file path error path. |

Unsupported URL schemes are rejected explicitly.

---

## Command tree (summary)

| Command | Purpose |
| ------- | ------- |
| `dp1 version` | Print dp1-cli, dp1-go, and Go versions (`--json` supported). |
| `dp1 init` | Create config dir and default `config.yaml` if missing. |
| `dp1 config …` | `path`, `show`, `get KEY`, `set KEY VALUE` (VALUE may be `-` for stdin line). |
| `dp1 key …` | `generate`, `import`, `show` (Ed25519 for DP-1 multi-signatures). See **Key commands** below. |
| `dp1 playlist …` | `validate`, `verify`, `create`, `sign`, `publish` |
| `dp1 group …` | `validate`, `verify`, `create`, `sign`, `publish` |
| `dp1 channel …` | `validate`, `verify`, `create`, `sign`, `publish` |

---

## Document commands

### `validate <source>`

- Runs the appropriate **`dp1.ParseAndValidate*`** for the resource.
- **`--allow-unsigned`:** when schema validation fails **only** because `signatures` / legacy `signature` are missing or `signatures` is an empty array, treat the document as a valid **unsigned draft** (decode fields for output; does not verify cryptographic signatures). Any other schema error still fails. Use after **`create`** and before **`sign`**; **`publish`** and **`verify`** still require a fully valid signed document.
- Human success: short summary with id/title/version fields when present; unsigned drafts include a note to run **`sign`** next.
- JSON success: see **`ValidateOK`** in `internal/output` (`ok: true`; `unsignedDraft: true` when `--allow-unsigned` accepted a signature-only failure).

### `verify <source>`

- Validates then **`verify.Run`** for the resource type.
- **`--pubkey`:** optional filter—verify only signatures matching that key (accepts `did:key`, `did:pkh`, Ed25519 hex, Ethereum address forms as implemented in `internal/verify`).
- JSON success: **`VerifyOK`**.

### `create`

- Interactive draft to stdout or **`-o` / `--output`** path. Drafts are **unsigned**; run **`sign`** before relying on them for publish or verification.
- **`playlist create`**, **`group create`**, and **`channel create`** share a baseline prompt order where it fits: optional resource **id** (UUID v4, generated when blank), **title**, optional **slug** (when blank, the CLI derives one capped at **24 characters**: a truncated normalized title stem plus `-` and the **last 12-character hexadecimal block of a UUID v4**; if the title cannot be normalized, the slug is **24 random `a-z` / `0-9` characters** — no generic stem like `untitled`), optional **created** (default now), then type-specific prompts. **`channel create`** asks extension **version** first (playlist **`dpVersion`** analogue).

### `sign <file>`

- Adds or updates one **v1.1+** multi-signature using dp1-go signing helpers (`internal/jsonsign`), preserving unknown top-level fields. If **`signatures`** already contains an entry with the same **`kid`** and **`role`** (after trimming surrounding whitespace; **`role`** compared case-insensitively), that entry is **replaced** by the new signature so each **`kid`/`role` pair is unique**—re-signing refreshes the slot instead of duplicating it.
- **`--private-key`:** hex key; else **`DP1_PRIVATE_KEY`**; else **`signing.private_key`** in config.
- **`--role`:** valid roles include `curator`, `feed`, `agent`, `institution`, `licensor`, and (for channels) `publisher`. Defaults: **`playlist sign`** and **`group sign`** default to **`curator`**; **`channel sign`** defaults to **`publisher`**.
- **`--ts`:** RFC3339 timestamp (default: now).
- **`--output` / `-o`:** write signed doc (default: overwrite `<file>`; `-` for stdout).

### `publish <source>`

- Reads bytes, validates, **`POST`** to:

  | Resource | Path |
  | -------- | ---- |
  | playlist | `/api/v1/playlists` |
  | group | `/api/v1/playlist-groups` |
  | channel | `/api/v1/channels` |

- **`--feed-url`:** override env/config for this invocation.
- Success when HTTP status is **`201 Created`**; the CLI prints the response body (pretty-printed in human mode when valid JSON).
- JSON success: **`PublishOK`** (`ok`, `resource`, `feed`, `statusCode`, `response`).

Feeds that return another 2xx for create may not be recognized as success by this client.

---

## Key commands

### `key generate`

- Creates a new Ed25519 key pair.
- **`--save-config`:** writes `signing.private_key` and `signing.public_key` to `~/.dp1/config.yaml`. **Does not print the private key** to stdout (human or `--json`); only public `did:key`, public hex, and a save confirmation. Use this for the usual post-`init` setup.
- Without **`--save-config`:** prints the private key hex so the operator can copy it elsewhere (`private_key_hex_expanded` in `--json`).

### `key import` / `key show`

- **`import`:** stores a private key in config; stdout shows public `did:key` only.
- **`show`:** prints public material from flag, env, or config (never secrets).

---

## JSON output shapes (stable for scripting)

Types are defined in `internal/output`:

- **`ValidateOK`:** `ok`, `resource`, optional `dpVersion` / `version`, `id`, `title`, `unsignedDraft`, `message`.
- **`VerifyOK`:** `ok`, `resource`, optional `mode`, `message`, `pubkeyMatch`.
- **`PublishOK`:** `ok`, `resource`, `feed`, `statusCode`, `response` (raw JSON from server).
- **`ConfigShowOK`:** `ok`, `signing` (`private_key`, `public_key`), `feed` (`url`), `defaults` (`output_format`) — merged view, same keys as `config.yaml`.
- **`ErrorReport`:** `ok: false`, `command`, `error` (and optional `resource` when set by callers).

---

## Feed errors

On non-201 responses for `publish`, the CLI parses JSON bodies shaped like `{"error":"...","message":"..."}` when present and includes them in a thrown error string / JSON `error` field (`internal/feed.APIError`).

---

## Compatibility notes

- **Signing and hashing** follow DP-1 and dp1-go; the CLI does not add alternate canonicalization.
- **Publish** is a thin wrapper around feed **create** semantics; PATCH/PUT/DELETE, registry endpoints, and conditional GET (ETag) are **not** exposed here.
- For channel and group documents, validation requires dp1-go builds with the same extension/core schema alignment as your target feed.

---

## Further reading

- [`docs/architecture.md`](architecture.md)
- [DP-1 Specification](https://github.com/display-protocol/dp1)
