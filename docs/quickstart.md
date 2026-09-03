# dp1-cli Quickstart (public beta)

Validation is the fastest way to confirm your integration is on the right track.

This page shows a minimal first run with **dp1-cli**, the open-source command-line tool for DP-1 documents.

**dp1-cli** is the **actively maintained** line in this repository, the **successor** to the frozen legacy **dp1-validator** tag line. **Release tags** separate the two: use **dp1-cli** tags and binaries for current validation, signing, verification, and feed publish workflows.

**dp1-cli is in public beta**; behavior and flags may evolve. See [`docs/cli_design.md`](cli_design.md) for the operator contract.

- What this is: validate, sign, verify, and optionally publish playlists (and related feed resources) using [dp1-go](https://github.com/display-protocol/dp1-go) for schema checks and Ed25519 signatures.
- Why use it: catch payload and signature issues before feed or player debugging; run the same checks locally or in CI.
- What to do next: validate one playlist now, then align schema details with the canonical spec.

## Version note

This quickstart follows **DP-1 core [v1.1.0](https://github.com/display-protocol/dp1/blob/main/core/v1.1.0/spec.md)** (`dpVersion: "1.1.0"`). In that version, each playlist item's `id` is a **UUID**, and a valid document has either a **`signatures[]`** block (recommended) or the legacy top-level **`signature`** field.

The sample below uses a **`signatures[]`** object with **placeholder** `sig` and `payload_hash` values so you can run `validate` and see the shape. Those placeholders are not a real signed playlist: use **`dp1-cli playlist sign`** (or your own signer aligned with the spec) before **`verify`** or **publish**.

dp1-cli delegates validation and signature semantics to **dp1-go**. Other tools in your pipeline may still differ on `signatures[]` verification details — confirm behavior where it matters.

## What dp1-cli does

- **Validate** playlist, playlist-group, and channel JSON against DP-1 rules.
- **Sign** and **verify** documents (Ed25519, per dp1-go).
- **Publish** to a compatible feed API (`POST` to `/api/v1/...` paths), when you configure URL and credentials.

See the [main README](../README.md) for install, config (`~/.dp1/config.yaml`), and environment variables.

## Minimal first run

**Step 1 — Save a minimal playlist as `playlist.json`:**

```json
{
  "dpVersion": "1.1.0",
  "id": "385f79b6-a45f-4c1c-8080-e93a192adccc",
  "title": "Minimal DP-1 Playlist",
  "created": "2025-10-17T07:02:03Z",
  "items": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "title": "Example Item",
      "source": "https://example.com/artwork.html",
      "duration": 30,
      "license": "open"
    }
  ],
  "signatures": [
    {
      "alg": "ed25519",
      "kid": "did:key:z6MkfZ6S4fHBifwKPMdB11HTEHgBuQtB9qrmQcRW7Vc8shxk",
      "ts": "2025-10-17T07:02:03Z",
      "payload_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "role": "curator",
      "sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

**Step 2 — Install and validate** (requires [Go](https://go.dev/dl/) 1.24+):

```bash
go install github.com/display-protocol/dp1-cli@latest
dp1-cli playlist validate ./playlist.json
```

`go install` places the binary on your `PATH` as **`dp1-cli`** (the module name). If you build from a clone with `go build -o dp1 .`, invoke **`dp1`** instead — the command tree is the same as documented in [`docs/cli_design.md`](cli_design.md).

Machine-readable output:

```bash
dp1-cli playlist validate ./playlist.json --json
```

For signing and verification flows, see [`docs/cli_design.md`](cli_design.md).

## Common failure points

- Wrong `dpVersion` for the document you intend to support (this page targets **`1.1.0`**).
- Invalid item `id` for v1.1.0 (must be a **UUID**, not an arbitrary string).
- Missing **`signatures`** and **`signature`** (the schema requires at least one).
- Signature mismatch caused by payload changes after signing.
- Placeholder **`sig`** / **`payload_hash`** pass structural validation but fail **`verify`** — replace them using **`playlist sign`** or an equivalent signer.

## Next step

Read the DP-1 [Schemas](https://github.com/display-protocol/dp1/blob/main/docs/schemas.md) page and align your payload model.
