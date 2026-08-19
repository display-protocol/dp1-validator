# dp1-cli Review Delta

Apply these repository-specific checks in addition to `prompts/code-review.md`:

- Keep DP-1 validation and signing in `dp1-go` public APIs; do not add ad hoc canonicalization or protocol logic under `cmd`.
- Preserve the CLI contract for flags, environment/config precedence, human output, stable `--json` shapes, and actionable errors. Never print credentials or secrets.
- Keep `cmd` orchestration separate from `internal/*`; pass contexts through HTTP and other blocking I/O with clear cancellation ownership.
- Check feed publish behavior, including documented `201` semantics, against `docs/cli_design.md` and update that document for user-visible changes.
- Run `make check`; update `docs/architecture.md` when package boundaries change.
