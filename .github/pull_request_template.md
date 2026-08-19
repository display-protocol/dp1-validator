## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation only
- [ ] Refactor (no user-visible behavior change)
- [ ] Dependency or tooling update

## Checklist

- [ ] I ran **`make check`** (or equivalent: `golangci-lint` + `go test ./... -race -count=1`).
- [ ] I updated **docs** when behavior, flags, env vars, or JSON output shapes changed (`docs/cli_design.md`, and `docs/architecture.md` if package boundaries changed).
- [ ] Tests cover new logic or regressions where practical.
- [ ] DP-1 / **dp1-go** semantics (validation, signing, canonicalization) are unchanged unless explicitly intentional and documented.
- [ ] **Agent review:** for a non-trivial change, run the fresh-context reviewer (`prompts/code-review.md` plus `prompts/code-review.delta.md`) and record the disposition of any material findings.

## Spec and compatibility

<!-- If this touches DP-1 behavior, cite the spec section or dp1-go release. If it is an interop-sensitive change, say how you verified it. -->

## Screenshots / examples

<!-- Optional: paste CLI output (human or `--json`) for notable UX changes. -->
