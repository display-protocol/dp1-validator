# AGENTS.md — dp1-cli

Contract for coding agents. Cursor loads granular rules from `.cursor/rules/`; this file is the overview and workflow index.

## Repository overview

- **Project:** dp1-cli — Go **command-line client** for [DP-1](https://github.com/display-protocol/dp1): validate, sign, verify, draft, and **create** documents on a compatible feed via `internal/feed`.
- **Protocol:** [dp1-go](https://github.com/display-protocol/dp1-go) owns validation, signing, and verification semantics. This repo orchestrates; it does not fork JCS, payload hashing, or schema logic.

## Canonical documentation

| Document | Role |
| -------- | ---- |
| `docs/architecture.md` | Package layout, dependency direction, flows. |
| `docs/cli_design.md` | Operator contract: commands, flags, env vars, JSON output. **Must stay in sync** with user-visible behavior. |
| `docs/go_coding_standards.md` | Go style expectations. |

There is **no** in-repo OpenAPI for a server; feed compatibility is described in `docs/cli_design.md` and the target service’s docs.

## Non-negotiables

- Prefer focused changes; avoid scope creep without explicit agreement.
- Use dp1-go public APIs for DP-1 correctness; do not reimplement canonicalization in `cmd`.
- Surface explicit errors; use `internal/output` for stable `--json` reporting.
- Update `docs/cli_design.md` when CLI behavior changes; update `docs/architecture.md` when package boundaries change.

**Default “always on” set for agents:** everything in `.cursor/rules/` with `alwaysApply` except treat **`spec-driven.mdc`** as the extra gate for **large or ambiguous** work (new command families, multi-package refactors, contract changes). **`review-workflow.mdc`** applies when you are finishing a PR-sized change and need an externalized review pass.

## Rule files (what to load when)

| Rule | Essential for | Notes |
| ---- | ------------- | ----- |
| `01-master-design.mdc` | **Always** | Boundaries and canonical doc pointers. |
| `10-go-coding-standards.mdc` | **Always** | Go readability, errors, testing style. |
| `15-comment-contract.mdc` | **Always** | When code is non-obvious (credentials, HTTP, dp1-go edges). |
| `20-architecture.mdc` | **Always** | Mirrors `docs/architecture.md` at high level. |
| `21-cli-design.mdc` | **Always** | Mirrors `docs/cli_design.md`; Publish paths, `--json` contract. |
| `35-testing-tdd.mdc` | **Always** | `make check`, test expectations. |
| `spec-driven.mdc` | **Large / ambiguous work** | New command trees, wide refactors, contract shifts—plan first (no `PLANS.md` in this repo). |
| `review-workflow.mdc` | **Non-trivial changes** | Fresh-context completion review; see below. |

**Feed-only concepts** (executor/store, OpenAPI, ETag, PostgreSQL) are **not** duplicated here; do not import workflows from other repos unless this project explicitly adopts them.

## Required development sequence

1. Refine small units and tests where practical.
2. Implement production code.
3. Run **`make check`** (golangci-lint + race tests).
4. For Markdown changes, satisfy repo markdown lint when touched (`make lint` / CI).

## Definition of done

A change is complete when:

1. **`make check`** passes (unless explicitly waived).
2. Comments cover non-obvious intent where needed.
3. User-visible behavior matches **`docs/cli_design.md`**; structure matches **`docs/architecture.md`** when applicable.
4. For non-trivial changes, a fresh-context review has reported findings per `prompts/code-review.md` for the change owner to disposition.

## Review workflow

For non-trivial changes, run the fresh-context review from `.cursor/rules/review-workflow.mdc` after implementation and green checks:

1. Compact handoff (goal, files, decisions, checks, assumptions).
2. Invoke the **`reviewer`** sub-agent: `.cursor/agents/reviewer.md`.
3. The named human change owner decides how to disposition each finding.
4. Treat the verdict as a sensor reading; it carries no commit, merge, or release authority.

**Reviewer sources:** the generated contract in `prompts/code-review.md`, plus the repository-specific checks in `prompts/code-review.delta.md`.

## Commit messages

Prefer [Conventional Commits](https://www.conventionalcommits.org/):

- `feat`, `fix`, `refactor`, `test`, `chore`, `docs`, `build`, `ci`, `perf`, `style`
- Optional scope; use `!` for breaking CLI behavior.

## Further reading

- `DEVELOPMENT.md` — clone, build, project tree, tooling.
- `.cursor/agents/reviewer.md` — reviewer sub-agent definition.
