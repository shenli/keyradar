# Validation record — 0.1.0-alpha

Baseline: 2026-10-21. Pre-push checks repeated on 2026-10-22. Local runner: macOS arm64, Go 1.26.2. All source and issuer API responses used by tests are mocked. No live provider credentials were supplied or used.

## Completed locally

| Check | Result | Evidence / scope |
|---|---|---|
| `go test ./...` | PASS | Core operations, case store, CLI, source adapters, issuer adapters, reports, secure IO, TUI and templates |
| `go test -race ./...` | PASS | Same automated test suite under race detector |
| `go vet ./...` | PASS | Static checks |
| `make smoke` | PASS | Built binary: local scan, metadata persistence, rescan history, report, cleanup, exit codes, invalid-argument containment; actual PTY demo/navigation/exit; temporary skill-layout installs |
| Parser fuzzing | PASS | `go test ./internal/scan -run '^$' -fuzz FuzzParseEnv -fuzztime 10s -parallel 2`: 513,943 executions; no failing input |
| Skill package validation | PASS | Both SKILL.md packages checked by the skill-creator validator |
| Schema drift | PASS | `python3 scripts/generate_schemas.py --check` |
| Linux amd64 cross-build | PASS | Compiled on macOS; Linux runtime execution remains pending CI |
| Clean staged-tree smoke | PASS | Exported staged source to a fresh directory; built CLI and passed offline PTY/workflow smoke |
| Native build | PASS | `go build -trimpath -o bin/keyradar ./cmd/keyradar` |
| Patch whitespace | PASS | `git diff --check` |

Specific assertions cover exact readable equality, same-name/different-value separation, unscoped password separation, unreadable/empty/reference uncertainty, sensitive Vercel values, encrypted responses, later GitHub page denial, Railway GraphQL errors, bounded retry behavior, cancellation, symlink rejection, schema/load errors, writer locking, and preservation of old credentials/tasks. A missing observation in a new scan does not remain a current credential copy.

Synthetic canaries are checked against private state, private/shareable JSON and Markdown, CLI failures and TUI views. This is evidence for the tested paths, not a proof that all possible secret-bearing metadata is recognizable. Shareable output independently omits external labels and issuer identifiers.

Issuer tests cover separate audit authorization, AWS account mismatch, advancing activity, null activity, future timestamps, OpenAI denial/missing/rate-limit failures, unexpected key identity, and raw error-body containment. No check completes retirement tasks or treats silence as proof of safety.

The PTY harness answers standard terminal startup queries. It checks the persistent caret, opens and cancels the guided Vercel form, runs the offline demo, visits all four screens and exits. A second PTY session adds a local path containing spaces through the guided form, explicitly scans it, and verifies the saved case through the CLI. Hidden authentication prompts and live issuer interaction have not been exercised in that PTY test.

## Pending before claiming the full production release gate

- Controlled live Vercel, Railway and GitHub account checks against the actual API contracts and permissions.
- Controlled live AWS IAM and OpenAI key-metadata checks with independent audit access.
- TUI authenticated interaction and cancellation during a real network operation, with terminal restoration verified.
- Actual Codex/Claude Code skill loading and adversarial behavior evaluations. File validation and temporary installation layout checks do not establish model behavior or isolation.
- Hosted Linux/macOS CI execution; consult the repository Actions results for the pushed commit.
- GitGuardian/TruffleHog comparison and responder usability sessions; see `benchmark.md` (not run).
- Confirm the repository's private security-reporting channel is enabled before publishing a release.

The implementation is a reviewable development alpha. Do not label these pending checks complete, claim exhaustive discovery, or claim that quiet issuer activity proves an old credential is safe to retain/revoke.

## Guided UI follow-up — 2026-10-22

The home screen now has a selected action and a compact layout capped at 100 columns, without padding to the bottom of a large terminal. Enter/arrow-key navigation handles source selection, scan initiation and movement through coverage, findings and next actions. Esc returns to earlier fields with their values preserved; invalid fields remain editable. Optional commands remain supported.

Regression checks cover the 400×100 terminal layout from the reported issue, complete Unicode dividers, narrow windows, command-free navigation, source removal before scanning, and Back navigation. The local-file PTY smoke uses Enter navigation to select, scan and persist a source without slash commands. Authentication and live-provider validation remain unchanged in scope.

Spacing refinement: terminals with at least 24 rows now separate the heading, helper text, input and keyboard guidance with deliberate margins. Source fields use a padded input box; the Railway form occupies about 20 rows at 100×24. Shorter windows retain the bounded compact layout. TUI checks and the built-binary PTY workflow pass.
