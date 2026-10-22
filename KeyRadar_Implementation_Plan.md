# KeyRadar: First Open-Source Release Implementation Plan

Implementation update (2026-10-22): the development alpha is implemented in this repository, including the four sources, AWS/OpenAI checks, TUI, cases/reports and both skills. Local offline validation passed; live account and real-host skill gates remain pending. See [validation record](docs/VALIDATION.md) and [release notes](docs/RELEASE_NOTES.md). The sections below retain the intended release criteria.

**Date:** October 21, 2026

**Design:** [RFC v0.3](KeyRadar_Design_RFC.md)

**Target:** `v0.1.0-alpha`; original planning estimate of 16–24 developer-hours including integration and validation

**Current repository:** Development-alpha implementation with offline checks; live integration and real-host skill validation remain pending

## 1. Initial release scope

Ship `v0.1.0-alpha` with Vercel, Railway, GitHub secret metadata and explicit local `.env` sources; automated AWS IAM/OpenAI issuer evidence checks; a minimal TUI; and installable Claude Code/Codex skills. All remote operations are read-only. The shared core identifies exact current duplicates, preserves historical-key tasks and produces private cases plus shareable reports.

These are **required first-release scope**:

| Capability | Minimum shippable behavior |
|---|---|
| Vercel + local | Selected-scope inventory and exact current-value matching |
| Railway | Selected project/environment/service variables; reference and sealed-value uncertainty |
| GitHub | Repository and explicitly selected environment secret metadata; names never prove equality |
| Automated issuer checks | On-demand AWS IAM last-used and OpenAI project-key metadata, per-key errors/provenance and continued-use detection |
| TUI | Source selection, progress/coverage, credential checklist and issuer evidence/export; shared core |
| Claude Code + Codex skills | Installable report-only workflows, independent-terminal handoff and reviewed runbooks |

The demonstration must cross the whole product: a Vercel/Railway/local duplicate forms one material group, GitHub stays a name hint, an old missing credential stays open, an issuer check refreshes activity, and the same evidence appears in the TUI and shareable report consumed by each skill.

Automatic writes/revocation, full deployment enumeration, GitHub organization inheritance, generic scanner integration, encrypted state, background polling and additional issuers remain out of scope. Stripe/PostgreSQL retain manual evidence workflows.

The original 7–9-hour estimate is superseded. This is an aggressive one-night target, not a claim that 16–24 developer-hours fit into a solo evening. Shared contracts let independent work packages overlap when implementation capacity is available. If a required integration or safety gate is unfinished, record the release as incomplete. A developer preview can be labeled as such, but does not satisfy this full release scope.

## 2. Build sequence and checkpoints

The effort ranges below overlap in setup/testing; use 16–24 developer-hours as an overall planning estimate, not a promised completion time.

| Order / dependency | Work | Effort | Concrete exit condition |
|---|---|---|---|
| 1 | Core types, secret boundary, template, synthetic fixture, operation contracts | 2–3 h | Frozen metadata DTOs and fake adapters; demo proves exposure/identity/lifecycle separation |
| 2, after contracts | Local + Vercel sources | 2–3 h | Scope, plaintext/readability and partial failures tested |
| 2, after contracts | Railway + GitHub sources | 2–3 h | GraphQL error handling, metadata-only GitHub, sealed/reference uncertainty tested |
| 2, after contracts | AWS + OpenAI issuer adapters | 2–3 h | Separate audit authorization; exact selected-key observations; errors/nulls never imply inactivity or revocation |
| 3, after model | Case store, evidence entry, CLI/report commands | 2–3 h | Round-trip persistence, historical-task preservation, shareable projection and cleanup |
| 4, after core operations | Minimal Bubble Tea TUI | 1–2 h | Four usable views, cancellation/resizing, identical core behavior |
| 4, after report schema | Two skills, installation guides and reviewed issuer runbooks | 0.5–1 h | Both install and interpret a synthetic shareable report without crossing the credential boundary |
| 5, integrated build | Security/failure tests and controlled integration smokes | 3–4 h | Every required connector, issuer, TUI and skill gate has recorded evidence |
| 6 | README/support matrix, license, CI and release build | 0.5–1 h | Clean checkout builds; exact tested capabilities documented |

Keep the first competitor baseline bounded. A complete comparison and user interviews continue after release; do not claim a benchmark win without running it. Make authentication/test-account availability explicit at the beginning: Vercel, Railway, GitHub, an AWS audit context and OpenAI project-key metadata access. Missing account permissions must be reported as a validation blocker rather than replaced with a mock and called tested.

## 3. Repository layout and implementation choices

Start with a small number of packages. Split further only when a real dependency requires it.

```text
cmd/keyradar/main.go
internal/model/          # metadata-only case, observations, evidence and task enums
internal/scan/           # local, Vercel, Railway, GitHub adapters; transient material and equality
internal/issuer/         # AWS/OpenAI read-only evidence adapters; separate audit auth
internal/app/            # shared scan/check/record/export operations for CLI and TUI
internal/incident/       # declarative template evaluation and task generation
internal/casefile/       # schema validation, lock, atomic read/write, cleanup
internal/report/         # explicit report DTOs, JSON, Markdown, shareable projection
internal/cli/            # command parsing, hidden prompts, structured record workflow
internal/tui/            # Bubble Tea views over metadata-only app events
integrations/claude-code/keyradar/SKILL.md
integrations/codex/keyradar/SKILL.md
integrations/README.md   # tested installation paths/commands and independent-terminal flow
templates/vercel-apr-2026.json
runbooks/                # reviewed generic, Vercel/Railway, AWS, OpenAI, Stripe and PostgreSQL guidance
schema/case-v1.json
schema/report-v1.json
testdata/                # synthetic sources and redacted expected reports only
docs/benchmark.md
docs/provider-capabilities.md
.github/workflows/ci.yml
README.md
SECURITY.md
CONTRIBUTING.md
LICENSE
```

Use the standard library for HTTP, JSON and command dispatch; `golang.org/x/term` for hidden prompts, the official AWS SDK for Go v2 for AWS request signing/clients, and Bubble Tea for the TUI. Prefer small typed HTTP clients for the other providers. Verify and pin current module paths/APIs during implementation. Pin dependency versions and commit `go.sum`. Use an installed, supported Go release and declare the tested version in `go.mod` and CI rather than promising every version/platform.

Keep connector implementations and secret handling within `internal/scan` initially. That lets an unexported secret type remain inaccessible to model/report/state packages. Inject an HTTP transport and clock for tests. Production endpoint overrides must not be exposed through case/template input; test endpoints exist only in test construction.

A transient secret wrapper must refuse JSON/text marshaling and render a fixed marker through formatting methods. This is defense in depth: reporters should never receive it at all. Audit parser/HTTP errors too; a safe wrapper cannot sanitize a raw error that embeds the original input.

No hashing is required. Compare length-bucketed candidate values against group representatives using exact bytes. Begin with explicit limits: 50 selected files, 1 MiB per file, 64 KiB per parsed value, 8 MiB total raw material and 2,000 observations per run. Limit hits produce partial coverage and fixed reason codes. Tune after profiling, not by removing limits.

## 4. Work items and acceptance requirements

### A. Core model and rules

Implement the records in RFC section 6 as ordinary structs, merging closely related metadata structs if useful. Use random IDs, typed enums and an injected clock. No persistence type may contain a raw value field.

Minimum task codes:

- `identify_issuer`, `identify_historical_credential`, `review_history`
- `create_replacement`, `update_configuration`, `replace_or_retire_deployments`, `check_health`
- `review_old_key_activity`, `revoke_old_credential`, `confirm_invalidation`, `review_derived_access`
- `review_unchecked_scope`, `cleanup_tool_access`

Task status is `pending`, `attested`, `observed`, `blocked` or `accepted_exception`, with evidence references. `attested` and `observed` must not collapse into one verified state. Do not enforce a single linear sequence: emergency revocation can precede migration.

Generate candidate credentials conservatively from names/formats, but inventory every variable. Unclassified variables receive review coverage rather than being declared non-secret. Manual promotion is available in `record`. Keep equal material and issuer identity separate; matching passwords on unrelated databases must not produce one revocation target.

**Done when:** tests prove that name-only matches never become exact matches; case history persists; missing values do not compare equal; unknown history cannot produce exclusion; and updated configuration cannot complete deployment/revocation tasks.

### B. Local source

Accept repeated `--local-file` arguments. Do not recurse or load `.env` automatically from the current directory. Reject symlinks in the selected path and open safely against replacement races; restrict the first tested release to macOS/Linux if platform-safe file handling is not implemented elsewhere.

Document a small grammar: blank/comment lines, `KEY=value`, optional `export`, unquoted values and single-line quoted values with explicit parsing rules. Preserve resulting value bytes. Reject unsupported interpolation/command syntax and multiline constructs without echoing them. Duplicate keys are ambiguous: mark that file partial and exclude conflicting entries from automatic matching. A mature parser is acceptable only if its expansion and error behavior satisfy the contract.

Keep source file/line/key metadata private; never store the original assignment line. Test whitespace, quotes, CRLF, malformed syntax, empty values, unusual Unicode, duplicates, oversized inputs, symlinks and non-regular files. A parser error must not include a secret-bearing snippet.

### C. Vercel source

Read the current [project environment listing](https://vercel.com/docs/rest-api/projects/retrieve-the-environment-variables-of-a-project-by-id-or-name) and [single-value retrieval](https://vercel.com/docs/rest-api/projects/retrieve-the-decrypted-value-of-an-environment-variable-of-a-project-by-id) contracts before coding. Record the tested route/version and response fields in `docs/provider-capabilities.md`. Do not infer plaintext status from a nonempty `value` field.

Require explicit team/project and target-environment selection; personal-account support may be deferred. Validate identifiers and encode path/query components. List metadata for the selected project, select permitted locations locally, and read values only for the approved scope where the API permits. Explain any broader metadata enumeration required by the endpoint. Never enumerate every accessible team/project by default.

Normalize provider classes without assuming a dashboard label equals an API enum. Keep branch-specific preview and custom/shared configuration distinctions; report unsupported dimensions. Unknown types, references, encrypted payloads, masked responses, permission failures and nulls cannot enter the equality engine as raw credentials.

Use fixed HTTPS hosts, no cross-host redirects, finite timeouts and bounded retries for rate limits/transient errors. Respect pagination when the selected endpoint supplies it; do not invent pagination on endpoints that return a complete collection. Record any provider truncation/limits as incomplete. Allow tests to simulate a late failure across pages or per-variable reads.

Create a `ToolAccess` record before the first request and a `ScanRun` record even on failure. Prompt for the token from a terminal; fail closed without a TTY in this alpha. No token argument or automatic loading from Vercel CLI files. Include `KeyRadar/<version>` plus the random run ID in the User-Agent.

**Done when:** fake transport tests cover plaintext, write-only, encrypted/non-decrypted responses, unknown classes, wrong scope, permission denial, rate limits, malformed JSON, cancellation, later-operation failure and bounded responses. A permitted synthetic live value must match a local canary before live support is advertised.

### D. Case, evidence entry and reporting

Use one schema-versioned JSON case file in a dedicated directory. `--case` explicitly enables persistence. Restrict directory/file permissions; reject symlink destinations and unsafe existing ownership/permissions. Validate a case marker before cleanup. Use a single-writer lock and same-directory temporary file plus atomic rename; preserve the previous valid case on failure.

On rescan, append observations and maintain source-locator mappings. Preserve earlier credentials/tasks. Do not infer cross-run equality or value change from a matching path, name or `updatedAt`. Source absence during an incomplete scan cannot imply removal. Even a confirmed removed location cannot close an issuer task.

`record` provides a simple terminal menu and the TUI exposes the same application operations. Provide five actions: promote/add a credential (including historical), bind an issuer identifier, link a replacement, record a task fact, record an issuer activity observation. Closing a case records an operator disposition and explicit exceptions. Only typed bounded fields and enums; no raw HTTP/log import or unrestricted notes.

Manual facts use `source=operator_attestation`. Do not let the menu create `source=issuer_api`. Observation time and reported last-used time are distinct fields. A manually entered key ID is a human binding until independently verified. Null last-use, unknown interval or missing freshness must remain insufficient evidence.

Render JSON from a dedicated allowlist DTO and Markdown from that DTO. Private output retains escaped actionable locators. Shareable output replaces all external labels/IDs with generated aliases and emits only fixed vocabulary, timestamps, typed facts, counters and reviewed text. Do not copy arbitrary case strings into the shareable projection.

`clean` first shows pending tool-access obligations. It removes only its validated case files, without following symlinks. It cannot claim remote revocation or secure erasure. Pending obligations require either retaining the case or explicit `--forget`; show the cleanup information before forgetting it.

**Done when:** read/write/record/report round-trip tests preserve provenance; corrupted/oversized/newer-version cases fail safely; rescan cannot erase a historical task; shareable reports omit private metadata; cancellation cannot corrupt the previous case.

### E. Railway and GitHub sources

Railway takes an explicit project/environment/service tuple. Use fixed GraphQL queries with variables, never string interpolation from metadata. Read permitted values and reference information, with HTTP and GraphQL error handling. Do not infer that an omitted sealed value was absent; declare unknown enumeration coverage if names cannot be obtained. Keep service and shared/reference locations distinct. No staging, mutation or deployment endpoints. Validate token type/header/scoping against the current [Railway API documentation](https://docs.railway.com/integrations/api/manage-variables).

GitHub takes repeatable repository selectors and explicit repository-environment selectors. Implement repository-secret and environment-secret metadata listing, with pagination and minimal endpoint-specific read permissions. Map every returned secret to `write_only`; never request values or inject a workflow to reveal them. Repository and environment names with the same secret name remain separate locations. Organization-secret inheritance and workflow references are `not_checked`, with review tasks. Consult the [GitHub Actions secrets API](https://docs.github.com/en/rest/actions/secrets) and its linked environment endpoints for the tested API version and permissions.

Both adapters share the HTTP limits, audit journal, hidden authentication, cancellation and per-scope coverage rules of the Vercel adapter. Keep selected provider identities in the private case; opaque aliases in shareable reports.

**Done when:** Railway tests cover ordinary values, references, inaccessible/omitted sealed data and HTTP-200 GraphQL errors; GitHub tests cover pagination, repository/environment separation, forbidden/missing scopes and write-only semantics. Controlled live smokes for both are recorded. A four-source test groups only readable equal material and retains GitHub as a hint.

### F. Automated AWS and OpenAI issuer checks

Implement `keyradar issuer check --case PATH --credential ID --issuer aws|openai`, with repeatable credential IDs. Bind the target issuer/account/key locally first. Reject incompatible/unbound credential classes with typed per-key outcomes. A batch must retain successes when another key fails.

AWS: use `GetAccessKeyLastUsed` with separate audit authorization, an explicit key ID and the official SDK. Require the operator to choose an approved auth source: a named profile or transient credentials entered in the independent terminal. Do not silently traverse the default credential chain, invoke arbitrary credential helper commands, or use the potentially exposed key. Profile helpers require explicit local operator selection. Account identity checks are also audited; lack of ownership evidence remains visible. Scope support to IAM access keys, not STS session keys.

OpenAI: use the documented project-key retrieval/list surface with a separate audit credential that has the required authority. Restrict requests to selected project/key IDs; disclose required access rather than pretending an ordinary inference key is sufficient. Read nullable last-used metadata without generating model traffic or authenticating candidate secrets. Project key/account binding provenance remains distinct from API observation provenance. [Project key API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys)

Each result records `source=issuer_api`, fetched time, provider-reported activity time, selected scope, null/freshness semantics and coverage. It does not upgrade a human assertion that a local value corresponds to that issuer key. A missing key/404, permission failure, empty result or unknown delay is not proof of invalidation/inactivity. Compare repeated observations for advancing last-use; retain earlier evidence and conflicts. Use manual `record` for unsupported issuers. No polling loop, automatic quiet-window approval or revocation endpoint in the first release.

**Done when:** transport tests cover increasing activity, null/stale/out-of-order observations, unknown lag, 403/404, pagination where applicable, wrong account/project, rate limits, mixed success and cancellation. Controlled AWS/OpenAI reads succeed with separate audit credentials; outputs and logs contain no audit secrets. Fake-clock tests establish that silence alone cannot close retirement work.

### G. Minimal TUI

Implement `keyradar tui --case PATH`; bare `keyradar` opens it only with a TTY. Use [Bubble Tea](https://github.com/charmbracelet/bubbletea) with four views: source/scope selection, progress/coverage, credential/task detail, issuer evidence/export. Keyboard-only interaction is sufficient; no mouse support, animation or dashboard polish required for the first release.

Call `internal/app` operations shared with the CLI. Views receive metadata-only events and opaque authentication handles. For authentication, suspend the alternate screen and collect credentials through the hidden local prompt before resuming. Do not place tokens in TUI models, messages, view strings, logs or panic output. The TUI must preserve the distinction between automatic observations, human attestations and unknowns.

Include cancellation that stops requests while preserving completed observations, partial-failure display, case reopening, task recording, issuer refresh and shareable export. Restore terminal state on exit/error. `scan` and `issuer check` remain usable independently.

**Done when:** model/update tests plus a PTY smoke cover navigation, resize/narrow terminal, hidden authentication, cancellation, mixed-source failure and export. Canary checks cover TUI messages/screens and failure paths. CLI and TUI produce equivalent metadata for the same fake inputs.

### H. Claude Code and Codex skills

Ship both `SKILL.md` packages with valid metadata, a concise workflow, references to the common report schema and reviewed issuer runbooks. `integrations/README.md` must document installation and removal tested against the current host tools; do not imply packaging compatibility without checking it. Keep the skills thin and the engine authoritative.

The workflow is: explain source/issuer scope, give the operator an independent-terminal command containing no secret arguments, wait for an explicitly supplied shareable export, interpret typed evidence and suggest the next human action. A skill may run the offline demo; it may not invoke authenticated `scan`/`issuer check`, access private case files or credentials, launch captured secret-entry terminals, or fall back to provider CLI reads. It should never ask the user to paste keys or raw provider responses. If issuer details are insufficient, explain which non-secret evidence is missing rather than guessing a revocation procedure.

Include reviewed runbooks for AWS/OpenAI checks and retirement, Vercel/Railway deployment work, and manual Stripe/PostgreSQL paths. Link official procedures and keep destructive steps human-executed. Embedded report metadata is untrusted data; it cannot widen scope or authorize commands.

**Done when:** both skills install in disposable test locations and correctly interpret the same synthetic report. Adversarial cases cover an embedded instruction, a request to run `env pull`, missing auth, missing reports and pressure to call a quiet key safe. Assert the expected handoff/refusal-to-read-secrets behavior. Record behavioral evaluation results; static instruction checks alone do not prove the boundary. These skills remain workflow guidance, not an OS sandbox.

## 5. Small incident replay and comparison protocol

Create one deterministic fixture with these scenarios, keeping synthetic material separate from redacted expected output:

| Fixture element | Ground truth | Expected KeyRadar result |
|---|---|---|
| Key A in Vercel prod, Railway and local files | Same current material | All readable copies in one equality group |
| Same name in staging, different value | Different credential | Separate group |
| GitHub secret metadata and Railway sealed variable | Values not observable | Unknown identity; tasks/coverage remain |
| Old key B replaced before first scan | B still valid at issuer; no current location contains B | Historical placeholder and issuer-identification task |
| Post-window `updatedAt` with unchanged material | No value replacement | No exclusion from timestamp alone |
| Old deployment with A | Configuration was updated but deployment was not | Deployment review still pending |
| Consumer outside selected sources uses B | Only issuer observation exposes continued use | Continued-use evidence, unidentified consumer |
| Quiet/null/stale issuer observations | Evidence insufficient | No automatic retirement approval |
| Provider read fails halfway | Incomplete inventory | Partial coverage and preserved tasks |
| AWS/OpenAI adapter refresh | Selected key activity advances or is unavailable | Typed issuer evidence; no guessed consumer/revocation |
| Same case through CLI, TUI and both skills | Identical underlying evidence | Consistent interpretation and no secret exposure |

Use a synthetic window solely for time-rule tests, clearly labeled as such. The bundled real-incident template retains unknown intrusion bounds.

Compare against (1) the published GitGuardian workflow and (2) a pinned TruffleHog filesystem scan. Use synthetic data, record versions, selected environments and settings, and disable active verification in the TruffleHog comparison (`--no-verification`). TruffleHog documents that switch; it is not a redaction guarantee. Keep scanner output private. [TruffleHog documentation](https://github.com/trufflesecurity/trufflehog)

For each path record elapsed time, manual steps, credentials identified, missed/false matches, plaintext files created, unresolved locations, historical credentials retained and deployment/issuer work still visible. Include manual reconciliation time for all paths. Synthetic non-functional tokens cannot support a meaningful live-validity detection comparison; measure workflow bookkeeping separately from detector accuracy.

If GitGuardian requires account/network setup unavailable during validation, record that comparison as **not run**. A manual walkthrough is not a benchmark. The same applies to TruffleHog if not installed. Keep the worksheet and run it later rather than invent results.

## 6. Mandatory release gates

These are tests to implement and run, not completed validation.

| Gate | Required evidence |
|---|---|
| Output containment | Canary absent from stdout, stderr, JSON, Markdown, case/temp files and CLI failure output; inject secrets into error bodies and metadata too |
| Matching correctness | Exact equality only; empty/unreadable/placeholder values excluded; same-name different-value split; parser preserves documented semantics |
| Honest state | Historical tasks survive; no timestamp-based replacement; manual evidence never becomes API-verified; unknown scope never becomes absent |
| Partial operation | Tests for forbidden scope, later read/page failure, rate limit, cancellation and input/resource limits |
| Local scope | No shell evaluation, file traversal, symlink race or unsupported-file read |
| State safety | Restrictive permissions, schema rejection, single-writer behavior, atomic replacement, cleanup boundaries |
| End-to-end | Offline demo and scan/report/record/rescan workflow run from built binary; exit codes and JSON framing checked |
| Live sources | Controlled Vercel, Railway and GitHub smokes; selected local files; exact scope/readability recorded |
| Live issuers | AWS and OpenAI audit reads, per-key result provenance; null/denied/missing never imply quiet/revoked |
| TUI | Four working views, cancellation/terminal restoration, hidden auth, no values in UI events |
| Skills | Both install; interpret shareable output; adversarial handoff/boundary evaluations recorded |

Run `go test ./...`, `go test -race ./...` on a supported runner, `go vet ./...`, and a release build. Include bounded fuzz/property tests for parsing, equality and state invariants. Inspect canary-test failures without printing the leaked content itself. No live provider secrets in CI; use fake transports and synthetic fixtures.

### Controlled live smoke

The operator prepares dedicated Vercel/Railway scopes with synthetic readable duplicates and protected variables, plus GitHub repository/environment secrets. Scan explicit scopes and confirm equality only where values are observable; protected and unenumerable data remain unknown. Exercise denials with fake transports if controlled accounts cannot safely produce them.

For AWS/OpenAI, use controlled target keys and separate audit access. An actual issuer-issued test key is sensitive even if created for this test: it never enters fixtures, reports or CI. Read its metadata without using it as authentication for KeyRadar. Verify observed scope and null/last-used behavior. Do not block release waiting for a long quiet period; the release tests evidence collection, not a claim that the key has no consumers.

Open the resulting case in the TUI, refresh issuer observations, record a manual task and export a shareable report. Exercise each installed skill against that export and the malicious-metadata fixtures. Review cleanup obligations for every source/issuer token created for the test; revoke them manually as appropriate.

Record test date, platform, API route/version, permissions, provider classes, evidence freshness limitations, skill host versions and cleanup status. Never commit credentials, raw API responses or real account identifiers. These checks verify integration behavior, not the historical incident or absence of security defects. Missing live access or failed mandatory checks remain release blockers for the requested full scope.

## 7. Open-source release packaging

Before tagging:

- Retain the repository’s existing Apache-2.0 license and preserve dependency notices in distributed artifacts.
- Write a README with the one-sentence promise, source-build instructions, an offline demo, the four-source and two-issuer support matrix, TUI usage, both skill installation guides, and a prominent alpha limitations section.
- Explain the independent-terminal authentication flow, automated versus manual issuer evidence, unencrypted metadata state and the distinction between cleanup and revocation.
- Add `SECURITY.md` with a real private reporting channel, and issue templates that forbid raw `.env` files, API responses and private case files. Request shareable reports only.
- Add `.gitignore` rules for real `.env` files, local cases, build outputs and temporary artifacts; explicitly keep approved synthetic fixtures. Inspect staged content before release.
- Run CI with minimum workflow permissions and pinned actions. Publish builds only for tested platforms; include checksums. Describe signing/provenance only if actually configured.
- Include release notes listing implemented vs manual vs unsupported capabilities. No claims of full inventory, automated rotation or verified incident containment.

Suggested release description:

> KeyRadar is a local CLI/TUI for credential incident response across Vercel, Railway, GitHub secret metadata and local `.env` files. It tracks migration and historical unknowns, checks AWS/OpenAI issuer activity, and exports redacted reports for its Claude Code and Codex skills. It does not write to providers or revoke credentials.

Publishing a tagged release and contacting response-guide authors follow the validation gates. Pushing source changes is not evidence that those gates passed.

## 8. Follow-up work, in order

1. **Finish the baseline and user check.** Reproduce the comparison and measure reconciliation effort and clarity of next actions with incident responders.
2. **Deepen the shipped issuer checks.** Characterize reporting latency, add optional bounded polling and product-specific usage evidence, and evaluate additional issuers. Keep unknown freshness visible.
3. **Expand the shipped connectors.** GitHub organization-secret applicability and workflow references; deeper Railway shared/reference coverage; Vercel shared/custom-environment handling and deployment enumeration.
4. **Improve persistence and replacement verification.** Optional OS-keychain-backed metadata encryption and independent-process expected-value comparison. Do not retain old raw credentials or stable public fingerprints.
5. **Refine the shipped TUI and skills.** Usability, accessibility, more reviewed runbooks and continued adversarial evaluations. Preserve the independent-terminal/shareable-report boundary.

Stop expanding if existing workflows solve the same job just as well. Contributing a thin workflow/integration upstream remains a valid result.
