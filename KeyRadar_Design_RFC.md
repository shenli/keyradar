# KeyRadar: Credential Incident Response Across Platforms and Issuers

**Design RFC · Draft v0.3 · October 21, 2026**

**Status:** Design baseline with a development-alpha implementation; see [validation](docs/VALIDATION.md) for completed and pending gates

**Implementation:** Open source, local-first, Go; shared core with CLI, TUI and report-only agent skills

**First release:** `v0.1.0-alpha`, Vercel + Railway + GitHub metadata + local files; AWS/OpenAI issuer checks; TUI; Claude Code/Codex skills

**Build sequence:** [Implementation plan](KeyRadar_Implementation_Plan.md)

## 1. Product decision

KeyRadar helps a developer retire credentials after a suspected exposure. It collects evidence from two directions: **configuration sources identify known places to update; credential issuers provide evidence about the old credential's activity and revocation.** Neither direction alone proves that an incident is resolved.

The product promise is: **Find known copies, track replacement and deployment, and show the evidence still needed to retire each old credential.** It does not promise to find every copy, prove that no dormant consumer exists, or determine that an attacker never used a credential.

The target user is an individual developer or small team with credentials spread across deployment platforms, CI and local projects, without an existing secret inventory. Installation happens after an incident. There is no hosted account, telemetry, or required AI service.

The durable unit of work is an issuer credential, including a historical credential whose value is no longer accessible. Locations help plan migration. Issuer evidence helps assess continued use and establish invalidation. Availability risk and security containment remain separate outcomes.

### What changes from v0.1

| Decision | Revised design |
|---|---|
| Primary example | Replay the documented Vercel April 2026 incident; Railway ships as a secondary source, without implying a Railway breach. |
| Unit of rotation | A `Credential` represents one issued key/password generation; locations and deployments reference it with explicit evidence. |
| Historical exposure | Exposure attaches to an observation/version and incident rule, not just today's variable name or readability. |
| Completion | Separate migration, observed activity, issuer invalidation, and operator closure. |
| Issuer activity | Useful positive evidence of use; silence is conditional evidence, never proof of no consumers. |
| First release | Four source types, AWS/OpenAI issuer checks, direct in-memory matching, redacted reports, evidence recording, TUI and two agent skills. |
| Deliberate deferrals | Automatic writes/revocation, broader issuer coverage, complete deployment discovery, encrypted state and scanner integration. |

## 2. Review of the expert feedback

Accept the shift toward issuer credentials, the real incident fixture, deployment tracking, scan audit records, cleanup of tool-access tokens, and a separate interactive process for sensitive work.

Qualify three claims before implementation:

1. **Readable does not mean confirmed stolen.** An incident can justify treating a class of credentials as potentially exposed without proving every account or value was accessed. A user's API token can also have a different view from an attacker with internal access. Use the advisory's scope and evidence, not token capability as a universal exposure rule.
2. **`updatedAt` after an incident does not prove a new value.** It may describe a metadata edit, re-saving the same value, or moving an older credential. A newly issued credential and trustworthy version history can establish a post-window generation; a timestamp alone cannot. Today's write-only setting likewise does not establish historical protection.
3. **An unchanged `last-used` does not prove nobody uses the old key.** Delayed telemetry, unsupported endpoints, idle workloads, monthly jobs, cached sessions and an inactive attacker can all produce silence. Issuer evidence narrows uncertainty; it must not manufacture certainty or indefinitely delay containment.

The distinction matters: verified revocation can contain the old key even while an unknown consumer will later fail. Conversely, successful migration of every known application does not establish that the leaked key is invalid.

## 3. Verified incident and comparison baseline

Vercel's bulletin attributes the incident to a Context.ai compromise followed by access to internal systems and non-sensitive environment variables. It describes affected subsets of customers, recommends rotating potentially exposed non-sensitive variables, and warns that deleting projects/accounts is insufficient. The bulletin records closure on October 16, 2026. Provider incident closure does not establish that a particular user's third-party credentials have been revoked. [Vercel bulletin](https://vercel.com/kb/bulletin/vercel-april-2026-security-incident)

GitGuardian's April 20 response uses `vercel env pull` followed by `ggshield secret scan path .env.local`, then upstream rotation and deployment checks. This is the published baseline. A second benchmark substitutes TruffleHog; it is our proposed comparison, not a workflow attributed to that article. [GitGuardian response](https://blog.gitguardian.com/vercel-april-2026-incident-non-sensitive-environment-variables-need-investigation-too/)

The replay is synthetic and reproduces documented failure modes, not private forensic evidence. It must not invent a precise intrusion window. Public disclosure and incident-closure dates are not intrusion start/end times. Template window bounds remain unknown unless supported by an advisory or customer-specific evidence.

**Go/no-go hypothesis:** KeyRadar earns its place if the same controlled case takes less manual reconciliation and produces clearer outstanding work than the baseline. Measure duplicate grouping, historical-key retention, deployment obligations, partial coverage and issuer evidence. Do not claim better secret detection or unique market coverage without a measured comparison.

## 4. Release scope

| Capability | v0.1 alpha target | Subsequent releases |
|---|---|---|
| Source collection | Selected Vercel scopes; Railway project/environment/service variables; GitHub repository and selected environment secret metadata; explicitly named local `.env` files | GitHub organization-secret applicability, deeper shared-variable and deployment inventory, other formats/history |
| Credential detection | Every variable inventoried; conservative name/format hints; manual candidate promotion | Mature scanner integration after output/verification review |
| Correlation | Exact parsed-value equality within a run; name hints and Railway reference observations kept separate | Full reference resolution and credential-component parsing |
| Incident assessment | One bundled Vercel replay template; generic user-declared scope | Reviewed incident-template library |
| Rotation | Generated tasks; structured human attestations; automatic issuer evidence; old-key records survive rescans | More issuer adapters and stronger rescan verification |
| Issuer observation | On-demand AWS IAM last-used and OpenAI project-key metadata checks; manual evidence for Stripe/PostgreSQL and unsupported classes | Broader usage telemetry, more issuers and optional bounded polling |
| Deployments | Mandatory manual production/preview/rollback review tasks | Enumerated deployment targets and reference evidence |
| State | Opt-in, metadata-only local case JSON with restrictive permissions | Optional OS-keychain-backed encryption |
| Interfaces | CLI, minimal Bubble Tea TUI, Markdown/JSON, Claude Code and Codex report-only skills | Richer navigation, additional integrations |

**Non-goals:** Hosted monitoring, secret storage, full asset discovery, automatic secret validation, automatic writes/revocation, zero-downtime guarantees, incident forensics, or comprehensive secret-pattern detection. No generic plugin system, graph database, daemon, MCP server, or in-process LLM/API dependency in the alpha. The included skills interpret exported reports through the user's existing agent.

All capabilities in the first-release column are required release scope, not stretch goals. Ship working read-only connectors and issuer adapters, a functional TUI, and installable Claude Code/Codex skills. Fixtures alone do not satisfy live-support gates. GitHub coverage is metadata-only; Railway sealed variables and unresolved references remain explicitly limited. If a required gate is blocked, report the release as incomplete instead of silently moving that capability to a later milestone.

## 5. Evidence semantics

Never use one combined `SAFE`/`EXPOSED` status to answer multiple questions.

| Dimension | Values / interpretation |
|---|---|
| Exposure assessment | `potentially_exposed`, `confirmed_exposed`, `excluded_by_rule`, `unknown` |
| Identity evidence | `equal_value`, `issuer_id`, `provider_reference`, `operator_assertion`, `name_hint`, `unknown` |
| Location migration | Independent tasks: `config_updated`, `deployment_replaced_or_retired`, `health_checked` |
| Credential lifecycle | Independent facts: `replacement_created`, `revocation_requested`, `revocation_effective`; unknown remains explicit |
| Old-key activity | `usage_observed`, `no_usage_observed_in_window`, `insufficient_evidence`, `unsupported` |
| Case disposition | `open`, `closed_by_operator`; unresolved items and accepted availability risk remain visible |

All facts include source, observation time, effective time when known, evidence strength and scope. API observations and human attestations are different evidence strengths. A later contradiction reopens a task or records a conflict; it does not erase the prior event.

`excluded_by_rule` is narrowly scoped to one incident mechanism, credential generation and evidence set. It is not a global safety statement. Excluding one protected location cannot exclude another copy of the same credential that was exposed elsewhere.

Source coverage is separate: `complete`, `partial`, `permission_denied`, `rate_limited`, `unsupported`, `not_checked`, `failed`. Value readability is separate again: `readable`, `write_only`, `denied`, `unavailable`, `unknown_type`. An enumeration can complete while values remain write-only. “Not observed” is only valid within the named, successfully checked scope.

### Incident-rule contract

A template is reviewed declarative data, not executable instructions. Store its ID/version, official advisory URL, review date, provider, affected account/project criteria, historical readability classes, optional window bounds, excluded classes, evidence requirements and recommended task codes. Unknown bounds are explicit nulls. Templates cannot select endpoints, execute commands, or silently widen authorization.

| Evidence | Assessment |
|---|---|
| Credential-bearing value falls within a supported incident scope and affected historical class | `potentially_exposed` |
| Provider/customer-specific evidence identifies the affected credential/version | `confirmed_exposed`, at the granularity actually supported |
| Historical protection and the template's exclusion conditions are established | `excluded_by_rule` for that location/version and mechanism |
| Only current readability or a generic `updatedAt` is available | No historical exclusion; retain uncertainty and required review |
| Issuer evidence establishes a fresh generation issued after a known window | Current generation can be excluded from that window; prior-generation task remains |
| Scope or historical evidence is missing | `unknown`; generate a review task, not a clean result |

The Vercel replay applies the bulletin's response guidance conservatively. It does not turn every readable variable into proof of exfiltration. Contemporary Vercel documentation now calls the classes **Config** and **Secret**; legacy Sensitive variables continue as Secrets. Preserve original API types and normalize with an explicit, tested mapping. Unknown types must not default to readable or excluded. [Vercel variable classes](https://vercel.com/docs/environment-variables/sensitive-environment-variables)

## 6. Data model

Implement plain Go structs and typed enums; no graph database is needed. The following are conceptual records, not a frozen public API.

| Record | Required information |
|---|---|
| `Case` | Random ID, schema version, incident template/version, selected scope, timestamps, disposition |
| `Credential` | Random case-local ID; issuer/account/key-kind when known; optional issuer-native key ID; identity strength; historical/current/unknown generation; replacement links |
| `Location` | Random case-local ID; source-native locator; project/environment/branch/key; kind `configuration` or `deployment`; parent/reference if applicable |
| `Observation` | Run ID, location ID, observed time, readability, original provider type, provider timestamps, documented revision semantics; no secret value |
| `CredentialBinding` | Credential ID, observation ID, relation/evidence strength, optional run-local equality-group ID |
| `ExposureAssessment` | Credential or observation target, incident rule/version, status, reason code, evidence references, assessed time |
| `IssuerObservation` | Credential ID, issuer key/account binding, observation type, fetched time, reported last-used time, covered interval, freshness/granularity if known, permission/coverage result |
| `Task` | Credential/location target, action code, status, dependency IDs, supporting evidence IDs |
| `EvidenceEvent` | Random ID, target, action/fact code, source kind, observed/effective time, typed evidence fields; append-only through the application |
| `ScanRun` | Start/end UTC, tool/template versions, source outcomes, configured limits, selected scope, non-secret auth-session ID, request counts and safe request IDs |
| `ToolAccess` | Random auth-session ID, provider, operator alias, provider token ID if safely available, expiry/permission description, creation-for-case flag, cleanup status; never the token |

### Identity and historical credentials

One `Credential` denotes one revocable issuer object/generation, not a variable name or an entire application. Rotation creates a new credential and a `replaces` relation. A shared old key may be replaced by multiple scoped keys; model replacement links as a list.

Exact equality establishes shared material in the current run. It does not necessarily establish one issuer object: identical passwords on two unrelated databases are two revocation targets. Unknown issuer context stays unknown. A key prefix/suffix is a display or lookup hint, not a unique identifier; even issuer-native IDs need account and credential-type context.

Create a historical placeholder when an incident may concern an earlier generation but its raw value or issuer ID is missing. Its location set may be empty. The task is “identify and invalidate the prior credential,” not “recover its plaintext.” Do not silently bind it to the current value or assume there was exactly one historical generation.

Keep a placeholder/open review even for an apparently stable current variable when history is unavailable: an earlier value might have been removed before the first scan. Users can also add historical credentials from issuer inventories or incident notices.

### Matching and rescans

Use direct in-memory byte comparison for the small alpha inventory; no HMAC/fingerprint subsystem. Parse according to a documented `.env` grammar, then compare the resulting value without additional trimming, case folding or URL normalization. Exclude empty values from credential groups. Do not persist raw values, encoded equivalents, or value-derived hashes.

The alpha compares whole variable values. A password embedded in two different connection strings, or a key embedded in JSON/base64, may not match its standalone copy. Report this limitation explicitly; credential-component extraction is later work and must retain issuer/account context.

Run-local equality groups expire with the scan. Case IDs and location IDs persist as random metadata identifiers. Locate a prior location using source-native IDs and complete scope, never by variable name alone. Preserve distinct production, preview, development, branch and custom-environment locations.

**Without retained secret material, a rescan cannot generally prove that yesterday's value changed.** An unchanged location ID or a later timestamp is not value equality/difference evidence. Across runs, bind credentials using an authenticated issuer identifier or an explicit operator assertion, with that strength displayed. Otherwise create an unresolved binding and preserve the old task. In-run equality still identifies current duplicates.

A later optional mode may compare an operator-supplied expected replacement in the independent process. It is not required for the first release. The alpha promises evidence refresh, not automatic verification of every replacement.

## 7. Issuer activity and retirement

Issuer activity answers “was this key observed being used?” It cannot identify every consumer from a timestamp, establish that usage was legitimate, or prove no dormant consumer remains.

### Capability research, checked October 21, 2026

These are documentation findings, not live-account validation. Each shipping adapter must establish its permissions, account/key binding, supported credential classes, null semantics, retention, clock/granularity behavior and reporting delay before claiming usable coverage.

| Issuer/type | Documented evidence | Product decision |
|---|---|---|
| AWS IAM access key | `GetAccessKeyLastUsed` accepts a key ID and returns last-use information, service and region. Null/N/A has multiple meanings. [API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html), [field semantics](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKeyLastUsed.html) | Required for the first release; separate audit authorization with `iam:GetAccessKeyLastUsed`. Do not authenticate with the suspected key. |
| AWS credential report | Report regeneration is limited to four-hour intervals; last-used fields coalesce uses in 15-minute spans. [Report documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html) | A cached report is not a real-time stream. Do not apply these timings to a different endpoint without evidence. |
| OpenAI project key | Project-key model includes `id` and nullable `last_used_at`. [Project API keys](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys) | Required for the first release: retrieve selected project-key metadata using separate authorized audit access. Test permissions; record unknown latency explicitly. Unknown/null is not inactivity. |
| OpenAI usage | Completions usage supports key filters/grouping and time buckets. [Usage API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/completions) | Supplemental product-specific usage evidence; not a universal authentication log. Usage aggregation is deferred; disclose and minimize the audit authority needed for the shipping project-key metadata adapter. |
| Stripe API key | Dashboard key management and request-log inspection are documented. [Stripe keys](https://docs.stripe.com/keys) | Manual evidence first. This review did not establish a supported public generic last-used API; do not call it nonexistent or scrape the dashboard. |
| PostgreSQL role/password | `pg_stat_activity` exposes current backend activity and usernames. [PostgreSQL monitoring](https://www.postgresql.org/docs/current/monitoring-stats.html) | Manual runbook: consider a replacement role, review privileges/pools/sessions. A connection snapshot is not historical per-password usage. |
| Signing/webhook secrets, offline credentials | Usage may occur outside the issuer's visibility | Use class-specific procedures. No universal last-used gate. |

### Required automated checks

`issuer check` operates on explicitly selected case credentials with issuer/account/key identifiers. It performs bounded read-only requests once, appends `IssuerObservation` records and returns per-key coverage. It does not run a daemon, try candidate keys, approve revocation or modify issuer resources.

For AWS, use the official Go SDK and separately authorized audit credentials to call `GetAccessKeyLastUsed` for an IAM access key ID. Confirm the selected audit account through the approved authentication context; resolve ownership where permissions permit. Preserve the provenance of an operator-supplied key-to-credential mapping: a successful lookup alone does not prove it matches a configuration value. Temporary STS credentials are outside this adapter's key-class coverage.

For OpenAI, retrieve metadata for the selected organization/project/key through the documented project-key API. Keep issuer-returned key ID, scope and nullable last-used separate from the operator's binding to a local credential. Do not identify keys from a prefix/suffix alone. No model calls or candidate-key authentication are needed.

Both adapters record fetched time, reported activity time, source, scope and errors. Missing permissions, missing keys, null activity, unknown reporting lag and incomplete results remain explicit. A missing key/404 is not proof of revocation. Only an explicit documented issuer state may establish invalidation; otherwise retain the human task. Repeated checks can flag advancing last-use while the quiet-window conclusion remains insufficient if freshness/coverage is unknown.

### Observation policy

The alpha automatically collects AWS/OpenAI observations on explicit request and accepts manual observations for other issuers; it does not automatically declare a quiet period sufficient. A future evaluator may mark **ready for human review** only when all of these hold:

1. The exact old issuer key/account is identified and known migration/health tasks are resolved or explicitly accepted.
2. Relevant telemetry coverage and freshness are understood; partial responses and unknown lag block an automated quiet-window conclusion.
3. The observed window spans the declared workload cadence, including scheduled jobs, with reporting delay and clock uncertainty accounted for. No universal default such as “24 hours is safe.”
4. No old-key use is observed after migration within that covered window. Advancing activity triggers investigation; it does not by itself distinguish an attacker from a forgotten consumer.
5. The operator makes a time-bounded risk decision. Waiting for a slow workload must not leave an exposed key usable indefinitely; exercising the workload or accepting a controlled interruption can be preferable.

`no_usage_observed_in_window` always carries its interval and limitations. It never changes a write-only location's identity evidence to `equal_value`. A consumer outside authorized sources can generate issuer activity, but that signal does not automatically reveal which consumer it was.

### Revocation and closure

Suspected active abuse or issuer instructions can require immediate containment before migration completes. Do not wait for activity telemetry in that path. KeyRadar records the decision; the operator performs changes through the issuer.

For ordinary guided migration: create replacement credentials; update known locations; replace/retire deployments; check health; review available issuer evidence; revoke the old credential; then record evidence of effective invalidation and check for authentication failures. A revoke request, a dashboard attestation, and an issuer-observed revoked state are distinct evidence.

Derived access may outlive a parent key. Include a class-specific task to review sessions, tokens or other access minted before revocation; AWS documents separate role-session revocation. [AWS session revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)

Show separate summaries such as `known migration: 3/4`, `old-key invalidation: operator-attested`, `activity: insufficient evidence`, `unresolved history: 1`. Case closure is operator-recorded and preserves exceptions. It never prints “all credentials safe.”

## 8. Deployment obligations

Vercel environment changes apply to new deployments, not previous deployments. Branch-specific preview values can override generic preview values, and a default `env pull` targets development. These distinctions must appear in scope and benchmark records. [Vercel environments](https://vercel.com/docs/environment-variables)

Every affected Vercel credential gets tasks to update the relevant configuration, deploy the replacement, verify active routing and application health, and review old production/preview deployments, rollback targets, scheduled work and other still-invocable endpoints. Merely deploying a new production version does not complete the old-deployment task.

Tonight these are explicit manual tasks, with deployment coverage marked `not_checked`. Later, collect deployment metadata and model known deployments as locations. Infer that a deployment may contain an old credential only with stated evidence; do not claim a configuration-to-runtime binding from creation time alone. Avoid downloading build logs or artifacts to recover secrets.

Retiring a deployment addresses a consumer. It does not revoke the issuer credential. Issuer silence is useful additional evidence, not a replacement for deployment review.

## 9. Architecture and connector contract

The CLI runs one local Go process. Source adapters pass observations and transient raw material to an internal collector. Matching and incident assessment produce a metadata-only case model. Task generation and report rendering consume only that model. The AWS and OpenAI issuer adapters contribute evidence to the same model through separate capability-limited clients. CLI and TUI invoke identical application operations; the TUI never implements its own matching or retirement rules.

Keep the secret-bearing type unexported to reporting/state packages. It must refuse serialization and print only a constant redaction marker if formatted. Report DTOs are constructed from an allowlist, never by serializing connector responses and deleting a few fields afterward.

Use small connector interfaces for scope validation, location listing and permitted reads. Each operation returns items **and** a coverage result, including errors on later pages. Finish supported selected scopes even if another fails. A 403 is not an empty list; a truncated scan is not complete.

Vercel implementation must validate metadata and permitted plaintext retrieval against the documented list and single-value endpoints using a controlled synthetic project. An encrypted payload, masked placeholder, or missing value must never enter the equality engine as plaintext. Do not silently fall back to `vercel env pull` or bypass Secret restrictions. [Vercel list endpoint](https://vercel.com/docs/rest-api/projects/retrieve-the-environment-variables-of-a-project-by-id-or-name), [single-value endpoint](https://vercel.com/docs/rest-api/projects/retrieve-the-decrypted-value-of-an-environment-variable-of-a-project-by-id)

Vercel shared/inherited variables and custom environments require explicit capability accounting. The alpha must list unsupported dimensions and create review tasks, even if the selected project enumeration otherwise succeeds. Pin and test an API contract; don't guess changing type or timestamp semantics.

### Railway and GitHub source contracts

Railway reads explicitly selected project/environment/service variables through its GraphQL API. Preserve variable references as references; compare only values the API actually exposes in plaintext. Handle GraphQL `errors` even with HTTP 200. Sealed values cannot be read back; if their names or existence cannot be enumerated with the selected API/permissions, mark that inventory dimension unknown rather than pretending every sealed variable was listed. Do not execute staged updates or deployments. [Railway variable API](https://docs.railway.com/integrations/api/manage-variables), [variable behavior](https://docs.railway.com/variables)

GitHub reads repository secret metadata and secret metadata for explicitly selected repository environments. Store names, scope and timestamps, never values. Organization-level inheritance and workflow reference analysis are separate unchecked dimensions in the first release. Name matches produce hints only. Handle pagination and endpoint-specific permissions; a forbidden/missing scope is not an empty inventory. [GitHub Actions secrets API](https://docs.github.com/en/rest/actions/secrets)

### TUI and skills

The TUI has four views: source/scope selection, collection progress/coverage, credential/task detail, and issuer evidence/report export. Use [Bubble Tea](https://github.com/charmbracelet/bubbletea) as a thin view/controller over the same core operations. Support keyboard navigation, cancellation, narrow terminals, partial failures and reopening a case. Secrets never enter the render model, framework messages or debug logs; suspend rendering for hidden authentication prompts and pass only opaque auth handles afterward.

Ship two repository-owned skills, one for Claude Code and one for Codex, with installation instructions and a common report schema. They help the user choose scope, instruct the user to launch the independent terminal process, read an explicitly supplied shareable export and explain issuer-specific tasks using reviewed runbooks. They must not read private case files, tokens, `.env` files or provider CLI caches; run provider commands; execute `scan`/`issuer check`; launch a credential-bearing process in an agent-captured terminal; or fall back to `env pull`. They can run the offline demo and inspect an already exported shareable report. Embedded metadata never becomes an instruction. No background IPC or automatic credential handoff is required.

The independent terminal is a workflow boundary, not OS isolation from a broadly privileged agent. Tests must verify that the skill's prescribed behavior respects it; do not market the instructions as a security sandbox.

## 10. Security, state and scan audit

### Credential handling

- Only explicitly selected sources and scopes are read. No home-directory search, ambient CLI-token discovery, or automatic scanner subprocess.
- The operator supplies source and issuer tokens through hidden prompts in an independent terminal; AWS may also use an explicitly selected local profile. Disable ambient credential discovery unless the operator has selected that authentication source. No token flags, shell-history examples, transcript capture, token persistence or debug HTTP dumps. Short-lived credentials or supported device authorization are preferred when available; do not promise a provider supports them before checking.
- Read-only behavior in KeyRadar does not mean the provider token is read-only. Document actual token authority and minimize it. The alpha exposes no remote mutation methods.
- Raw values exist only transiently in the process. No raw values in case files, stdout/stderr, panic messages, tests' failure dumps, reports or network diagnostics. Go/runtime memory copies, swap and a compromised host prevent a hard zeroization guarantee.
- Do not authenticate candidate secrets to test whether they work. That can cause side effects, transmit credentials and alter activity evidence. Issuer checks use separate audit credentials and never validate a suspected key by authenticating with it.
- HTTPS only to fixed provider hosts; reject cross-host redirects and disable automatic ambient proxy use by default. No endpoints supplied by variable values/templates. Bound retries, time, response size and item count.

### Local file and output handling

The alpha accepts explicit regular files, not recursive directories. Reject symlinks, non-regular files and oversized inputs; use no-follow/open-then-validate handling appropriate to supported platforms, not a check-then-open path vulnerable to replacement. No shell evaluation, variable expansion, command substitution or sourcing `.env` files. Unsupported syntax becomes a scoped parse warning without echoing content.

Metadata is untrusted too. Escape control characters, ANSI sequences, Markdown links/HTML and terminal output; cap field lengths. Do not export provider comments, arbitrary error bodies or unrestricted operator notes. Mask known secret material if it appears in metadata, but do not claim this detects every possible secret embedded in a name.

The operator report may retain sanitized names/paths to make tasks actionable and remains private. `--shareable` replaces external names, paths, issuer IDs, request IDs and token aliases with opaque labels, retaining only typed facts, counts and reviewed runbook text. It is the only output intended for agent context or public issues. Redaction is not complete anonymization or a hard defense against a broadly privileged agent.

### State and cleanup

By default, scans keep state in memory and emit a report. `--case PATH` explicitly opts into metadata persistence: a private directory (`0700`) and atomic JSON files (`0600`), outside the repository in examples. No plaintext secret material or fingerprints are stored. **Alpha case metadata is not encrypted.** This is an explicit reduction from the original RFC so keychain integration does not block a small release. Document filesystem/backups exposure; encryption is a later feature, not a current claim.

The case stores random IDs, source locators, timestamps, coverage, evidence and tasks. Validate schema/enums/references on load; reject oversized or unknown-version files. Keep previous scan observations and tasks. Use a simple single-writer lock and atomic replacement, not a database. Application events are not tamper-proof audit evidence; local owners can edit the file.

`clean --case PATH` shows the tool-access cleanup list before local deletion and asks the operator to revoke tokens created for the case, or review continued retention of reused tokens. It cannot revoke remotely. Deleting local files neither revokes tokens nor securely erases filesystem snapshots/backups. Never delete source files, a generic directory, or the only cleanup record without showing pending token obligations; explicit `--forget` may discard the case with that limitation acknowledged.

### Scan audit footprint

Record scan start/end UTC, scopes, auth-session alias/non-secret provider token ID if available, tool version, request counts, safe request IDs, and retries. Use a recognizable User-Agent with a random run ID. Log no authentication headers, token fragments or response bodies. Reports explain that provider reads may appear in access logs; the local journal helps correlate legitimate scan activity but cannot prove which requests were legitimate. Shareable output omits these infrastructure identifiers.

## 11. CLI and human workflow

All commands are proposed. No command below is an implementation claim.

```sh
# Offline, synthetic demonstration; no token or provider calls.
keyradar demo --scenario vercel-apr-2026 --format markdown

# Operator runs this in an independent terminal; token is prompted invisibly.
# Repeated flags select exact scopes and files. No secret-valued arguments.
keyradar scan --incident vercel-apr-2026 \
  --vercel-team team_example --vercel-project prj_example \
  --environment production --environment preview \
  --local-file ./api/.env --local-file ./worker/.env \
  --case "$HOME/.local/state/keyradar/cases/example"

# Additional sources use explicit repeatable selectors (all identifiers are examples).
keyradar scan --incident vercel-apr-2026 \
  --railway-project project_example --railway-environment env_example \
  --railway-service service_example --github-repo owner/repo \
  --github-environment owner/repo:production --local-file ./api/.env \
  --case "$HOME/.local/state/keyradar/cases/secondary-example"

# Bind exact issuer identifiers locally first; audit authentication stays in this terminal.
keyradar issuer check --case "$HOME/.local/state/keyradar/cases/example" \
  --credential C1 --issuer aws --aws-profile keyradar-audit
keyradar issuer check --case "$HOME/.local/state/keyradar/cases/example" \
  --credential C3 --issuer openai
keyradar tui --case "$HOME/.local/state/keyradar/cases/example"

# Structured, guided local entry: tasks, issuer observations, historical keys.
keyradar record --case "$HOME/.local/state/keyradar/cases/example"

keyradar report --case "$HOME/.local/state/keyradar/cases/example" --format markdown
keyradar report --case "$HOME/.local/state/keyradar/cases/example" --format json --shareable

# Re-run scan with the same case and explicit scope flags to append evidence.
# The command validates the scope against the case; it never expands it silently.
keyradar clean --case "$HOME/.local/state/keyradar/cases/example"
```

Bare `keyradar` opens the TUI when attached to a terminal; without a TTY it prints help. `keyradar tui` explicitly opens the same interface. `record` uses fixed action codes and structured fields, not shell commands or free-form secret-bearing notes. It can create a historical placeholder, attach an issuer identifier through a local prompt, link a replacement, or attest a checklist action. Human-entered facts always remain labeled as such. Manual issuer observations include the exact key binding, observation time, covered interval when known, and source kind.

Every report includes selected scope, actual coverage, current observations, historical unknowns, credential groups, migration tasks, issuer evidence, tool-token cleanup, and the next action for each open item. Use independent counters, not a misleading overall rotation percentage. JSON has a `schema_version` and stable enums.

Command exit codes: `0` means the command succeeded with complete requested collection (not incident resolution); `2` means a usable partial report; `1` means no usable result or an invalid request. Unsupported dimensions remain visible even when intentionally excluded from requested collection. Diagnostics go to stderr as fixed messages; stdout remains valid report data.

Example summary, entirely synthetic:

```text
Case: Vercel incident replay                 Scan coverage: PARTIAL
Selected: 1 project, 2 environments, 2 local files
Deployment inventory: NOT CHECKED            Historical values: UNKNOWN

C1  issuer key unresolved   3 equal current copies   migration 0/3
C2  historical placeholder  0 current locations      identify old key
C3  issuer key identified   manual use observation  investigate continued use

Old-key invalidation: 0 issuer-observed; 0 operator-attested
Tool-access cleanup: 1 token to review
Next: identify C2 at its issuer; review old deployments; update C1 copies.
```

## 12. Acceptance fixtures and release gates

Fixtures use synthetic, non-functional canaries and a fake clock. The incident replay does not query actual affected accounts. A live smoke test, separately authorized by its operator, uses a dedicated project with synthetic variables.

| Case | Required result |
|---|---|
| Same value in Vercel and two local files | One current equality group, three locations, no value or fingerprint exported |
| Same variable name, different prod/staging values | Separate groups and migration work |
| Railway sealed variable or GitHub secret metadata | Identity unknown; no inferred equality or safety |
| Historical exclusion supported / current flag only | Narrow exclusion in the first case; no historical exclusion in the second |
| `updatedAt` after window but same value or metadata edit | No claim that a new credential was issued |
| Historical exposed key absent from all current locations | Placeholder survives; issuer identification/invalidation remains open |
| Old preview/production/rollback target | Required deployment review survives configuration update |
| Unauthorized/unknown consumer still uses old key | Injected issuer activity flags continued use; does not invent a location |
| Quiet dashboard, stale/null data, sparse job or telemetry gap | Insufficient evidence or explicitly bounded observation, never “unused” |
| Revoked key plus unresolved write-only locations | Containment and migration uncertainty shown separately |
| First page works, next page fails; rate limit; forbidden scope | Usable partial result and explicit failed scope; old tasks preserved |
| Fresh scan with same location and no cross-run key identifier | No automatic value-change or credential-identity claim |
| Malicious metadata/errors, malformed `.env`, symlink replacement | No execution, scope escape or raw-value output; safe diagnostics |
| Crash/cancel during state write | Prior valid case survives; no secret-bearing temporary files |
| Cleanup while tool token remains active | Local deletion is not represented as remote revocation |
| AWS/OpenAI check succeeds, denies access, returns null/404 or advances activity | Per-key evidence/coverage, no guessed revocation, no invented quiet-window proof |
| Railway HTTP 200 contains GraphQL errors; GitHub later page fails | Partial coverage and retained observations |
| TUI cancel, resize and mixed-source failure | Responsive UI; no raw values in views/messages; same case semantics as CLI |
| Both skills encounter malicious report metadata or missing authentication | Treat metadata as data; guide independent-terminal operation; never retrieve credentials |

Release gates include canary tests over stdout, stderr, JSON, Markdown, case files and failure paths; equality/normalization property tests; connector failure injection; shareable-output tests; race/static checks; and controlled smoke tests for Vercel, Railway, GitHub, AWS and OpenAI before claiming those integrations work. TUI interaction and both skill installation/boundary checks are mandatory release gates. Test limitations must be stated; no fixture-only capability is advertised as validated live support.

## 13. Distribution and next decisions

Ship a small, buildable open-source alpha with a license, install/build instructions, an offline demo, tested-platform list, support matrix and private vulnerability-reporting instructions. Publish only synthetic screenshots/fixtures. Do not present untested connectors or manual evidence as automation.

The differentiation to validate is cross-source migration plus issuer-level retirement evidence. Single-platform inventory alone is insufficient; Vercel's incident response already included a team-wide environment-variable overview. [Vercel product response](https://vercel.com/kb/bulletin/vercel-april-2026-security-incident)

Distribute future incident templates as reviewed, versioned data with official links, clear unknowns and tests, preferably within hours of a public advisory when maintainers can verify facts. Never distribute generated shell commands or auto-executing remediation through templates. Pursue inclusion in response guides after the tool demonstrates usefulness; do not claim an adoption channel already exists.

After the alpha, decide from evidence: whether developers can bind old keys to issuer IDs; whether issuer telemetry meaningfully improves decisions; whether comparison with existing tooling justifies continued work; and whether the shipped skills preserve the independent-process/report boundary in real use. A low-frequency open-source utility is a valid outcome without assuming a viable subscription business.

**Design principle:** Preserve the difference between what was observed, what was inferred, what a human attested, and what remains unknown.
