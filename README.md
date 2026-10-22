# KeyRadar

Find known credential copies, track migration, and collect the evidence needed to retire an old key after an incident.

KeyRadar is an open-source, local-first Go CLI/TUI. It inventories selected Vercel and Railway variables, GitHub Actions secret metadata, and local `.env` files. It can read AWS IAM/OpenAI key activity through separate audit authorization and export shareable reports for its Claude Code and Codex skills. It never writes to providers or revokes credentials.

**Development alpha:** automated tests use synthetic values and mocked provider responses. Live provider/account validation and real-host skill evaluations have not been performed. Do not treat this as a production-vetted incident-response tool or a completed release gate. See [validation status](docs/VALIDATION.md).

[Quickstart](#build-and-try-it-offline) · [User guide](#your-first-session) · [Support matrix](#supported-scope) · [Contributing](CONTRIBUTING.md)

## Build and try it offline

Requires Go 1.26+, macOS or Linux. No provider account is needed for the demo. From a checkout of this repository:

```sh
go build -trimpath -o bin/keyradar ./cmd/keyradar
./bin/keyradar demo --format markdown --shareable
./bin/keyradar tui
```

The TUI opens with **Choose sources to scan** selected. Press Enter to start, use ↑↓ to select a source, and enter one field at a time. Esc goes back and preserves earlier fields. After adding sources, choose **Scan selected sources** or **Add another source**. Select **Try the offline demo** to explore without an account.

Results guide you through Coverage → Findings → Next actions. Use Enter to continue, Esc to go back, Tab to switch sections, and PgUp/PgDn to scroll long results. The input stays beside the current step, even in a large terminal. Optional commands such as `/add`, `/demo`, `/scan` and `/quit` still work. Authentication uses separate hidden prompts. The demo intentionally reports partial coverage and exits with code **2** in CLI mode.

## Your first session

Start with **Try the offline demo** if you want to learn the interface. It uses synthetic data and makes no provider requests. To inspect your own sources, open KeyRadar in your own terminal. Choose a case directory when you want to save progress:

```sh
./bin/keyradar tui --incident custom \
  --case "$HOME/.local/state/keyradar/cases/first-review"
```

Use `--incident vercel-apr-2026` for that incident's guidance. The default is the Vercel template; use `custom` for a general inventory. KeyRadar creates a new private case directory for you. Reopen the same command to resume; without `--case`, the session lives only in memory.

### 1. Choose what to inspect

**Choose sources to scan** is selected when you start. Press **Enter**, choose a source with **↑↓**, and press **Enter** again. Fill in one field at a time; **Esc** returns to the previous field so you can correct it.

| Source | What to enter | Example shape (not real identifiers) |
|---|---|---|
| Local `.env` file | One explicit file path; spaces and `~/` are supported | `./api/.env` |
| Vercel | Team ID, project ID, then `production`, `preview` or `development` | `team_example`, `prj_example`, `production` |
| Railway | Project ID, environment ID and service ID; use identifiers rather than display names | IDs copied from the selected project's settings |
| GitHub Actions | `owner/repository`, then an optional environment name | `owner/repo`; leave environment blank for repository secrets |

For a first scan, a single local file is enough. Use **Add another source** to select more locations, or **Remove a source** to correct a selection before scanning. Adding a source does not read its values. Once a case has a scan, its scope is fixed; start a new case to change it.

These fields are for paths and identifiers. Provider tokens are requested separately when you choose **Scan selected sources**. Hidden token entry does not echo characters. Paste only the token requested for that provider, then press Enter. Local-only scans do not require a token. The TUI accepts Railway account tokens; use the CLI's `--railway-project-token` option for a Railway project token.

### 2. Scan and read the result

Review the selected locations, choose **Scan selected sources**, and press Enter. The result opens in **Coverage**. Check failures and unchecked areas before moving on: a successful read of one scope does not mean the rest of the platform was inspected.

Press Enter on **Review findings**, then on **Review next actions** to continue:

| Screen | What to look for |
|---|---|
| Coverage | Which selected sources were read, denied, incomplete or not checked |
| Findings | Known credential groups, historical credentials and outstanding tasks |
| Next actions | Record rotation progress, collect issuer activity, or export a report |

A GitHub secret is write-only and stays unknown for value identity. A credential with zero current locations can still need retirement. Updating configuration does not update old deployments or revoke the old key. Unchanged or missing issuer activity does not establish that a key is safe.

### 3. Record progress and check an issuer

Choose **Record rotation progress** to open the structured text prompts. The TUI temporarily leaves its full-screen view for these prompts and for authentication; it returns when the operation finishes.

Use `bind` to attach an issuer account/project/key ID to a credential before choosing **Check issuer activity**. Enter issuer-native identifiers, never a secret value. AWS and OpenAI checks require separate audit authorization. Choose `task` to attest a completed step, `historical` for an old credential that no longer appears in configuration, or `cleanup` to record removal of a tool token.

Use the full IDs in the private report or TUI, such as `cred-…` and `task-…`. If a line is truncated, open the private report in your own terminal:

```sh
./bin/keyradar report --case "$HOME/.local/state/keyradar/cases/first-review"
```

The tool records evidence and your attestations. You perform configuration updates, deployment changes and revocation through the relevant provider.

### 4. Export and finish

Choose **Export a shareable report** and enter a new output path. Existing files are refused. Supply only this shareable export to an agent or issue report; the private case and private report contain account and source identifiers.

With `--case`, completed operations save automatically. Exit with **Ctrl+C** or `/quit` followed by Enter, then reopen the same case to resume. Review tool-token cleanup before deleting local case state; local deletion does not revoke remote credentials.

### Keyboard reference

| Key | Action |
|---|---|
| Enter | Choose the highlighted action, accept a field, or run a typed command |
| ↑ / ↓ | Select an action or source |
| Esc | Go back; in a form, return to the previous field |
| Tab / Shift+Tab | Switch result sections after a scan |
| PgUp / PgDn | Scroll long result lists |
| Left / Right, Home / End | Move the input cursor |
| Backspace / Delete | Edit input |
| Ctrl+U | Clear the current input |
| Ctrl+C | Exit, or cancel collection while retaining completed observations |
| `/help` + Enter | Show optional commands |

Use a terminal at least 35 columns × 14 rows; 100 × 24 or larger gives fields more breathing room. Terminal font size is controlled by your terminal application. If you rebuild while KeyRadar is open, exit and relaunch it to load the new binary.

### Common questions

- **Why does the demo exit with code 2?** It deliberately includes partial and unchecked coverage. Code 2 means usable partial evidence, not a crash.
- **Why is an unreadable secret unknown?** Its name or presence does not establish its value, exposure history or issuer identity.
- **Why is a path rejected?** Local files and case paths cannot traverse symlinks. On macOS, `/tmp` and `/var` can be aliases; use the real path, such as `/private/tmp`, or a non-symlink path under your home directory.
- **Why is a case locked?** Another writer may have it open. Close that process first. After a crash, remove only the case directory's stale `.lock` once you have confirmed no writer is running.
- **Why did the interface switch to text prompts?** Authentication, recording, issuer checks and export use dedicated terminal prompts. Follow the prompt labels; do not paste tokens into the main command field.

## Supported scope

| Source / interface | Implemented behavior | Limits |
|---|---|---|
| Local | Explicit `.env` files; exact parsed-value matching | No directory crawl, symlinks, interpolation, multiline values or history |
| Vercel | Selected team/projects and production/preview/development; metadata plus permitted reads | Sensitive values remain unreadable; shared/custom/deployment inventory unchecked |
| Railway | Selected project/environment/service; unrendered variable query | References remain unresolved; sealed-variable enumeration unknown; shared/deployment inventory unchecked |
| GitHub | Repository and selected environment secret metadata | Values unavailable; organization inheritance and workflow references unchecked |
| AWS IAM | Selected access key last-used lookup with separate static audit profile | IAM access keys only; unknown freshness; no SSO/process/role-profile helpers |
| OpenAI | Selected organization/project/key metadata with separate audit credential | No inference requests; null/missing/denied is not evidence of inactivity or revocation |
| TUI | Scope entry, scan/coverage, tasks, issuer checks, shareable export | Guided source entry supports paths with spaces; account-token Railway auth in TUI |
| Skills | Codex and Claude Code shareable-report interpretation | No authenticated collection from the agent; host behavioral validation pending |

## Local inventory

```sh
./bin/keyradar scan --incident custom \
  --local-file ./api/.env --local-file ./worker/.env \
  --format json --shareable
```

The parser accepts single-line `KEY=value`, optional `export`, single/double quotes without escapes, blank lines and full-line comments. Unquoted surrounding whitespace is trimmed; whitespace inside quotes is retained. `$`, backticks, backslash escapes inside quotes and unsupported multiline syntax are rejected with a partial-scan warning. Duplicate keys are excluded. Inline `#` is literal in this small grammar. Empty values are inventoried but never equality-matched.

Only whole values match. A password embedded in a URL will not match its standalone copy. Same names do not imply same values. Equal password strings without issuer context are kept as separate revocation targets.

## Provider inventory

Run authenticated commands yourself in an **independent terminal**, outside agent-captured tool execution. Tokens are prompted invisibly; no token flags, environment-token discovery or CLI-cache scraping.

```sh
./bin/keyradar scan --incident vercel-apr-2026 \
  --vercel-team team_example --vercel-project prj_example \
  --environment production --environment preview \
  --railway-project project_example --railway-environment env_example \
  --railway-service service_example \
  --github-repo owner/repo --github-environment owner/repo:production \
  --local-file ./api/.env \
  --case "$HOME/.local/state/keyradar/cases/example"
```

Use `--railway-project-token` for a Railway project token rather than an account token in CLI scans. The source flags are explicit and repeatable where noted in `help`; the Railway tuple is single-scope per run. Reads use fixed provider hosts and no ambient HTTP proxy. The tool's read-only behavior does not make a broad provider token read-only.

The Vercel template is guidance based on the documented April 2026 incident, not a claim that every selected credential was stolen. It has no invented attack window. A later `updatedAt` does not prove replacement; today's sealed/sensitive setting does not prove historical exclusion.

## Cases, tasks and issuer checks

`--case` opts into **unencrypted metadata-only state** in a private directory. Case files never store source values, authentication tokens or value fingerprints. Private metadata includes locators, issuer key IDs, scopes and timestamps. Keep it outside repositories and public backups. Existing directories must be owned by you and private (`0700`); symlink paths are rejected.

```sh
./bin/keyradar report --case "$HOME/.local/state/keyradar/cases/example"
./bin/keyradar record --case "$HOME/.local/state/keyradar/cases/example"
./bin/keyradar tui --case "$HOME/.local/state/keyradar/cases/example"
```

`record` supports historical credentials, candidate promotion, issuer binding, replacement links, task attestations, manual activity, tool-token cleanup, and operator closure. Use IDs from the **private** report. Shareable aliases such as `C1` are report labels, not command IDs. Enter issuer-native identifiers, never credential values. Operator assertions remain labeled as such.

After binding a credential to its issuer account/key in `record`:

```sh
./bin/keyradar issuer check --case "$HOME/.local/state/keyradar/cases/example" \
  --credential cred_REPLACE_WITH_CASE_ID --issuer aws --aws-profile keyradar-audit

./bin/keyradar issuer check --case "$HOME/.local/state/keyradar/cases/example" \
  --credential cred_REPLACE_WITH_CASE_ID --issuer openai
```

AWS reads only the explicitly selected static profile from the standard AWS config/credentials files and uses a separate audit identity. It does not execute credential helpers or use the default chain. The checker calls `sts:GetCallerIdentity` to compare the audit account and uses `iam:GetAccessKeyLastUsed` for the selected key; the audit identity must be authorized for that IAM lookup. OpenAI prompts for a separate credential authorized to read the selected project-key metadata; an ordinary inference key may not have that authority. [Provider contracts](docs/provider-capabilities.md) link the authoritative references.

Checks fetch evidence once. They do not poll indefinitely, exercise a suspected key, prove there are no dormant consumers, or approve revocation. A 404 is not proof that a key was revoked. Derived sessions may require separate containment. Stripe and PostgreSQL guidance is manual.

Re-run `scan` with the same explicit scope and case directory to append evidence. Old credentials and tasks remain. Without retained values or fingerprints, a later scan cannot generally prove a previous value changed; unresolved current bindings get new records rather than being guessed equal to old records.

## Reports and cleanup

```sh
./bin/keyradar report --case "$HOME/.local/state/keyradar/cases/example" \
  --format json --shareable > shareable-report.json

./bin/keyradar clean --case "$HOME/.local/state/keyradar/cases/example"
```

Only `--shareable` exports are intended for agent context or public issues. They omit external names/paths/key IDs and use opaque aliases. Private reports include scan time windows and auth-session IDs for audit correlation. Neither output is an exhaustive inventory or an all-clear.

`clean` displays tool-access obligations and refuses to forget pending token cleanup unless `--forget` is explicit. It deletes only its own metadata files, not source files, remote credentials or backups. Revoke test/incident tool tokens yourself and record their cleanup. Local deletion is not secure erasure.

## Agent skills

[Install the Codex and Claude Code skills](integrations/README.md). They interpret an explicitly supplied shareable report and guide the independent-terminal workflow. They do not read `.env` files, private case state or tokens, or run authenticated scan/issuer commands.

## Development

```sh
make check
make smoke
go test ./internal/scan -run '^$' -fuzz FuzzParseEnv -fuzztime 10s
```

Tests include fake HTTP/SDK responses, canary containment, partial collection, parser fuzz seeds, historical/rescan semantics, private case handling, issuer uncertainty, CLI output and TUI navigation. `make smoke` checks the built binary and an offline PTY session. Live account checks are a separate, currently pending gate.

Exit codes: `0` command succeeded; `2` usable partial evidence; `1` failed/invalid request. Success never means the incident is resolved.

[Release notes](docs/RELEASE_NOTES.md) · [Contributing](CONTRIBUTING.md) · [Design RFC](KeyRadar_Design_RFC.md) · [Implementation plan](KeyRadar_Implementation_Plan.md) · [Security](SECURITY.md) · [Apache-2.0 license](LICENSE)
