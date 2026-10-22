# 0.1.0-alpha — implementation candidate

KeyRadar now provides a local CLI and four-view TUI for cross-platform credential incident response.

Implemented:

- Explicit Vercel, Railway, GitHub Actions metadata and local-file inventory, with scoped coverage and partial failure reporting.
- Transient exact-value grouping, separate historical credential records, per-location migration tasks and per-credential retirement tasks.
- Read-only AWS IAM last-used and OpenAI project-key metadata checks using independent audit authorization.
- Metadata-only cases, append-only scan/evidence history, private audit windows, tool-access cleanup records, and separate shareable JSON/Markdown exports.
- Embedded conservative Vercel April 2026 guidance and a custom incident template.
- Installable report-reading skills for Codex and Claude Code, with issuer-specific manual runbooks.
- Persistent command prompt with a visible caret, guided source picker, editable metadata fields and explicit Enter-to-run commands.
- Offline demo, mocked API tests, race/static/fuzz checks, PTY smoke test and pinned CI workflow.

Known limits: no remote writes or revocation, no exhaustive platform/deployment inventory, no cross-run value-change proof, no quiet-window retirement approval, static AWS profiles only, and no OS-level isolation between a user-owned agent and terminal. Cases contain private unencrypted metadata. See the README support table and validation record for precise scope.

This candidate has passed local offline checks. Live integration checks, real-host skill behavior and hosted CI remain pending. This document describes the source alpha; it is not a tagged release announcement.
