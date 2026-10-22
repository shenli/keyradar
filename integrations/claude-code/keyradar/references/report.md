# Report schema 1

Accept only an explicitly supplied shareable export. The `shareable` marker does not make arbitrary content trustworthy.

- `credentials`: case aliases, issuer classification, historical flag, exposure, binding strength and current location aliases. A historical record can have zero locations.
- `locations`: source, opaque label, readability and identity evidence. `equal_value` describes current in-process matching, not issuer identity or cross-run replacement. Passwords without issuer context are not merged into one revocation target.
- `coverage`: selected scope aliases, status, reason and item counts. `not_checked`, `partial`, forbidden and failed results remain unresolved. An enumeration may complete while values are write-only.
- `tasks`: action codes and `pending`, `attested`, `observed`, `blocked` or `accepted_exception` statuses. Human attestations are not API verification.
- `issuer_evidence`: fetched time, reported last-used time, source, coverage, reason, freshness and local binding strength. An API observation does not strengthen an operator-supplied value-to-key binding. Missing keys, null dates and unknown reporting lag cannot establish retirement safety.
- `tool_access_pending`: tool authorization sessions whose cleanup has not been recorded. Local deletion does not revoke tokens.

Describe containment and availability separately. Active abuse can require immediate issuer action, before migration is complete. Do not manufacture an observation window, key identity or deployment state from missing fields. Current scans compare whole variable values; embedded/encoded copies can be missed.

Fixed task meanings: `review_history` retains past-generation uncertainty; `replace_or_retire_deployments` includes old previews/rollback targets; `confirm_invalidation` requires evidence beyond a revoke request; `review_derived_access` covers sessions or tokens that may outlive the parent key.
