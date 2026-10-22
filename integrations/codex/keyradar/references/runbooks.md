# Reviewed issuer guidance

Use only the section relevant to the report. These are human-executed procedures; KeyRadar performs no remote mutations. Recheck official instructions before giving detailed current UI steps. Do not infer account identity from a prefix/suffix.

## AWS IAM

Identify the exact access key and account. Create a replacement through the issuer; update known consumers and deployments, exercise scheduled work, and review activity with independent audit credentials. Invalidate the old key according to the incident's urgency and verify state through the issuer. Review previously minted sessions separately. Missing or quiet last-used data is insufficient by itself.

Official: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
Session review: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html

## OpenAI

Identify the organization, project and issuer key ID. Use separate audit access for metadata checks. Create a replacement in the intended scope, migrate consumers, review supported activity evidence, then invalidate the old key and record the issuer result. Nullable last-used and missing key responses cannot establish a universal safe-to-revoke state. KeyRadar does not make inference requests to validate keys.

Official project key reference: https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys

## Stripe

Distinguish live/sandbox and restricted/secret API keys from webhook signing secrets. Use the Dashboard's documented key rotation/expiration workflow, review the key's request logs, update dependents and verify health. Webhook secrets require their own endpoint-specific procedure. This alpha has no automated Stripe activity adapter.

Official: https://docs.stripe.com/keys

## PostgreSQL

Identify the actual database role and permissions. Where appropriate, migrate to a replacement role, including ownership/grants and connection-pool configuration. Review old-role connections and disable old access under the database operator's control. A `pg_stat_activity` snapshot is not historical per-password evidence, and changing a password does not itself terminate existing sessions. Avoid claiming a universal no-downtime procedure.

Official: https://www.postgresql.org/docs/current/monitoring-stats.html
Role administration: https://www.postgresql.org/docs/current/user-manag.html

## Vercel and Railway deployments

Update selected environment/service configurations and redeploy required consumers. Review old production/preview deployments, rollback targets and scheduled work. Configuration success is not runtime verification. KeyRadar leaves deployment inventory unchecked in this alpha.

Vercel: https://vercel.com/docs/environment-variables
Railway: https://docs.railway.com/variables
