# Provider contracts and validation

Checked against public documentation on October 21, 2026. All implemented adapters are tested with mocked responses; no live-account smoke has been run for this alpha.

| Adapter | Contract used | Authorization / limitations |
|---|---|---|
| Vercel | `GET /v10/projects/{project}/env?decrypt=false`, then `GET /v1/projects/{project}/env/{id}` | Explicit team/project/environment. Read plain values or values explicitly marked decrypted; otherwise preserve unreadability. Sensitive values are not read. |
| Railway | `POST https://backboard.railway.com/graphql/v2`, fixed `variables` query with `unrendered: true` | Explicit project/environment/service. Bearer account token or explicit project-token header. GraphQL errors are partial even with HTTP 200. Sealed enumeration is unknown. |
| GitHub | Repository Actions secrets and repository environment secrets, paginated; API version `2026-03-10` | Separate read permission for the selected endpoint. Metadata only; organization inheritance unchecked. |
| AWS | SDK v2 `STS.GetCallerIdentity`, `IAM.GetAccessKeyLastUsed` | Selected static profile only. Account is checked; key-to-local-material binding stays an operator assertion. No STS target keys or freshness guarantee. |
| OpenAI | `GET /v1/organization/projects/{project}/api_keys/{key}` | Independent audit credential, explicit organization/project/key. Nullable `last_used_at`; no inference traffic, raw response logging or revocation inference from 404. |

No provider token is provisioned by KeyRadar. Every authenticated session creates a metadata cleanup obligation. Source request time windows and counts are retained locally. Failed API response bodies never become diagnostics.

Official sources:

- [Vercel list](https://vercel.com/docs/rest-api/projects/retrieve-the-environment-variables-of-a-project-by-id-or-name), [single value](https://vercel.com/docs/rest-api/projects/retrieve-the-decrypted-value-of-an-environment-variable-of-a-project-by-id), [SDK source](https://github.com/vercel/sdk).
- [Railway variable query](https://docs.railway.com/integrations/api/manage-variables), [variable semantics](https://docs.railway.com/variables).
- [GitHub Actions secrets](https://docs.github.com/en/rest/actions/secrets).
- [AWS last-used API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html), [null semantics](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKeyLastUsed.html).
- [OpenAI project keys](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys).

Unknown latency remains unknown. The alpha makes no automated quiet-window or safe-to-revoke decision. Manual task evidence is required for effective invalidation and deployment health.
