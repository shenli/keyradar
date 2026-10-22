# Security

KeyRadar processes credentials during incident response. This alpha has not received an independent security audit or live-provider validation.

Report suspected vulnerabilities privately through the repository's [security advisory form](https://github.com/shenli/keyradar/security/advisories/new), if the maintainer has enabled private reporting. If that form is unavailable, open a non-sensitive issue asking the maintainer to establish a private channel; do not put exploit details, secrets or private cases into the issue. As of October 22, 2026, the repository is private and availability of this reporting form is unverified. A working private channel must be established before public release.

Never attach `.env` files, raw provider responses, private case JSON, audit tokens or real credential values. A synthetic reproduction and `--shareable` report are preferred.

The implementation uses fixed-host read-only requests, bounded responses, explicit source selection, no-follow local file access on macOS/Linux, typed metadata reports and separately supplied audit authorization. It does not validate suspected keys by using them. The TUI suspends rendering for independent-terminal authentication.

Private state is unencrypted metadata with restrictive file permissions. A broadly privileged agent, debugger, compromised host, memory dump, swap or backup can defeat workflow protections. Go does not provide a hard secret zeroization guarantee. Shareable output minimizes identifiers but is not complete anonymization. Skill instructions are not an OS sandbox.

A source inventory cannot prove all copies were found. Issuer silence cannot prove no dormant consumer remains. Revocation requests, effective invalidation, deployment health and human closure are distinct evidence. Never use KeyRadar to postpone urgent containment solely to wait for a quiet period.
