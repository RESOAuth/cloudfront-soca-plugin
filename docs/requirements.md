# SOCA requirements assessment

Target: [requirements at 60ea4db](https://github.com/RESOAuth/soca-plugins/blob/60ea4db827457b4a4a7b11d79e86b654612a75e1/requirements.md).
Assessed 22 October 2026 for MVP 0.1.0. This is a static-content gate without host
accounts or admin UI. Partial/planned rows remain target gaps. No AWS deployment
or real-provider login is claimed.

Versioned evidence: [configuration](../src/config.mjs), [runtime](../src/runtime.mjs),
[network](../src/network.mjs), [generator](../generator/package.mjs),
[protocol tests](../tests/runtime.test.mjs), [package tests](../tests/package.test.mjs),
[transport tests](../tests/network.test.mjs), [HTTPS demo](../tests/demo.test.mjs),
[operations](security.md) and the deployment modules.

| ID | Status | Evidence and remaining gap |
| --- | --- | --- |
| F-01 | Partial | Explicit issuer/capability validation and RESOAuth default; one profile, no enforced real-login activation. |
| F-02 | Partial | Code, S256 PKCE, state, nonce, exact callback, ES256 assertions; F-25 global replay gap. |
| F-03 | Partial | Signature, issuer, subject, audience/azp, nonce, times, response issuer, auth_time/acr/amr. ID-token-only claims; UserInfo reconciliation planned. |
| F-04 | Partial | Public HTTPS CIMD/JWKS, stable ID, branding fields and document check. Promotion/reachability operator-enforced. No host branding API. |
| F-05 | Partial | Default proxy, sorted JSON, URI indirection, preview/check and 4096 limit. Real proxy/provider tests and negotiated transport limits planned. |
| F-06 | Partial | Public-only JWKS/metadata; inline JWKS planned. |
| F-07 | Partial | Stable jwks_uri through overlap and configuration-bound transactions. Atomic replica revocation and identity migration tooling planned. |
| F-08 | Partial | Persistent P-256 keys, private package handling. User-selected exportable keys; external non-exportable signing and recovery tests planned. |
| F-09 | Planned | Manual overlap tested locally; unattended rotation, cache confirmation and atomic promotion absent. |
| F-10 | Partial | Fixed ES256/P-256 default; alternative algorithms/vectors planned. |
| F-11 | Partial | Five-minute caches, bounded refresh and fail-closed verification. Provider cache directives/revocation feeds planned. |
| F-12 | Partial | Deny default, boolean verified email, domain/wildcard validation and deny precedence. Policy preview/sensitive-account controls planned. |
| F-13 | Not applicable | S3 has no local account lookup or enabled-user API; issuer/subject plus admission controls access. |
| F-14 | Not applicable | No account provisioning/default credentials; requires an account-bearing host. |
| F-15 | Partial | Identity/admission separate from static read access; no escalation. Provider-side removal affects existing sessions at expiry. |
| F-16 | Not applicable | No local accounts to link; exact issuer/subject, never email-based ownership. |
| F-17 | Partial | No silent email relinking; config/security_epoch revokes cookies. Audited migration tooling planned. |
| F-18 | Planned | No profile writes; admission uses validated email. Mapping/preview absent. |
| F-19 | Planned | No claim diagnostics or retained reports. |
| F-20 | Partial | Headless settings/defaults/TTL override, repeatable builds, revision-bound document results and disabled packages. Candidate-only login, enforced activation evidence and audit absent. No host GUI. |
| F-21 | Partial | Safe return, absolute sessions, CSRF local logout and freshness settings. Individual/RP/back-channel revocation planned. |
| F-22 | Partial | AWS IAM recovery, disable and security_epoch. Edge propagation prevents instantaneous disable; live drill planned. |
| F-23 | Partial | Immutable versions, no host mutations, lifecycle/recovery documented. Live rolling upgrade/restore tests planned. |
| F-24 | Supported | Identity scopes only; discard code/access/ID token, no refresh/offline or delegated profile. |
| F-25 | Partial | Confidential, purpose-separated, expiring browser-bound cookies and parallel-tab cap. No platform store; true atomic global consume needs shared state. First-binding race documented. |
| N-01 | Partial | Maintained JOSE, fail-closed crypto, CSRF logout and source review. Independent security review planned. |
| N-02 | Partial | TLS tests, mixed DNS, pinning, 5-second/128-KiB bounds, no redirects. Restricted-egress/slow-network fault matrix planned. |
| N-03 | Partial | Minimal encrypted identity, no app logging/telemetry/token retention, boundary tests. External logging, backups/deletion and retention are operator duties. |
| N-04 | Partial | Stateless workers, overlap and revocation tested locally. No live failover, rotation, restore or propagation measurements. |
| N-05 | Partial | Local normal requests, bounded cookies/caches/network, 5-MiB ZIP budget. Distributed rates and sustained load tests planned; use deployment controls such as WAF. |
| N-06 | Partial | Semantic logout/error UI, no token dumps. Accessibility audit, redacted incident references, tamper-evident audit and metrics planned. |
| N-07 | Partial | AGPL, Node24, locks, pinned actions/image, CI/audit/SBOM/Dependabot. Signed releases/provenance and rollback evidence planned. |
| N-08 | Partial | Negative crypto/protocol tests, standalone ZIP, TLS transport, browser-like HTTPS roundtrip and container CI. No real browser/provider login, AWS deployment or conformance/independent review. |
| N-09 | Partial | All 34 IDs with versioned evidence/gaps; production gates/coverage automation planned. |

The simulator validates ES256 code/PKCE/assertions and rejects reused codes. Public
RESOAuth discovery was fetched using the real transport and advertised ES256.
That is a discovery check, not a real CIMD login. Hosted/proxy live-provider tests,
AWS propagation and real browser coverage remain unperformed.
