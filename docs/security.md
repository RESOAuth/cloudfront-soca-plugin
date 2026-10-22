# Operations and threat model

The resource is static content accessible to every admitted identity. Trust the
configured issuer, HTTPS/TLS, AWS IAM/control plane, CloudFront behaviours and
private deployment package. Keep S3 private and readable by the specific
distribution through OAC, not an S3 website endpoint.

## Cryptography and network

Client assertions use P-256/ES256 and expire in 60 seconds. ID tokens use the
trusted issuer's P-256 keys and ES256 only. JWT headers/discovery ordering cannot
enable another algorithm. State, nonce and PKCE verifier are independent random
values. Encrypted transaction cookies bind browser, issuer, client ID, callback,
configuration and safe return path. A separate encrypted cookie provides browser
binding; parallel tabs use independent state-named transaction cookies. Two
first-ever concurrent login starts without an established browser cookie can race;
retry the affected tab.

Authentication/transaction cookies use purpose-separated HKDF-SHA256 keys,
AES-256-GCM with random 96-bit IVs,
authenticated context, `Secure`, `HttpOnly`, `SameSite=Lax`, host-only scope and
`Path=/`. No JavaScript storage. Sessions retain only issuer, subject, random ID,
times and policy revision. Access/refresh tokens are never retained. ID tokens are
discarded by default; `enable_readable_id_token_cookie=true` intentionally retains
the full validated JWT in a separate JavaScript-readable cookie for the static app.
Session expiry is absolute and is not extended by activity.

That opt-in cookie, `__Host-soca_id_token`, is signed by the provider but not encrypted
or `HttpOnly`. It is host-only, `Secure`, `SameSite=Lax`, `Path=/`, limited to 3800
characters, and expires no later than the ID token or session. Oversized/expired
tokens fail opted-in login before issuing any session. Logout deletes it; signing
in with the option off deletes a previous copy. It is not renewed on content access
and never authorises edge requests. All SOCA cookies are stripped from origin
requests. Every same-origin script can read or alter this cookie, so this is an
explicit exception to confidential token storage/browser-storage targets in F-24,
F-25 and N-03. Verify with trusted issuer keys and claims if the app needs independent
authenticity; the plugin's signing JWKS does not validate provider ID tokens.

Outbound JSON requests require public HTTPS endpoints on port 443, verify TLS,
check every DNS answer, pin the address, reject redirects, disable pooling and
enforce a five-second total deadline and 128 KiB limit. Discovery/JWKS expire in
five minutes; refreshes coalesce, with unknown-key/signature refreshes limited to
once per 30 seconds per instance. Outages/expired trust fail closed. Shorter
provider cache directives and revocation feeds are not implemented yet.

## Rotation and revocation

Key files contain `signing_key` (active private JWK), `public_keys` (public
current/next/retiring JWKs) and `session_keys` (first encrypts; all decrypt).
Each keyring has at most three entries. `init` generates an independent key file;
there is no unattended rotation or automatic promotion command. Prepare a combined
file locally without printing its contents or replacing the production file.

For signing rotation, add the next public key while retaining the old signer.
Deploy, check public documents, wait for full CloudFront propagation and the
provider's documented JWKS cache bound, then switch `signing_key`. Retain the old
public key through outstanding assertions/transactions plus cache/rollout bounds.
Stable `jwks_uri` preserves client IDs in hosted and proxy modes.

For session rotation, add the next key **second**. Deploy and wait for all replicas,
then promote it to first and redeploy. Retain old decryption keys through the
longest session lifetime plus propagation. Retained keys decrypt across versions;
configuration changes invalidate cookies. Increment `security_epoch` to force
invalidation without an admission change.

Operators coordinate these procedures; they are not atomic across replicas.
Do not claim zero interruption until a real rollout is tested. Emergency changes
apply as new versions propagate. Disabling the distribution through AWS IAM is
the recovery control for an urgent incident.

Without shared replay state, deleting a cookie cannot provide atomic global single
use. The IdP must reject reused codes, but that is not complete F-25 compliance.
Concurrent captured callback replay and an issuer reissuing codes remain risks.
Transactions expire in five minutes by default. There is no individual denylist or
back-channel logout: a copied session remains valid until expiry, key removal or
policy change reaches its replica. Provider account revocation alone does not
invalidate an existing session. Default bound: 12 hours.

## Recovery, retention and releases

Local logout requires same-origin POST and does not contact the provider. It clears
browser cookies, without revoking stolen copies. Rebuild with `enabled=false`,
increment `security_epoch` and deploy to disable SSO. Keep AWS IAM recovery separate
from SOCA and test distribution disable/rollback before uploading content. Never
remove authentication while leaving private content publicly accessible.

Back up keys/configuration in restricted encrypted storage. Lost session keys sign
everyone out; lost signing keys require replacement. Old ZIPs, S3 object versions,
Lambda versions and backups contain secrets after rotation. Restrict
`lambda:GetFunction`, source-object access and deployment roles. Delete obsolete
versions after replica cleanup. Do not restore revoked keys or an earlier security
epoch. The software does not perform remote deletion.

There is no application logging or telemetry. Disable/redact cookie/query logging
at CloudFront and in external observability pipelines. AWS execution logging is
infrastructure-managed; configure its retention/IAM. Public documents expose site
identity and public keys, never admission policy. Never publish deployment ZIPs.

Patch high/critical findings before release. CI pins dependencies/actions, audits
packages and scans with CodeQL. Signed release provenance, browser accessibility
testing, OIDC conformance and independent review are planned. Report security
issues through [private vulnerability reporting](https://github.com/RESOAuth/cloudfront-soca-plugin/security/advisories/new).

Initial CodeQL triage: test permission checks/readbacks use the same open file
handle. [Alert 4](https://github.com/RESOAuth/cloudfront-soca-plugin/security/code-scanning/4)
traces operator-configured public document/issuer URLs from the configuration file
to the CLI's HTTPS document check, not key material. This intended flow was reviewed
and recorded as a false positive; the query remains enabled.
