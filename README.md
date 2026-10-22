# CloudFront SOCA plugin

An MVP SOCA/OIDC gate for private S3 static content. One Lambda@Edge viewer-request
handler checks access before CloudFront serves cached objects. A local generator
packages JavaScript, configuration, ES256 keys and AES-256-GCM session keys into a
private ZIP. No runtime KMS, database, Secrets Manager, Parameter Store or AWS SDK.
Sign-in contacts the trusted identity provider; authenticated content requests use
local cryptography only. There are no local user accounts or admin UI.

**Alpha:** ES256, one issuer, static GET/HEAD content and stateless sessions.
Sessions default to **43,200 seconds (12 hours)**. Sign-in is disabled by default
and admission denies everyone until an allow rule is supplied. See the
[requirements and verification gaps](docs/requirements.md) before deployment.

## Package

Use Node.js 24 and npm. Licence: AGPL-3.0-only.

```sh
npm ci --ignore-scripts
mkdir -p .soca
cp examples/config.json .soca/config.json
npm run soca -- init .soca/keys.json
# Edit origin, issuer, allow rules and paths in .soca/config.json.
npm run soca -- preview .soca/config.json .soca/keys.json
npm run soca -- build .soca/config.json .soca/keys.json .soca/deployment-v1.zip
```

Keep the key file across rebuilds. `init` and `build` refuse to overwrite files.
The ZIP contains `index.mjs`, private `deployment.json` and the licence; dependencies
are bundled. No generator or simulator runs inside Lambda. Identical source,
configuration and keys produce identical ZIPs.

Generated ZIPs **contain private keys**. Keep them in private deployment storage,
never Git, public releases, CI artefacts or the content bucket. Key files and ZIPs
are created with mode `0600`. Anyone allowed to download Lambda code or the source
ZIP can extract the keys. This is the chosen exportable-key model.

## Deploy

- [Terraform module](terraform/README.md) publishes a numbered Lambda version.
- [CloudFormation template](cloudformation/README.md) deploys the function from a
  private, versioned S3 ZIP. Use it directly or as a nested stack, the practical
  equivalent of a reusable Terraform module.
- [Complete Terraform example](examples/terraform/README.md) adds private S3, OAC
  and CloudFront, with a disabled distribution for safe hostname bootstrap.

Deploy in `us-east-1`, Node.js 24, x86_64, handler `index.handler`. Associate the
numbered version with **viewer-request on every relevant cache behaviour**, with
`include_body=false`. Lambda@Edge has no custom runtime environment variables;
configuration is fixed in the ZIP. Source is in [src/](src/).

First publish an `enabled=false` package for the real HTTPS origin and run:

```sh
npm run soca -- check .soca/config.json .soca/keys.json
```

This checks exact public documents and provider capabilities. It does **not** test
login or authorise activation. Verify a real allowed and denied login on a separate
staging distribution with `enabled=true` before deploying that configuration with
production content. There is no candidate-only operator login or enforced
activation evidence yet. See F-20 in the assessment.

For content caching, exclude cookies, query strings and viewer identity headers
from cache keys and S3 forwarding, as in the example. All admitted users receive
the same static objects. Do not use this cache configuration for personalised
responses. Avoid access logs that retain callback query strings or cookies.

## Configuration

All settings/defaults are in [src/config.mjs](src/config.mjs). File values override
defaults; `SOCA_SESSION_TTL_SECONDS` overrides the file **at generator time**.
It has no runtime effect. Unknown settings fail validation.

| Setting | Meaning/default |
| --- | --- |
| `origin` | Required canonical public HTTPS origin, no trailing slash; never inferred from headers. |
| `issuer` | Exact trusted issuer; default `https://auth.resoauth.cloud`. |
| `enabled` | `false`: metadata stays public; protected content and login return 503. |
| `session_ttl_seconds` | Absolute lifetime, `43200`; integer range 1 to 604800. |
| `enable_readable_id_token_cookie` | `false`; opt in to the full validated JWT in JavaScript-readable `__Host-soca_id_token`. |
| `transaction_ttl_seconds` | `300`; integer range 1 to 600, four pending logins maximum. |
| `protected_paths` / `public_paths` | `['/']` / `[]`. Literal segment prefixes: `/docs` matches itself and descendants, not `/docs-old`. Public exceptions take precedence. |
| `allow_domains` / `deny_domains` | Empty; exact DNS domains or `*.example.com` for subdomains only. |
| `allow_emails` / `deny_emails` | Empty; case-insensitive exact addresses. Deny rules take precedence. Boolean `email_verified: true` required. |
| `auth_path` | `/_soca`; reserves `client.json`, `jwks.json`, `login`, `callback`, `logout`. |
| `metadata_mode` / `proxy_template` | `hosted`; proxy default `https://dynamic-cimd.resoauth.cloud/cimd/%s`. |
| `client_name`, `client_uri`, `logo_uri`, `policy_uri`, `tos_uri` | Site identity and public legal/branding URLs. Client URI defaults to origin; unavailable optional fields are omitted. |
| `scopes` | `['openid', 'email']`; only `openid`, `email`, `profile` accepted. No refresh tokens or UserInfo retrieval. |
| `max_age_seconds`, `required_acr`, `required_amr` | Optional freshness/assurance. Defaults `null`, `[]`, `[]`; use the provider's documented assurance semantics. |
| `security_epoch` | Non-negative integer, default 0. Increment to invalidate cookies as updated edge versions propagate. |

Selected-path protection covers **viewer paths**. Protect every alias to the same
object, including `/` if it maps to a protected default root object. Do not add
origin rewrites or custom error fallbacks that serve protected objects from public
paths. Ambiguous encoded delimiters, double encoding and dot segments are rejected.

Proxy mode uses sorted-key compact UTF-8 JSON, unpadded base64url, no `client_id`
inside the payload and a 4096-character URL limit. It references a stable public
`jwks_uri`; inline JWKS is not implemented. Proxy metadata is public and visible
to the proxy. The proxy does not perform provider authentication.

## Readable ID token

Set `"enable_readable_id_token_cookie": true` in the deployment configuration and
rebuild the ZIP to expose the original, validated provider ID-token JWT to the
static app:

```js
const idToken = document.cookie.split('; ')
  .find(cookie => cookie.startsWith('__Host-soca_id_token='))?.split('=')[1];
```

This separate cookie is host-only, `Secure`, `SameSite=Lax`, `Path=/` and deliberately
omits `HttpOnly`. It expires at the earlier of ID-token expiry and session expiry,
and is not refreshed by content requests. The authenticated session can outlive it;
the app must handle an absent token. Logout clears it, and a successful sign-in
with the option disabled clears a previous readable cookie. Full JWTs exceeding
3800 characters cause opted-in sign-in to fail; they are never truncated.

For independent verification, use the **issuer's JWKS** from its trusted discovery
document, not this plugin's client-assertion JWKS. Pin ES256, the configured issuer
and exact client ID (including proxy mode), and validate expiry and other required
claims using a maintained library such as [JOSE](https://github.com/panva/jose).
Decoding alone does not verify a JWT. Browser JWKS retrieval requires provider CORS
support. The readable token is app identity data; edge access still requires the
encrypted `HttpOnly` session. Its signature alone does not bind it to that session.

Opting in exposes all ID-token claims to scripts on this origin, including injected
or third-party scripts. Keep the default off unless the app needs those claims.
The token is stripped before origin forwarding and is never published in metadata
or logs. This explicit opt-in is recorded in the SOCA requirements assessment.

## Test and demo

```sh
npm test
podman build -t soca-edge-demo .
podman run --rm --network=none soca-edge-demo npm test
podman run --rm -p 127.0.0.1:8443:8443 soca-edge-demo
```

Docker accepts the same commands. Open `https://localhost:8443` and accept the
local demo's ephemeral self-signed certificate. It uses real JWT/cookie
cryptography with an **in-process identity-provider simulator**, automatically
admitting `reader@example.com`. It simulates the CloudFront event and static
origin, not AWS replication or a real provider login. Simulator injection is
confined to demo/tests, never packaged as a runtime option. `npm run demo` runs
without a container, with `openssl` installed.

CI tests source, standalone ZIP and container, validates infrastructure, audits
dependencies and emits a dependency SBOM. CodeQL scans JavaScript and workflows.
No secret-bearing ZIP is uploaded by CI. See the
[operations and threat model](docs/security.md) for rotation and stateless limits.
