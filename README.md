# auth-jwks

Async JWKS key fetching, caching, and JWT verification built on `httpx` + `PyJWT`.

## Why

Validating JWT tokens against JWKS endpoints requires:

- fetching keys from a discovery URL or certs endpoint
- caching keys with TTL to avoid hitting the endpoint on every request
- thread-safe refresh under asyncio (double-checked locking)
- handling key rotation (`kid` lookup + automatic refresh)

`auth-jwks` solves this with a single async client that handles
discovery, caching, and verification in one call.

## Features

- OpenID Connect discovery (`.well-known/openid-configuration`)
- Direct JWKS endpoint access (skip discovery with `jwks_uri`)
- Strict issuer cross-check against OIDC discovery document (`IssuerMismatchError`)
- Cloudflare Access token validation + Starlette middleware
- Async-native (`httpx`), no blocking I/O
- Auto-caching with configurable TTL (default 15 min)
- RS256 + ES256 algorithms
- Bearer prefix auto-stripping
- Fully typed (`py.typed`)

## Installation

```bash
pip install auth-jwks
# With Cloudflare Access support:
pip install auth-jwks[cloudflare]
```

## Usage

### OAuth2 / OpenID Connect

Validate ID Tokens or JWT Access Tokens against any OIDC provider
(Ory Hydra, Keycloak, Auth0, etc.):

```python
from auth_jwks import JWKS

jwks = JWKS(
    discovery_url="https://your-issuer/.well-known/openid-configuration",
    issuer="https://your-issuer",   # recommended: cross-checked against discovery
    aud="your-client-id",
)
payload = await jwks.verify_token(token)
await jwks.close()
```

[Token verification with automatic key discovery, caching, and rotation handling diagram](docs/diagrams/jwks-oidc.md)

#### Security: strict issuer validation

When `issuer=` is provided in discovery mode, `auth-jwks` cross-checks the
configured value against the `issuer` field in the OIDC discovery document on
every cache refresh. If they disagree, an `IssuerMismatchError` (a subclass of
`jwt.InvalidTokenError`) is raised before any keys are trusted.

This prevents silent acceptance of tokens from a misconfigured or foreign IAM
tenant — for example, if `discovery_url` is accidentally pointed at the wrong
environment. The configured `issuer` becomes the authoritative anchor for PyJWT
validation instead of whatever the discovery document returns.

```python
from auth_jwks import JWKS, IssuerMismatchError
import jwt

jwks = JWKS(
    discovery_url="https://your-issuer/.well-known/openid-configuration",
    issuer="https://your-issuer",
    aud="your-client-id",
)

try:
    payload = await jwks.verify_token(token)
except IssuerMismatchError:
    # discovery URL pointed at wrong tenant — treat as configuration error
    raise
except jwt.InvalidTokenError:
    # token itself is invalid
    raise
```

Without an explicit `issuer=`, the library trusts the issuer from the discovery
document unconditionally and emits a `WARNING` log recommending the explicit
form for production deployments.


### Direct JWKS Endpoint

When you already know the JWKS URI and don't need OpenID Connect discovery
(e.g., AWS Cognito, Firebase, or custom providers):

```python
from auth_jwks import JWKS

jwks = JWKS(
    jwks_uri="https://your-provider.example.com/.well-known/jwks.json",
    issuer="https://your-provider.example.com",
    aud="your-client-id",
)
payload = await jwks.verify_token(token)
await jwks.close()
```

This skips the discovery step and fetches keys directly from the JWKS endpoint.
The `issuer` parameter is optional; when omitted, issuer claim validation is skipped.

### Cloudflare Access

Validate Cloudflare Access JWT tokens and extract user identity:

```python
from auth_jwks.cloudflare import CloudFlareTokenValidation

cfa = CloudFlareTokenValidation(aud="your-aud", team="your-team")
user = await cfa.verify_user(token)      # -> User(sub, email, country)
email = await cfa.verify_email(token)    # -> str
identity = await cfa.get_identity(token) # -> Identity (full CF profile)
await cfa.close()
```

[Token validation against Cloudflare's certs endpoint with optional identity enrichment diagram](docs/diagrams/cf-access.md)

### Starlette / FastAPI Middleware

Protect routes with Cloudflare Access authentication:

```python
from auth_jwks.cloudflare import CfaAuthMiddleware, CloudFlareTokenValidation

cfa = CloudFlareTokenValidation(aud="your-aud", team="your-team")
app.add_middleware(CfaAuthMiddleware, verify_token=cfa.verify_user)
# request.state.user -> User(sub, email, country)
```

[Request authentication flow with dev bypass and automatic token extraction diagram](docs/diagrams/middleware.md)

## Configuration

### JWKS

| Parameter | Default | Description |
|-----------|---------|-------------|
| `discovery_url` | `None` | OpenID Connect discovery endpoint |
| `jwks_uri` | `None` | Direct JWKS endpoint URL (skips discovery) |
| `issuer` | `None` | Expected issuer. In discovery mode: cross-checked against OIDC document (recommended for production). In direct mode: used for PyJWT issuer validation. Must be a non-empty string or `None`. |
| `aud` | `None` | Expected audience (skip validation if `None`) |
| `allowed_algorithms` | `{"RS256", "ES256"}` | Accepted signing algorithms |
| `cache_ttl` | `900` | Key cache lifetime in seconds |
| `leeway` | `30.0` | Clock skew tolerance in seconds |
| `timeout` | `5.0` | HTTP request timeout in seconds |
| `retries` | `3` | HTTP retry count |
| `fix_local_url` | `True` | Normalize local/Docker URLs (scheme + host replacement) |

At least one of `discovery_url` or `jwks_uri` must be provided. When both are given, `jwks_uri` takes precedence.

### Upgrading

**`issuer=""` is now rejected** — passing an empty string for `issuer` raises `ValueError` in both discovery and direct mode. Previously an empty string was silently accepted with ambiguous results: in discovery mode it raised a `ValueError` internally (no-op), while in direct `jwks_uri` mode PyJWT would validate the `iss` claim against an empty string and silently reject all real tokens. Neither behaviour was intentional or useful. To skip issuer validation explicitly, pass `issuer=None` (the default); to validate the issuer, pass a non-empty string.

### CloudFlareTokenValidation

| Parameter | Default | Description |
|-----------|---------|-------------|
| `aud` | — | Cloudflare Access application audience tag |
| `team` | — | Cloudflare Access team name |
| `allowed_algorithms` | `{"RS256", "ES256"}` | Accepted signing algorithms |
| `cache_ttl` | `900` | Key cache lifetime in seconds |
| `leeway` | `30.0` | Clock skew tolerance in seconds |

All clients must be closed after use (`await client.close()`).
Token methods raise `jwt.InvalidTokenError` on validation failure.
`IssuerMismatchError` (importable from `auth_jwks`) is a subclass of `jwt.InvalidTokenError`
raised when a configured issuer disagrees with the OIDC discovery document.

## License

MIT
