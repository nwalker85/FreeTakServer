# OIDC / OAuth2 Support for FreeTAKServer

Status: proposed
Audience: FreeTAKServer maintainers
Companion change: `FreeTAKTeam/UI` (matching PR)

## Goal

Add provider-agnostic OpenID Connect (OIDC) authentication to all three FTS
auth surfaces — the REST API, the Web UI, and TAK client onboarding — without
breaking the existing static-token / username-password flows.

Reference IdP for tests and docs: Zitadel. The implementation only depends on
standard OIDC discovery, JWKS, authorization-code, and device-authorization
grants — any compliant IdP (Keycloak, Authentik, Auth0, Okta, Entra, Google)
should work unchanged.

## Non-goals

- Replacing the FTS user model. OIDC users are mapped onto existing
  `systemUser` rows; no schema migration is required for v1.
- Federation server-to-server auth. Out of scope; tracked separately.
- TAK client UI changes. Stock ATAK / iTAK / WinTAK are unmodified — they
  speak TLS+username/password or TLS+client-cert as today. OIDC is used by
  the *human* during onboarding, then a TAK cert package is issued.

## Decisions (locked)

| Decision | Choice | Rationale |
|---|---|---|
| Library | `authlib` | Single dep covers OIDC client, JWKS validation, device code |
| Token coexistence | OIDC preferred, legacy fallback | Try JWT validation first; fall through to existing DB token lookup |
| TAK client onboarding | OIDC Device Authorization Grant → cert package | No client changes; standards-based; works on headless devices |
| Feature flag | `FTS_OIDC_ISSUER` env (unset = disabled) | Zero behavior change when not configured; safe upstream default |

## Surfaces

### 1. REST API (`FreeTAKServer/services/rest_api_service`)

Existing: `flask_httpauth.HTTPTokenAuth(scheme='Bearer')` →
`controllers/authentication.py::verify_token` looks up token in `APIUser` /
`systemUser` tables.

Change: `verify_token` first attempts JWT validation against the configured
issuer's JWKS. On success, returns the resolved user (auto-provisioning a
`systemUser` row keyed by `sub` if absent, gated by
`FTS_OIDC_AUTOPROVISION`). On failure (no issuer configured, malformed JWT,
or wrong issuer), falls back to the legacy DB lookup.

Claims contract (configurable via env, sensible defaults):
- `sub` → `systemUser.uid`
- `preferred_username` or `email` → `systemUser.name`
- `groups` claim (or `FTS_OIDC_GROUPS_CLAIM`) → `systemUser.group`
- `FTS_OIDC_REQUIRED_AUDIENCE`, `FTS_OIDC_REQUIRED_SCOPE` enforced

No route changes — every existing `@auth.login_required` decorator gets the
new validator transparently.

### 2. Web UI (`FreeTAKServer-UI/app/base/routes.py`)

Existing: `/login` POSTs username/password to FTS `/AuthenticateUser`.

Change: when `FTS_UI_OIDC_ISSUER` is set,
- the `/login` template renders an "Sign in with SSO" button alongside the
  password form (or replaces it entirely if `FTS_UI_OIDC_ONLY=true`),
- new routes `/oidc/login` (kicks off authorization-code+PKCE) and
  `/oidc/callback` (exchanges code, validates ID token, calls flask_login's
  `login_user` with the resolved/auto-provisioned User).

Local password login remains the default when OIDC is not configured.

### 3. TAK Client onboarding (CoT/DataPackage)

TAK clients can't speak OIDC over the CoT socket, so OIDC sits *in front of*
the existing certificate-issuance pipeline (`core/util/certificate_generation`).

Two new endpoints on the REST API:

```
POST /enroll/device         # Start device-code flow (returns user_code, verification_uri)
POST /enroll/complete       # Poll: when ID token issued, generate + return TAK client cert package (.zip)
```

Flow:
1. Operator launches enrollment helper on/for the device.
2. Helper calls `/enroll/device`; FTS proxies to IdP's
   `/oauth/device_authorization`, returns `user_code` + `verification_uri`.
3. Operator authenticates in a browser (any device) using the user_code.
4. Helper polls `/enroll/complete`; FTS polls IdP's token endpoint. On
   success, FTS validates the ID token, provisions / looks up the
   `systemUser`, generates a TAK client cert package keyed to that user, and
   streams the .zip back.
5. Operator imports the package into ATAK normally.

The CoT/SSL listeners are **unchanged** — they continue to authenticate the
client via TLS client cert + username/password, both of which were just
provisioned via the OIDC flow.

## Configuration (env, all optional)

```
# Server (REST API)
FTS_OIDC_ISSUER=https://auth.example.com
FTS_OIDC_AUDIENCE=fts-api
FTS_OIDC_REQUIRED_SCOPE=fts:api
FTS_OIDC_GROUPS_CLAIM=groups
FTS_OIDC_AUTOPROVISION=true

# Server (Device-code enrollment, optional)
FTS_OIDC_CLIENT_ID=fts-enrollment
FTS_OIDC_CLIENT_SECRET=...     # optional for public clients

# UI
FTS_UI_OIDC_ISSUER=https://auth.example.com
FTS_UI_OIDC_CLIENT_ID=fts-ui
FTS_UI_OIDC_CLIENT_SECRET=...
FTS_UI_OIDC_REDIRECT_URI=https://fts.example.com/oidc/callback
FTS_UI_OIDC_ONLY=false         # if true, hide local password form
```

## Backwards compatibility

- All new behavior is gated on `FTS_OIDC_ISSUER` / `FTS_UI_OIDC_ISSUER`. With
  these unset, the server and UI behave identically to today.
- Static API tokens continue to work alongside OIDC JWTs.
- The existing `/AuthenticateUser` endpoint is preserved for the UI's local
  password flow.
- Database schema is unchanged.

## Test plan

- Unit: JWT validator with mocked JWKS (valid, expired, wrong-aud, wrong-iss,
  missing-scope cases).
- Unit: claims → systemUser mapping with autoprovision on/off.
- Unit: device-code flow with mocked IdP responses.
- Integration: docker-compose profile spinning up FTS + Zitadel, exercising:
  - API call with Zitadel-issued JWT
  - UI login via Zitadel
  - Device-code enrollment producing a usable cert package
- Regression: existing static-token tests still pass unchanged.

## Rollout

PR strategy: single feature branch per repo (`feat/oidc`), opened first
against `nwalker85/FreeTakServer` and `nwalker85/FreeTakServer-UI` forks.
Once exercised against tyr's deployment with Zitadel, propose upstream to
`FreeTAKTeam/FreeTakServer` and `FreeTAKTeam/UI`.
