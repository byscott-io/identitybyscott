# identitybyscott

An OpenID Connect identity server. Authenticates people and issues RS256 tokens
that applications verify **offline** against a published JWK Set.

**Behaviour rules live in `.claude/rules/identitybyscott.md`, not here.** Read
them before changing anything — they are short, and each one prevents an error
already made or easily made. This file is the map.

## The model

**Realm** — a suite of applications that share identities. Realms are fully
isolated: the same email address is a *different* identity in each, with its own
password and its own MFA. `realms.key`, `require_email_confirmation`.

**Identity** — a person, within one realm. The `uuid` primary key is the OIDC
`sub` and the only cross-application key for that person. Never the email, which
is mutable.

**Client** — a registered application. This record is what makes realm isolation
real: every request's realm is resolved from the `client_id` it presents. Also
holds the CORS origin allowlist and the URLs this server builds emailed links
from. Note `client_id` is a readable public **key** (`churchcare`), not a
database id — the `id` column is an internal uuid that never leaves the server.

## Request shape

```
POST /api/apps/:client_id/auth/sign_in
GET  /.well-known/jwks.json
GET  /.well-known/openid-configuration
```

`client_id` is a path segment because a CORS preflight can see nothing else.

## Where things are

| | |
|---|---|
| `app/controllers/api/base_controller.rb` | resolves the client, enforces the origin allowlist |
| `app/controllers/api/authenticated_controller.rb` | verifies this server's own access token |
| `app/controllers/api/preflight_controller.rb` | CORS preflight, deliberately unauthenticated |
| `app/services/signing_keys.rb` | RS256 key material and the published JWK Set |
| `app/services/token_issuer.rb` | access-token claims |
| `app/services/mfa_challenge.rb` | the short-lived token between password and TOTP |
| `app/models/identity.rb` | credentials, TOTP, backup codes, realm-scoped lookup |
| `bin/check-public-safe` | refuses secrets and infrastructure detail; see the rules |

## Running it

```bash
bin/with-ruby bundle exec rspec        # also the pre-push hook
bin/with-ruby bundle exec rubocop      # also the pre-commit hook
bin/with-ruby ruby bin/check-public-safe --all
```

Hooks run through `bin/with-ruby` because they run non-interactively and would
otherwise die on a Ruby version mismatch.

## Configuration

Read from the environment, never committed:

| | |
|---|---|
| `IDENTITY_SIGNING_KEY` | RSA private key, PEM. Signs every token. |
| `IDENTITY_SIGNING_KEY_ID` | optional `kid`; a stable digest is derived otherwise |
| `IDENTITY_RETIRED_PUBLIC_KEYS` | `\|`-separated PEMs, still published and accepted |
| `IDENTITY_ISSUER` | the `iss` claim, and the base of the published URLs |
| `MAILER_SENDER` | From address |

### Rotating the signing key

Two phases, and the order matters. Publish the new **public** key via
`IDENTITY_RETIRED_PUBLIC_KEYS` first and wait for verifier caches to refresh;
only then switch `IDENTITY_SIGNING_KEY`. A key put straight into service is
unverifiable to any verifier that fetched recently and is throttled from
re-fetching. Drop the old key once the longest token lifetime has passed.

## What is not here, on purpose

No hosted login page, no HTML, no sessions, no cookies. No OAuth provider for
other people's APIs — each application keeps its own. No knowledge of
containers, memberships or roles.
