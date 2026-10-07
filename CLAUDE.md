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

**SsoSession** — a browser's claim to be an identity across a whole realm,
held as a cookie. The widest-reaching credential here: a `Session` holds a
refresh token redeemable at one application, this one speaks for every
application in the realm. Hence a 12-hour life against a refresh token's 30
days, and its own revocation. Only issued where `realms.sso_enabled`.

**AuthorizationCode** — the short-lived, single-use code `/sso/authorize` hands
back through a redirect, exchanged once for tokens. The most exposed credential
here, because it travels in a URL: one minute, consumed atomically on first use,
and bound to the client, the exact `redirect_uri`, a PKCE challenge and the
browser session it came from. Seeing one is not enough to redeem it.

**PendingAuthorization** — the validated authorize request, signed and carried
across the login form so the POST never re-derives the `redirect_uri` from user
input. Not a credential: holding one lets somebody start a login they could have
started anyway.

**Theme** — the appearance tokens an application may give the login page.
Validated values, never CSS, and never read from the request.

**Grant** — permission for one identity to use one application. Existing in a
realm is *not* permission to use the applications in it: authentication says who
someone is, a grant says where they may take that. Signing up grants the
application signed up through; every other application in the realm is a
deliberate later step. A grant can only ever name an application in the
identity's own realm, enforced rather than assumed. Revoking is deleting the
row. The foreign key is `granted_client_id`, not `client_id`, because a uuid
column called `client_id` sitting beside Client's public string `client_id`
is the confusion that class already warns about.

## Request shape

```
POST /api/apps/:client_id/auth/sign_in
GET  /sso/authorize?client_id=…&redirect_uri=…&state=…&code_challenge=…
GET  /sso/login?authorization=…               (the hosted login page)
POST /sso/login                               (credentials; sets the cookie)
POST /sso/login/mfa
POST /api/apps/:client_id/auth/token          (redeems the code)
GET  /.well-known/jwks.json
GET  /.well-known/openid-configuration
```

On the credential endpoints `client_id` is a path segment because a CORS
preflight can see nothing else. `/sso/authorize` takes it from the query string
instead — no preflight reaches a top-level navigation, and discovery publishes
one `authorization_endpoint` — but still from a named source, never `params`.

`/sso/authorize` answers from an existing realm session, or sends the browser to
the **hosted login page** — the only HTML here outside mailers. `prompt=none` is
the exception and still answers `login_required`, so an application can ask "is
there a session?" without a form appearing.

The cookie is established in reply to a credential submission from that browser,
which is what makes session fixation structurally impossible rather than
mitigated — there is nothing to transplant into somebody else's browser. The
page carries **no JavaScript** and ships `script-src 'none'`; that is what makes
serving HTML acceptable in the process holding the signing key. Read the rule
before touching it.

The two halves sit on different surfaces, decided by what a CORS preflight can
see. `/authorize` is a top-level navigation, so no preflight happens and there is
no origin check to keep; the token endpoint is a preflighted cross-origin POST,
and a refused preflight stops the real request being sent — so its `client_id`
stays in the path to keep that control. Discovery therefore advertises
`authorization_endpoint` but **no `token_endpoint`**: OIDC publishes one, and
this server's is per-application. That is deliberate, not a gap.

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
| `app/models/grant.rb` | which applications an identity may use |
| `app/models/sso_session.rb` | the realm-wide browser session behind single sign-on |
| `app/models/authorization_code.rb` | the redirect-borne code, and the rules for consuming it |
| `app/controllers/sso/logins_controller.rb` | the hosted login page, and why HTML is safe here |
| `app/controllers/concerns/double_submit_csrf.rb` | CSRF without a session, and why not Rails' own |
| `app/services/credential_check.rb` | the ORDERED sequence both the API and the page use |
| `app/models/theme.rb`, `app/services/theme_css.rb` | appearance tokens: validated in, re-checked out |
| `app/controllers/sso/authorizations_controller.rb` | `/sso/authorize`; the validation ORDER is the security property |
| `app/controllers/api/tokens_controller.rb` | redeems a code; consumes BEFORE verifying, deliberately |
| `app/controllers/concerns/sso_cookie.rb` | the only cookie this server sets, and its attributes |
| `app/controllers/concerns/issues_sessions.rb` | the one place a session is issued, and where grants are enforced |
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

No Rails session, no flash, and no JavaScript anywhere. No OAuth provider for
other people's APIs — each application keeps its own. No knowledge of
containers, memberships or roles.

HTML exists for the hosted login page only, under `app/views/sso`. Two cookies
exist — the realm session and the login form's CSRF token — each written in
exactly one place and path-scoped to `/sso` so neither reaches the API. See the
"API only, plus the hosted login page" rule.
