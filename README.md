# identitybyscott

An OpenID Connect identity server. It authenticates people and issues RS256
tokens that applications verify offline against a published JWK Set.

Published for transparency. It is not packaged for reuse and is not intended to
be imported or deployed by anyone else.

## What it is

- **Realms.** A realm is a suite of applications that share identities. Realms
  are fully isolated: the same email address is a *different* identity in each,
  with its own password and its own MFA.
- **API only.** There are no forms here. Each application builds its own sign-in,
  sign-up and password-reset forms and posts them to this server over HTTPS, so
  an application keeps the look it already has.
- **The realm is never claimed.** It is resolved from the `client_id` a request
  presents, against a registration held here. An application cannot name a realm.

## A note on `client_id`

It is a **key**, not a database id: a stable, public, readable name for an
application, like `churchcare`. It appears in URLs, in the `aud` claim of every
token, and in each application's own configuration.

It is public by design, so it is deliberately readable rather than random --
randomising it would hide nothing and make URLs, tokens and logs harder to read.
A guessed `client_id` grants nothing on its own: posting credentials still needs
the password, and passing a CORS preflight still needs an `Origin` on that
client's own allowlist.

The name is the one RFC 6749 uses, which is why it survives despite describing
a key rather than an id.

## Why RS256 and not HS256

A symmetric secret able to *verify* this server's tokens could also *forge*
them. Under RS256 this server holds the private key and applications hold only
the public half, so a compromised application cannot mint tokens for any other.

## The credential API

Every endpoint is scoped by `client_id` in the path, which is what resolves the
realm. The path is the only part of a request a CORS preflight can see -- a
preflight carries the `Origin`, the method and header *names*, never a body --
so the client is read from the path parameters rather than from `params`, and a
body parameter cannot name a different client than the one whose `Origin` was
approved.

```
POST   /api/apps/:client_id/auth/sign_up
POST   /api/apps/:client_id/auth/sign_in
POST   /api/apps/:client_id/auth/verify_mfa
POST   /api/apps/:client_id/auth/forgot_password
POST   /api/apps/:client_id/auth/reset_password
DELETE /api/apps/:client_id/auth/sign_out

PUT    /api/apps/:client_id/auth/change_password
PUT    /api/apps/:client_id/auth/profile

POST   /api/apps/:client_id/auth/refresh
GET    /api/apps/:client_id/auth/sessions
DELETE /api/apps/:client_id/auth/sessions/:id
DELETE /api/apps/:client_id/auth/sessions

GET    /api/apps/:client_id/auth/mfa
POST   /api/apps/:client_id/auth/mfa/setup
POST   /api/apps/:client_id/auth/mfa/enable
POST   /api/apps/:client_id/auth/mfa/disable
GET    /api/apps/:client_id/auth/mfa/backup_codes
POST   /api/apps/:client_id/auth/mfa/regenerate_backup_codes

GET    /.well-known/jwks.json
GET    /.well-known/openid-configuration
```

Two contracts are worth reading before integrating.

`reset_password` takes the emailed token as **`token`**, not
`reset_password_token`. A wrong parameter name produces a 422 that reads
identically to an expired token.

`GET .../auth/mfa/backup_codes` returns a **count, not the codes**. Backup
codes are stored as digests, so the raw codes exist only in the response that
generated them -- `mfa/enable` and `mfa/regenerate_backup_codes`. A store that
can show you your codes can also show them to whoever reads the database. This
differs on purpose from an application that keeps its own codes in plaintext.

The password grant is deliberately **not** advertised in the discovery
document. OAuth 2.1 removes it and the Security BCP advises against it, so the
credential endpoints are a plain API that is honest about not being OAuth
rather than an advertised deprecated grant.

## Status

Running. What works:

- **Realms and isolation.** Email is unique per realm, on `[realm_id,
  lower(email)]` -- never globally, which is what a `rails g devise` would have
  produced and what would make the second realm's signup fail.
- **The credential API** above, including MFA step-up on sign-in.
- **MFA**: TOTP with clock drift, and single-use backup codes stored as digests.
- **RS256 signing and JWKS publication.** A token verifies against a key
  rebuilt from the published `n` and `e`; no private component is ever emitted.
- **Lockable**, always on, with `unlock_strategy: :both` -- an email unlock link
  *and* automatic expiry, because lockable alone hands an attacker a
  lockout denial-of-service against a central server.
- **Confirmable**, per realm, defaulting to on.
- **Rate limiting** on sign-in, sign-up, password reset and confirmation resend,
  keyed on IP *and* email -- either alone is sidestepped by rotating the other.
  Signup is paired the same way rather than limited by IP alone, because a
  church hall, an office or a school is one public address and a per-IP limit is
  a limit on the whole building.

  A limited request answers **429 with a JSON body** and a `Retry-After` header
  carrying the window. Rails' default is a bare status with no body, which a
  client parsing JSON unconditionally reads as a parse error rather than a rate
  limit.
- **Password rules**: a 12-character minimum and a **72-byte** maximum, checked
  in bytes because bcrypt truncates there while Rails' length validator counts
  characters.
- **CORS** per client, from an origin allowlist on the client's registration.
- **Central session management.** Every accepted credential leaves a session
  row, so the list spans every application and device rather than showing only
  the app you happen to be looking at -- which is what no application could do
  alone, because none of them can see the others. One call revokes them all.
  `sign_out` revokes the session its own token was minted from. Refresh tokens
  are stored as digests and are audience-scoped, so one leaked from one
  application is not redeemable at another.

What is missing, and should not be assumed:

- **Revocation of an ACCESS token is eventual**, bounded by its fifteen-minute
  life. Revoking a session stops the refresh token immediately, but an access
  token already issued stays valid until it expires -- that is the price of
  offline verification, and it is the trade this design took deliberately.

- **Client registration is console-only.** There is no admin interface.
- **No federated or social login**, which would require a redirect flow and a
  view layer this server deliberately does not have.
- **No SAML, SCIM, device flows, or audit log**, all of which exist in
  established identity servers and do not exist here.
- **No independent security review.**
