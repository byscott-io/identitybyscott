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

GET    /api/apps/:client_id/auth/mfa
POST   /api/apps/:client_id/auth/mfa/setup
POST   /api/apps/:client_id/auth/mfa/enable
POST   /api/apps/:client_id/auth/mfa/disable
POST   /api/apps/:client_id/auth/mfa/regenerate_backup_codes

GET    /.well-known/jwks.json
GET    /.well-known/openid-configuration
```

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
- **Rate limiting** on sign-in, password reset and confirmation resend, keyed on
  IP *and* email -- either alone is sidestepped by rotating the other.
- **Password rules**: a 12-character minimum and a **72-byte** maximum, checked
  in bytes because bcrypt truncates there while Rails' length validator counts
  characters.
- **CORS** per client, from an origin allowlist on the client's registration.

What is missing, and should not be assumed:

- **Central session management.** Tokens expire; they cannot yet be revoked, and
  there is no sessions list. Until that exists, revocation is eventual rather
  than immediate -- so an application with real users should not depend on it.
- **Client registration is console-only.** There is no admin interface.
- **No federated or social login**, which would require a redirect flow and a
  view layer this server deliberately does not have.
- **No SAML, SCIM, device flows, or audit log**, all of which exist in
  established identity servers and do not exist here.
- **No independent security review.**
