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

## Status

Early. The data model and realm isolation are in place; the credential API, JWKS
publication and client registration are not yet.
