# Working in identitybyscott

Only what is true while editing this repository, and only what prevents a real
error. Each of these has already been got wrong once, or would be easy to.

## This repository is PUBLIC

Published for transparency. Nothing may contain a secret, an internal hostname,
an IP address, a deploy user, an SSH key filename or any other infrastructure
detail — not in a file, not in a commit message, not in history.

`bin/check-public-safe` enforces it in three modes: `--staged` (pre-commit),
`--all` and `--history` (CI, which `--no-verify` cannot bypass), and `--message`
(commit-msg hook). A deliberate exception goes in `.public-safe-allow` with a
reason, which is reviewable; bypassing the check is not.

## It does not use corebyscott

Not the gem, not the npm package. Dependencies are declared directly.

This is deliberate: a broken release of the package whose auth this server
federates must not be able to take down login for every application at once,
and this process holds the private signing key and every password hash, so its
dependency list is a security property. The npm package is also unusable here —
it is served from a private registry, and a public repository must never hold a
token.

## API only, and exactly one cookie

`config.api_only = true`, `ActionController::API`, no session store and no
flash. The only views are mailer templates.

Do not add an HTML page, a Rails session or a flash. Applications render every
form — sign in, sign up, password reset, MFA prompts — and post credentials
here.

**The one cookie is the single sign-on session**, and it is confined on purpose:

- Set and cleared only in `SsoCookie`. One file, so its attributes are stated
  once and cannot be weakened by a copy somewhere else.
- **Established only at `/sso/bootstrap`, during a top-level navigation. Never
  in a reply to `sign_in`.** This looks like a pointless detour and is not. The
  applications are on their own registrable domains, so this server is a THIRD
  PARTY to all of them, and a cookie set in reply to a cross-site request is
  refused by Safari's tracking prevention and partitioned by Firefox's — filed
  under the application's own top-level site, where no other application in the
  realm can see it, which is the only thing single sign-on is for. Setting it at
  sign-in therefore *appears* to work in whichever browser it is first tried in
  and silently fails to do its job. A top-level navigation makes this server the
  top-level site, so the cookie is first-party and shared across the realm.
  `sign_in` hands back a one-use `sso_bootstrap_token` and the application
  navigates with it. This was got wrong once already.
- `path=/sso`, which is the load-bearing part. The browser decides what to
  attach by path, so the cookie is simply absent from every request under
  `/api` — not by a convention this code has to remember, but because the
  browser never sends it. **Nothing under `app/controllers/api` may read a
  cookie**, and a spec enforces that by grepping the directory.
- `HttpOnly`, `Secure` outside local, `SameSite=Lax`, no `Domain`. Lax is what
  lets `/authorize` work at all — it still rides a top-level navigation — and
  what stops the SSO surface being driven from a cross-site fetch or iframe.
  Never `None`.
- Opaque value, digest stored. Not a signed or encrypted cookie: a signed
  cookie is self-contained and so stays valid until it expires whatever the
  database says, and this credential has to be revocable.
- Revoked by `sign_out` and by log-out-everywhere. A realm session that
  survived sign-out would make sign-out decorative — the application would
  bounce through `/authorize` and be signed straight back in.

So the API still has **no ambient credential**, which is why it still needs no
CSRF token: a request to `/api` cannot carry anything but a bearer token the
caller attached deliberately.

`/authorize` is where that changes, and it is the thing to get right when it
lands. It will be reached by a top-level navigation carrying the cookie, so it
is the first endpoint here with an ambient credential. Its protection is not a
CSRF token but the shape of the flow: `SameSite=Lax`, a `redirect_uri` matched
exactly against the client's registered list, and the `state` the application
checks on the way back. It must stay a GET that mints a code for a registered
URI and nothing else — any state change behind that cookie is CSRF-able.

## Email is unique PER REALM, never globally

The same address is a different identity in each realm, with its own password
and MFA. The index is `[realm_id, lower(email)]`.

**Never add a global unique index on `email`.** It is what Devise generates and
what every consuming application carries, so it is the obvious wrong move: it
makes the second realm's signup fail on a uniqueness error.

**Never look up an identity by email without a realm.** Use
`Identity.find_for_authentication_in_realm`. Devise's own
`find_for_authentication` queries globally and would authenticate against the
wrong suite.

## The realm is never a request parameter

It is resolved from the `client_id` a request presents, against a `Client`
record held here. An application that could send `realm=church` could claim any
realm, and the isolation this whole design rests on would be decorative.

The token carries a `realm` claim so an application can *check* its own
registration. That direction only: this server states the realm, the
application may verify it.

## client_id is read from a NAMED source, never from `params`

Not from `params`, which merges path, query and body. Rails does give the path
precedence, so `params` happens to be correct — but a security property must not
rest on an implicit merge order.

On the credential endpoints it must also stay a path segment. A CORS preflight
carries only the `Origin`, the method and the *names* of requested headers — no
body, no header values — so the URL is the only part of a credential request a
preflight can see. Move `client_id` anywhere else and per-client origin checking
becomes impossible.

`/sso/authorize` is the exception, and reads `request.query_parameters`. Neither
half of the reason above applies to it: there is no preflight on a top-level
navigation, and it has no origin check at all, while discovery must publish ONE
`authorization_endpoint`, which a per-client path could not be. The principle
survives the exception — the source is still named, so nothing rests on
`params`' merge order — and an architecture spec asserts both halves.

## Failure responses are uniform, deliberately

Sign-in answers identically for a wrong password, an unknown address, and an
address that exists only in another realm. `forgot_password` always answers 202.
A lock is reported only *after* the password verifies.

Do not make these more helpful. Each would turn the endpoint into a way to ask
which realm an address belongs to — the exact cross-realm fact realms isolate —
and `forgot_password` is the easiest to abuse, since it needs no password.

`sign_up` is the one exception, and only where a realm does not require
confirmation: the caller is owed a token on success, so failure must be
distinguishable. Where confirmation is required, the address owner is emailed
instead of the caller being told.

## Tokens carry no container, membership or role claim

This server has no `memberships` table and cannot know which organisation
someone is acting in. A guessed container claim is a cross-tenant data leak
rather than an error. The application resolves that itself after mapping `sub`.

Claim names are the integration contract with the client library and must not be
renamed casually: `email`, `given_name`, `family_name`, `nickname`, `zoneinfo`.

## Every emailed link targets the APPLICATION, never this server

There are no forms here, so a link pointing at this server is a dead end. URLs
are built from the client's `app_base_url` and optional `url_templates`,
preferring the current request's client and falling back to the identity's
`signup_client` for a reset raised outside a request. `IdentityMailer` raises
rather than sending a link it cannot build.

## bcrypt truncates at 72 BYTES

Password length is validated in bytes, not characters, because Rails' `length`
validator counts characters and 25 multibyte characters is already 75 bytes. Two
passwords differing only after a 72-byte prefix verify against the same hash.

## Backup codes are digests, and are consumed on use

Stored as SHA-256 digests so a database dump yields no usable second factors,
and deleted when used — a reusable backup code is a permanent second factor that
cannot be revoked without regenerating the whole set.

## Do not advertise a password grant

`openid-configuration` lists `authorization_code` style metadata only. OAuth 2.1
removes the password grant and the Security BCP advises against it, so
advertising it would misrepresent something this server does differently on
purpose: credential endpoints here are a plain API, which is honest about not
being OAuth.

## Prove a spec can fail

The convention throughout: after writing a spec for a security property, break
the property and confirm the spec fails. Several real bugs here were found that
way, and at least two specs were vacuous until checked. A spec that cannot fail
is not evidence.
