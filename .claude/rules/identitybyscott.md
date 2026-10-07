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

## API only, plus the hosted login page

`config.api_only = true`, no session store and no flash. Every credential
endpoint is `ActionController::API` and stateless.

**Do not add a Rails session or a flash.** Rails' CSRF keys its token to a
session, so reaching for `protect_from_forgery` would put an ambient credential
on every path here — which is what the uniform-failure and no-CSRF reasoning
elsewhere rests on. `DoubleSubmitCsrf` does the job with one cookie instead.

### HTML exists, for the login page and nothing else

This was forbidden outright while apps owned their forms. It changed because
that design leaves the password field in an **application's** origin, and then
that application's XSS steals the **credential**, not a session. No token
binding fixes it — script on a registered origin can do whatever the real page
can — and an embedded form does not either: an iframe stops script *reading* the
field but not drawing a convincing fake over it. Only a top-level page on this
server's origin fixes both, because only it gives somebody an **address bar** to
check who is asking.

So HTML is permitted **only** under `app/views/sso` and `app/views/layouts/sso`,
and an architecture spec enforces that.

**The page carries NO JavaScript, and that is what makes this acceptable.** It
ships `script-src 'none'`, so views created no XSS surface in the process
holding the signing key and every password hash. Never add script to it — not a
helper, not an analytics tag, not an inline handler. A spec greps the views for
it.

Also fixed by specs, and all load-bearing: `frame-ancestors 'none'` (an embedded
login page cannot show whose it is), `form-action 'self'`, `default-src 'none'`,
`base-uri 'none'`, `img-src 'self'` with the logo served from here rather than a
remote URL, the one `<style>` block admitted by **nonce** rather than
`'unsafe-inline'`, `Referrer-Policy: no-referrer` so the authorize URL's `state`
and PKCE challenge never reach the application, and `Cache-Control: no-store`.

### Theming is tokens, never CSS, and never from the request

Appearance lives on the `Client` record — same principle as the realm. Anything
an application can put in a URL, anyone can put in a URL, and a login page
restyled by a link is one that can be made to look like something else.

`Theme` validates on the way in and `ThemeCss` re-checks on the way out, falling
back rather than emitting what it cannot recognise. The form, its fields and the
page structure are **not** themeable: apps control chrome, never the thing a
password is typed into.

### Two cookies, each written in exactly one place

| | |
|---|---|
| `SsoCookie` | the realm session. Read only by `/sso/authorize` |
| `DoubleSubmitCsrf` | the login form's token |

Each is `HttpOnly`, `Secure` outside local, path-scoped to `/sso`, and host-only
with no `Domain`. A writer anywhere else would be a second, unreviewed set of
those attributes, which is how one ends up subtly weaker than the other — a spec
enforces the single writer.

**The realm cookie is established only in reply to a credential submission from
that browser.** That is what makes session fixation structurally impossible
rather than mitigated: there is no token to transplant into somebody else's
browser. Never reintroduce a mechanism that *plants* a session — a bootstrap
token did exactly that and was reverted for it, and the review that found it is
worth re-reading before adding anything similar.

### The credential sequence lives in `CredentialCheck`

Two things ask whether a password gets somebody in — the API and the page. The
checks are **ordered** and the order is load-bearing: unknown address
indistinguishable from wrong password, a lock reported only after the password
verifies, the grant checked before any second factor. Do not inline that
sequence anywhere; a drifted copy would not look broken, it would just stop
asking something.


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
