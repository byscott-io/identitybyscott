# frozen_string_literal: true

# The one place the single sign-on cookie is set and cleared.
#
# This server is otherwise cookie-free and deliberately so -- see the "API only"
# rule. This is the single exception, and it is kept to one file so the
# attributes below are stated once rather than copied to a second caller and
# quietly weakened there.
#
# NOTHING READS THIS COOKIE. No controller consults it, no request is
# authenticated by it, and `/authorize` does not exist. It is issued now so its
# shape, lifetime and revocation are settled before anything depends on them.
module SsoCookie
  extend ActiveSupport::Concern

  included do
    # api_only drops the cookie middleware, so it is added back in
    # config/application.rb. This brings the `cookies` accessor into the
    # controllers that need it -- and ONLY those, which is why it is here rather
    # than in BaseController.
    include ActionController::Cookies
  end

  # Not prefixed `__Host-`, which would otherwise be the obvious choice.
  #
  # That prefix is a browser-ENFORCED guarantee of Secure, host-only and no
  # Domain -- all of which we want -- but it also mandates `Path=/`, and the
  # path restriction below is worth more than the prefix. A cookie the browser
  # never attaches to a credential endpoint cannot be misused by one.
  # ONE COOKIE PER REALM, named for it.
  #
  # A single shared name would give every realm one slot on this host, and the
  # second realm's sign-in would evict the first's. Not a leak -- /authorize
  # refuses a cookie whose identity belongs to another realm and shows the form
  # instead -- but single sign-on would silently stop working for whichever
  # realm a browser touched least recently, which is worse than failing loudly.
  #
  # Both cookies are sent on every request here, since they share this host and
  # path. The server reads only the one belonging to the client's realm, which
  # it always knows first: /authorize validates client_id and loads the Client
  # before it touches a cookie, and the login page carries the client in its
  # signed authorization payload.
  #
  # Realm keys are validated as /\A[a-z0-9][a-z0-9_-]*\z/, so they are already
  # safe in a cookie name without escaping.
  COOKIE_PREFIX = "identity_sso_"

  # The keys a realm may contribute to a cookie name. Deliberately the same
  # shape Realm validates, restated here because that validation is model-level:
  # update_column and raw SQL both bypass it, and this is the one place a key
  # becomes part of an HTTP header.
  #
  # Rack already refuses a malformed cookie name, so a bad key fails closed with
  # an ArgumentError rather than injecting header content. This checks anyway, so
  # the failure names the realm and the reason instead of surfacing as "invalid
  # cookie key" from inside Rack.
  SAFE_KEY = /\A[a-z0-9][a-z0-9_-]*\z/

  def self.cookie_name(realm)
    raise ArgumentError, "a realm is required to name the single sign-on cookie" if realm.nil?

    key = realm.key.to_s
    unless key.match?(SAFE_KEY)
      raise ArgumentError, "realm #{realm.id.inspect} has a key that cannot be used in a cookie name"
    end

    "#{COOKIE_PREFIX}#{key}"
  end

  # Everything under here, and nothing else, ever sees this cookie.
  #
  # The browser decides what to attach based on path, so scoping it away from
  # `/api` is not a convention this code has to keep remembering -- the cookie
  # is simply absent from every credential request, every token request and
  # every authenticated API call. That is why the SSO surface gets its own
  # prefix instead of living at `/authorize`: `end_session` has to see the same
  # cookie, so both need one common path.
  COOKIE_PATH = "/sso"

  private

  # The session the presented cookie names, or nil.
  #
  # Only /authorize calls this, and only because the cookie's path scope means
  # only /authorize ever receives the cookie. Nothing under app/controllers/api
  # may call it -- a spec enforces that by grepping the directory.
  #
  # Realm-wide is not realm-agnostic: this returns a session for an identity in
  # SOME realm, and the caller must check that realm against the client it is
  # answering. SsoSession.authenticate deliberately takes no client for that
  # reason.
  # Takes the realm rather than searching, so a caller cannot accidentally read
  # some other realm's session. There is deliberately no "find any session"
  # variant: every question about a browser's session is a question about one
  # realm.
  def sso_session_from_cookie(realm)
    SsoSession.authenticate(cookies[SsoCookie.cookie_name(realm)])
  end

  # Issues the realm-wide browser session, but only where the realm asked for
  # one. A realm with sso_enabled false never gets this cookie at all, which is
  # what makes the flag a real control rather than a hint.
  def issue_sso_cookie!(identity)
    return unless identity.realm.sso?

    sso_session, raw = SsoSession.issue!(identity: identity, request: request)

    cookies[SsoCookie.cookie_name(identity.realm)] = sso_cookie_attributes.merge(
      value: raw,

      # An explicit expiry, matching the row's. A session cookie (no expiry)
      # would outlive the row whenever a browser restores tabs, leaving a value
      # that is presented and rejected rather than one that is gone.
      expires: SsoSession::SSO_SESSION_TTL.from_now
    )

    # Returned so a caller can bind what it issues to this browser session --
    # the hosted login page binds the authorization code it mints to it.
    sso_session
  end

  # Revokes every live SSO session for this identity and clears the cookie.
  #
  # Coarse on purpose, for now: the cookie is not readable here -- a sign-out
  # arrives as an XHR to /api, which this cookie's path keeps it away from -- so
  # the row for THIS browser cannot be singled out. Revoking all of them signs
  # the identity out of the realm everywhere, including on another device.
  #
  # That errs toward asking for a password, which is the right direction to err,
  # and it can be narrowed once /authorize can match the presented cookie to its
  # row. The alternative -- leaving the realm session alive -- would make
  # signing out of an application decorative: the application would redirect to
  # /authorize, the cookie would still be good, and the person would be silently
  # signed straight back in.
  def revoke_sso_sessions!(identity)
    revoked = identity.sso_sessions.active.to_a
    revoked.each(&:revoke!)

    # response.delete_cookie, NOT cookies.delete.
    #
    # The cookie jar's delete begins `return unless @cookies.has_key?(name)` --
    # it only clears a cookie the REQUEST carried. This request never carries
    # it: sign-out arrives at /api, and COOKIE_PATH deliberately keeps the
    # cookie away from there. So the jar would silently do nothing, and the
    # browser would keep holding a value until it expired on its own.
    #
    # Writing the header directly clears it regardless. The path has to match
    # the one it was set with, or the browser keeps the original and the
    # deletion only shadows it at a different path.
    # Only this realm's cookie. Signing out of one realm says nothing about the
    # others, and the rows revoked above are this identity's, which belong to
    # exactly one realm.
    response.delete_cookie(SsoCookie.cookie_name(identity.realm), path: COOKIE_PATH)

    revoked.length
  end

  def sso_cookie_attributes
    {
      # No JavaScript, ever. An XSS in any application in the realm must not be
      # able to read a credential that authenticates at all the others.
      httponly: true,

      # Never over plain HTTP. Relaxed only for local development and test,
      # which have no TLS -- if this were unconditional the specs could not
      # observe the cookie at all, and a false `secure` in production is the
      # kind of thing that is only noticed by someone intercepting traffic.
      secure: !Rails.env.local?,

      # The property the whole flow depends on, in both directions.
      #
      # Lax means the browser DOES attach this cookie to a top-level navigation
      # arriving from another site, which is exactly how /authorize gets reached
      # and the only reason single sign-on can work at all. It also means the
      # cookie is NOT attached to a cross-site fetch, XHR or iframe -- so the
      # SSO surface cannot be driven silently from someone else's page.
      #
      # Never None. That would hand this credential to any site that embeds us.
      same_site: :lax,

      path: COOKIE_PATH

      # No `domain`, so the cookie is host-only. Setting a parent domain would
      # broadcast the realm's credential to every sibling host under it, and
      # applications in a realm are not trusted with each other's cookies --
      # they are trusted with audience-scoped tokens, which is a far narrower
      # thing.
    }
  end

  # Deliberately NOT a signed or encrypted cookie.
  #
  # The value is already 256 bits of randomness whose SHA-256 digest is the
  # lookup key, so a signature would add nothing -- an attacker cannot forge a
  # digest that matches a row. What it would REMOVE is the thing that matters:
  # a signed cookie is self-contained and therefore valid until it expires,
  # whatever the database says. Revocation has to actually revoke, so the
  # server-side row is the authority and the cookie is just a pointer to it.
end
