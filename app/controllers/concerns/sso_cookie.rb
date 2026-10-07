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
  COOKIE_NAME = "identity_sso"

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
  def sso_session_from_cookie
    SsoSession.authenticate(cookies[COOKIE_NAME])
  end

  # Issues the realm-wide browser session, but only where the realm asked for
  # one. A realm with sso_enabled false never gets this cookie at all, which is
  # what makes the flag a real control rather than a hint.
  def issue_sso_cookie!(identity, link_session: nil)
    return unless identity.realm.sso?

    sso_session, raw = SsoSession.issue!(identity: identity, request: request)

    # The sign-in that led here, now that the realm session it belongs to
    # exists. This is what lets that application's later sign-out revoke THIS
    # browser's realm session rather than all of them -- a sign-out arrives at
    # /api and cannot see the cookie, so the link is the only identification.
    link_session&.update!(sso_session: sso_session)

    cookies[COOKIE_NAME] = sso_cookie_attributes.merge(
      value: raw,

      # An explicit expiry, matching the row's. A session cookie (no expiry)
      # would outlive the row whenever a browser restores tabs, leaving a value
      # that is presented and rejected rather than one that is gone.
      expires: SsoSession::SSO_SESSION_TTL.from_now
    )
  end

  # Revokes THIS browser's realm session and clears the cookie.
  #
  # The realm session has to go, or signing out of an application would be
  # decorative: it would redirect to /authorize, the cookie would still be good,
  # and the person would be signed straight back in without a password.
  #
  # But only this browser's. A sign-out arrives at /api and cannot see the
  # cookie -- the path scope keeps it away deliberately -- so the browser is
  # identified by the link recorded when the session was created, at the
  # bootstrap navigation or the code exchange. Before that link existed this
  # revoked every realm session the identity had, which signed them out on their
  # phone because they signed out on their laptop.
  #
  # Other applications on this browser keep their refresh tokens: the realm
  # session is nullified from them, not cascaded. What is gone is reaching a NEW
  # application without a password.
  #
  # Nothing to revoke is a normal outcome, not a failure -- a realm without
  # single sign-on, or a session predating the link. Signing out is idempotent
  # and the caller gets the same answer.
  def revoke_sso_session!(session)
    revoked = [ session&.sso_session ].compact.select(&:active?)
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
    response.delete_cookie(COOKIE_NAME, path: COOKIE_PATH)

    revoked.length
  end

  # Log out EVERYWHERE, which is the one case that should reach every browser.
  # Named separately so the narrow case above cannot be widened by accident.
  def revoke_all_sso_sessions!(identity)
    revoked = identity.sso_sessions.active.to_a
    revoked.each(&:revoke!)

    response.delete_cookie(COOKIE_NAME, path: COOKIE_PATH)

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
