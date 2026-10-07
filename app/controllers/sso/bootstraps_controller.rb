# frozen_string_literal: true

module Sso
  # POST /sso/bootstrap -- establishes the SSO cookie, then sends the browser back.
  #
  # Reached by a TOP-LEVEL FORM SUBMISSION from the application, which is the
  # entire point. This server is on a different registrable domain from every
  # application it serves, so a cookie it sets in reply to a cross-site
  # subresource request is refused or partitioned by the browser; one it sets
  # during a top-level navigation to itself is first-party and visible to every
  # application in the realm. See SsoBootstrap.
  #
  # == Why a POST, and why the Origin check is not optional
  #
  # This endpoint plants a realm-wide session in whatever browser performs the
  # navigation. The token alone cannot establish who that browser should be: an
  # attacker can sign in to THEIR OWN account server-side -- where
  # Api::BaseController#enforce_origin! deliberately does not apply, since a
  # caller with no Origin is not a browser -- and obtain a perfectly valid
  # bootstrap token for their own identity.
  #
  # If this were a GET, they could then put that token in a link, and any victim
  # who followed it would be holding a twelve-hour cookie for the ATTACKER'S
  # identity: silently signed in to real applications as somebody else, with
  # everything they subsequently typed going into the attacker's account. That is
  # login CSRF, or session fixation, and it is a materially worse thing than the
  # risk /sso/authorize reasons about -- that comment assumes the cookie already
  # belongs to the victim, which is exactly what this endpoint decides.
  #
  # A POST closes it, because the browser attaches an Origin header to a
  # top-level POST and attaches none to a GET navigation. Script cannot forge
  # it, and unlike Referer it cannot be suppressed by a referrer policy. So the
  # navigation must demonstrably come from a page on an origin the issuing
  # application registered, which is the same browser-facing boundary the
  # credential endpoints already rest on.
  #
  # RESIDUAL RISK, stated rather than implied: script running ON a registered
  # origin could still do this, so an XSS in any application in the realm can
  # plant a session. That is the same limit Client#allowed_origins_list already
  # documents about itself, and it is a far narrower thing than one link. The
  # durable fix is for credentials to be submitted in a first-party context in
  # the first place, which would remove this endpoint entirely; it is recorded
  # on the tracking issue rather than pretended away.
  class BootstrapsController < ApplicationController
    include SsoCookie

    rate_limit to: 30, within: 1.minute, by: -> { request.remote_ip },
               with: -> { render json: { error: "Too many requests" }, status: :too_many_requests }

    # Ordering, as at /authorize, is the security property.
    #
    # The token is spent FIRST, before anything else is looked at, so no refusal
    # can be retried -- same reasoning as the code exchange, since this token
    # establishes a realm-wide session and must be single-ATTEMPT. A legitimate
    # application whose origin or return_to is misconfigured therefore burns a
    # token per attempt, which is the right way round: it fails loudly at
    # integration time rather than leaving a replayable credential.
    #
    # Then the Origin, then return_to, and nothing is redirected until both
    # hold. The cookie is issued last, so a refused request leaves no session.
    def create
      bootstrap = SsoBootstrap.consume!(submitted["token"])
      return render_refused("unknown or spent token") if bootstrap.nil?

      # The issuing application's allowlist, not any application's: the token
      # names which application signed this person in, and only that one's pages
      # may complete it.
      origin = request.headers["Origin"]
      if origin.blank? || !bootstrap.client.origin_allowed?(origin)
        return render_refused("origin not allowed")
      end

      return_to = submitted["return_to"].to_s
      unless bootstrap.client.redirect_uri_allowed?(return_to)
        return render_refused("unregistered return_to")
      end

      # The realm could have had single sign-on turned off in the minute since
      # the token was issued, and this is the request that would otherwise hand
      # out the cookie anyway. issue_sso_cookie! checks the flag too; this makes
      # the refusal explicit rather than a silent no-op followed by a redirect
      # that looks successful.
      return render_refused("sso not enabled for realm") unless bootstrap.identity.realm.sso?

      issue_sso_cookie!(bootstrap.identity, link_session: bootstrap.session)

      redirect_to return_to, allow_other_host: true, status: :see_other
    end

    private

    # request.request_parameters -- the POST body, named explicitly, for the same
    # reason /authorize names the query string: a security property must not rest
    # on `params` merging path, query and body in whatever order it happens to.
    # Here it matters more than usual, because a token accepted from the QUERY
    # string would be one that could travel in a link again, which is the whole
    # thing this endpoint being a POST is meant to prevent.
    def submitted
      @submitted ||= request.request_parameters
    end

    # A plain 400, never a redirect: every refusal above happens before a
    # return_to is trusted, so there is nowhere safe to send the browser.
    #
    # Uniform body, reason logged, as at /authorize. A caller who can tell a
    # spent token from an unregistered return_to learns which half they got
    # right.
    def render_refused(reason)
      Rails.logger.info("[identity] /sso/bootstrap refused: #{reason}")

      render json: { error: "invalid_request" }, status: :bad_request
    end
  end
end
