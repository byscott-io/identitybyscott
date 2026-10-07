# frozen_string_literal: true

module Sso
  # GET /sso/bootstrap -- establishes the SSO cookie, then sends the browser back.
  #
  # Reached by a TOP-LEVEL NAVIGATION, which is the entire point. This server is
  # on a different registrable domain from every application it serves, so a
  # cookie it sets in response to a cross-site request is refused or partitioned
  # by the browser; one it sets during a navigation to itself is first-party and
  # visible to every application in the realm. See SsoBootstrap.
  #
  # The flow: an application signs someone in, receives a single-use
  # sso_bootstrap_token with the tokens, and immediately navigates here with it
  # and the URL to come back to.
  class BootstrapsController < ApplicationController
    include SsoCookie

    rate_limit to: 30, within: 1.minute, by: -> { request.remote_ip },
               with: -> { render json: { error: "Too many requests" }, status: :too_many_requests }

    # Ordering, as at /authorize, is the security property.
    #
    # The token is spent FIRST, before return_to is even looked at, so a failed
    # attempt cannot be retried -- same reasoning as the code exchange, since
    # this token establishes a realm-wide session and must be single-ATTEMPT.
    #
    # Then return_to is checked against the registered URIs of the application
    # that issued the token, and nothing is redirected until it matches. An open
    # redirect here would be one on an endpoint that has just set a credential
    # cookie.
    #
    # The cookie is issued only after both, so a refused return_to leaves no
    # session behind.
    def show
      bootstrap = SsoBootstrap.consume!(requested["token"])
      return render_refused("unknown or spent token") if bootstrap.nil?

      return_to = requested["return_to"].to_s
      unless bootstrap.client.redirect_uri_allowed?(return_to)
        return render_refused("unregistered return_to")
      end

      # Belt and braces: the realm could have had single sign-on turned off in
      # the minute since the token was issued, and this is the request that
      # would otherwise hand out the cookie anyway. issue_sso_cookie! checks the
      # flag too; this makes the refusal explicit rather than a silent no-op
      # followed by a redirect that looks successful.
      return render_refused("sso not enabled for realm") unless bootstrap.identity.realm.sso?

      issue_sso_cookie!(bootstrap.identity)

      redirect_to return_to, allow_other_host: true, status: :found
    end

    private

    # request.query_parameters, never `params` -- same reason as /authorize: a
    # security property must not rest on how path, query and body are merged.
    def requested
      @requested ||= request.query_parameters
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
