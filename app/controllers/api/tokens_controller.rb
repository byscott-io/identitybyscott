# frozen_string_literal: true

module Api
  # POST /api/apps/:client_id/auth/token -- redeems an authorization code.
  #
  # The other half of /sso/authorize. The application lands on its callback with
  # a code in the URL and posts it here with the PKCE verifier it kept; it gets
  # back exactly what sign_in returns, so the client library needs no new
  # handling for a single-sign-on login.
  #
  # UNDER /api, not /sso, and that is the deliberate counterpart to /authorize
  # living at /sso. The deciding question in both cases is what a CORS preflight
  # can see:
  #
  #   * /authorize is a top-level navigation. No preflight happens, so there is
  #     no origin check to preserve, and discovery has to publish ONE
  #     authorization_endpoint -- so client_id goes in the query.
  #   * this is a cross-origin POST from the application's front end. A
  #     preflight DOES happen, and a refused one stops the real request being
  #     sent, which is a control this server already built. A preflight can see
  #     only the URL, so client_id has to be in the path to keep it.
  #
  # It also means the SSO cookie never reaches here: it is path-scoped to /sso,
  # so the browser does not attach it to this request at all.
  class TokensController < BaseController
    include IssuesSessions

    # A code is single-use and PKCE-bound, so guessing is not the threat;
    # hammering is. Keyed on the address, like the other unauthenticated
    # credential endpoints.
    rate_limit to: 30, within: 1.minute, by: -> { request.remote_ip },
               with: -> { rate_limited!(retry_after: 1.minute) }

    GRANT_TYPE = "authorization_code"

    def create
      return render_unsupported_grant unless params[:grant_type] == GRANT_TYPE

      # CONSUMED BEFORE THE VERIFIER IS CHECKED, deliberately.
      #
      # Whatever happens next, this code is now spent. If the verifier were
      # checked first, a failed check would leave the code live and redeemable,
      # and a code that survives a failed redemption is one an attacker may
      # keep trying things against. Burning it on any attempt makes single-use
      # mean single-ATTEMPT, which is the stronger property and what the OAuth
      # security guidance asks for.
      #
      # The cost is real and accepted: a client that posts a malformed verifier
      # loses the code and has to go round /authorize again. That is the right
      # way round -- a wasted redirect rather than a code left lying usable.
      code = AuthorizationCode.consume!(
        params[:code],
        client: Current.client,
        redirect_uri: params[:redirect_uri].to_s
      )
      return render_invalid_grant if code.nil?

      return render_invalid_grant unless code.verifies?(params[:code_verifier])

      # Re-checked here as well as at /authorize, for the same reason the
      # refresh endpoint re-checks it: a grant revoked in between must not still
      # yield a session. The window is a minute, which is small and not zero.
      unless Grant.permits?(identity: code.identity, client: Current.client)
        return render_invalid_grant
      end

      # sso_cookie: false. The realm session already exists -- this code was
      # minted from it and is bound to it -- so there is nothing to establish.
      #
      # More importantly, issuing one here would quietly convert the twelve-hour
      # absolute lifetime into a sliding one: every application a person opened
      # would push the realm session's expiry out again, and the bound window
      # that lifetime was chosen to provide would never close for an active
      # browser.
      render json: session_response(code.identity, sso_cookie: false)
    end

    private

    # ONE answer for every way a redemption can fail: an unknown code, one
    # already consumed, an expired one, one issued to another client or for
    # another redirect_uri, a bad verifier, a revoked browser session and a
    # revoked grant.
    #
    # Distinguishing them would say which of those a caller had got right, and
    # the useful version of that question -- "was this code ever real?" -- is
    # exactly what someone holding a leaked URL would ask.
    def render_invalid_grant
      render json: { error: "invalid_grant" }, status: :bad_request
    end

    def render_unsupported_grant
      render json: { error: "unsupported_grant_type" }, status: :bad_request
    end
  end
end
