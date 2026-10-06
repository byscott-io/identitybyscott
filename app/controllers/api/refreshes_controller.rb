# frozen_string_literal: true

module Api
  # Exchanges a refresh token for a fresh access token.
  #
  # Unauthenticated by design: the refresh token IS the credential, and an
  # expired access token is exactly the state this endpoint exists to recover
  # from -- requiring a valid one would make it useless.
  class RefreshesController < BaseController
    include IssuesSessions

    # The refresh token is a long-lived bearer credential, so guessing attempts
    # are worth throttling even though the space is 256 bits.
    rate_limit to: 20, within: 1.minute, by: -> { request.remote_ip },
               with: -> { rate_limited!(retry_after: 1.minute) }

    def create
      session = Session.authenticate(params[:refresh_token], client: Current.client)

      # One response for unknown, revoked, expired and wrong-client. Telling
      # them apart would say whether a token was ever real, and whether it was
      # revoked -- which is a revocation oracle.
      return render_invalid_refresh if session.nil?

      # Re-checked on every refresh, not only at sign-in. Otherwise revoking
      # a grant would leave an existing session minting fresh access tokens
      # for up to the refresh token's 30 days -- the grant would be gone and
      # the access would not.
      #
      # Answered as an invalid refresh rather than 403: this caller holds a
      # token, not a password, and the application's response to either is
      # the same -- send the person back to sign in, where the 403 explains
      # itself.
      unless Grant.permits?(identity: session.identity, client: Current.client)
        return render_invalid_refresh
      end

      session.touch_used!

      issuer = TokenIssuer.new(
        identity: session.identity, client: Current.client, session: session
      )

      render json: {
        access_token: issuer.access_token,
        token_type: "Bearer",
        expires_in: TokenIssuer::ACCESS_TOKEN_TTL.to_i
      }
    end

    private

    # The refresh token is deliberately NOT rotated here.
    #
    # Rotation detects a stolen token by failing when both copies are used, but
    # it also breaks every client that retries a request, races two tabs, or
    # loses the response to a dropped connection -- each of which silently logs
    # a real person out. Revocation is central and immediate for refresh, so the
    # window a stolen token buys is bounded by that rather than by rotation.
    # Worth revisiting with replay detection, not before.
    def render_invalid_refresh
      render json: { error: "Invalid or expired refresh token" }, status: :unauthorized
    end
  end
end
