# frozen_string_literal: true

module Api
  # For endpoints that act on behalf of a signed-in identity.
  #
  # Verifies this server's own access token. It holds the private key, so it
  # could verify with that -- but it uses the public half deliberately, so this
  # path exercises exactly what a consuming application does and cannot drift
  # from it.
  class AuthenticatedController < BaseController
    before_action :authenticate_identity!

    private

    attr_reader :current_identity

    # The session this token was minted from, named by its sid claim.
    #
    # Scoped to the current identity as well as the id: a sid naming someone
    # else's session must resolve to nothing, or sign_out becomes a way to log an
    # arbitrary person out using a token of your own.
    #
    # nil is a legitimate answer -- a token minted without a session, such as by
    # a test helper, carries no sid, and nothing may assume one is present.
    def current_session
      return @current_session if defined?(@current_session)

      sid = @payload&.dig("sid")
      @current_session = sid.present? ? current_identity.sessions.find_by(id: sid) : nil
    end

    def authenticate_identity!
      token = bearer_token
      return render_unauthorized if token.blank?

      payload = decode(token)
      return render_unauthorized if payload.nil?

      @payload = payload

      # An MFA challenge is signed with the same key and would otherwise pass
      # every check here. It proves a correct password and nothing more, so
      # accepting one would make MFA skippable for every authenticated endpoint
      # -- including the one that disables MFA.
      return render_unauthorized if payload["purpose"].present?

      @current_identity = realm.identities.find_by(id: payload["sub"])
      render_unauthorized if @current_identity.nil?
    end

    def decode(token)
      JWT.decode(
        token, SigningKeys.private_key.public_key, true,
        algorithm: SigningKeys::ALGORITHM,
        iss: ENV.fetch("IDENTITY_ISSUER", nil), verify_iss: true,
        aud: Current.client.client_id, verify_aud: true
      ).first
    rescue JWT::DecodeError, SigningKeys::ConfigurationError
      nil
    end

    def bearer_token
      request.headers["Authorization"].to_s[/\ABearer (.+)\z/, 1]
    end

    def render_unauthorized
      render json: { error: "Unauthorized" }, status: :unauthorized
    end
  end
end
