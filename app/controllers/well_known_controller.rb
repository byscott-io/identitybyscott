# frozen_string_literal: true

# Unauthenticated discovery documents.
class WellKnownController < ApplicationController
  # GET /.well-known/jwks.json
  #
  # The PUBLIC half of this server's signing keys, so applications can verify
  # its tokens without being able to mint any.
  def jwks
    expires_in 1.hour, public: true
    render json: SigningKeys.jwk_set
  rescue SigningKeys::ConfigurationError => e
    # 503, not 500: this endpoint is unauthenticated, so a crash here is a
    # public error page. 503 tells a fetching verifier to retry, which is right
    # -- the fault is ours and fixable. The message names configuration, so it
    # is logged rather than rendered.
    Rails.logger.error("[identity] Cannot publish JWKS: #{e.message}")
    render json: { error: "Key set unavailable" }, status: :service_unavailable
  end

  # GET /.well-known/openid-configuration
  def openid_configuration
    issuer = ENV.fetch("IDENTITY_ISSUER", request.base_url)

    render json: {
      issuer: issuer,
      jwks_uri: "#{issuer}/.well-known/jwks.json",
      id_token_signing_alg_values_supported: [ SigningKeys::ALGORITHM ],
      # Credential endpoints are this server's own API rather than OAuth grants.
      # The password grant is deliberately NOT advertised: OAuth 2.1 removes it
      # and the Security BCP advises against it, so claiming it would be
      # misleading about something this server does differently on purpose.
      token_endpoint_auth_methods_supported: [ "client_secret_post" ],
      subject_types_supported: [ "public" ],
      scopes_supported: %w[openid profile email],
      service_documentation: "#{issuer}/docs"
    }
  end
end
