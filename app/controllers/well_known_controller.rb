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

      # Single sign-on. Advertised because it exists and works; there is
      # deliberately no token_endpoint yet, because the code exchange is the
      # next slice and claiming an endpoint that 404s is worse than omitting
      # one.
      authorization_endpoint: "#{issuer}/sso/authorize",
      response_types_supported: [ "code" ],
      response_modes_supported: [ "query" ],

      # S256 only, and required rather than optional. `plain` carries the
      # verifier alongside the code it is meant to protect.
      code_challenge_methods_supported: [ AuthorizationCode::CHALLENGE_METHOD ],

      # none and login, and nothing else -- NOT because the others are
      # unimplemented but because this server has no hosted login page and no
      # HTML, so it cannot prompt at all. /authorize either answers from an
      # existing realm session or returns login_required for the application to
      # handle with its own form. Saying so here is the honest thing: a client
      # that expects to force a prompt should learn otherwise from discovery.
      prompt_values_supported: %w[none login],
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
