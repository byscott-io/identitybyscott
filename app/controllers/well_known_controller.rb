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

      # Single sign-on.
      #
      # There is no token_endpoint here even though the code exchange exists,
      # and that is not an omission to fix later. OIDC publishes ONE
      # token_endpoint, and this server's is per-application
      # (/api/apps/:client_id/auth/token) because a CORS preflight can see only
      # the URL, so the client has to be in the path for the origin check that
      # protects every other credential endpoint to work there too.
      #
      # One URL would mean giving that check up. Publishing a URL with a
      # placeholder in it, or one that 404s, would be worse than saying nothing.
      # So the authorization endpoint is advertised, the token endpoint is
      # documented, and discovery stays honest about being partial -- which it
      # already is, since the credential endpoints are this server's own API
      # rather than OAuth grants.
      authorization_endpoint: "#{issuer}/sso/authorize",
      response_types_supported: [ "code" ],
      response_modes_supported: [ "query" ],

      # S256 only, and required rather than optional. `plain` carries the
      # verifier alongside the code it is meant to protect.
      code_challenge_methods_supported: [ AuthorizationCode::CHALLENGE_METHOD ],

      # none and login. Both are genuinely implemented: prompt=none answers
      # from an existing realm session or returns login_required without a
      # form, and prompt=login skips the cookie and goes straight to the
      # hosted login page.
      #
      # consent and select_account are NOT advertised because there is no
      # consent screen and no account picker here -- a client that expects
      # either should learn otherwise from discovery rather than from a
      # redirect that silently did something else.
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
