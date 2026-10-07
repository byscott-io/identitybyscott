# frozen_string_literal: true

require "rails_helper"

# POST /api/apps/:client_id/auth/token -- redeeming an authorization code.
#
# The other half of /sso/authorize, and the point at which single sign-on
# actually produces a session. Most of these specs go the whole way round --
# authorize, then exchange -- because the properties worth proving are about the
# two halves agreeing: a code is bound to the client, the redirect_uri, the PKCE
# challenge and the browser session it came from, and the exchange has to
# reproduce every one of them.
RSpec.describe "POST /api/apps/:client_id/auth/token" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: true) }
  let(:callback) { "https://app.example.com/auth/callback" }
  let(:client) do
    create(:client, realm: realm, redirect_uris: callback,
                    allowed_origins: "https://app.example.com")
  end
  let!(:identity) do
    create(:identity, realm: realm, signup_client: client, confirmed_at: Time.current)
  end

  let(:verifier) { SecureRandom.urlsafe_base64(64) }
  let(:challenge) do
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(verifier), padding: false)
  end

  around do |example|
    ENV["IDENTITY_SIGNING_KEY"] = signing_key.to_pem
    ENV["IDENTITY_ISSUER"] = "https://identity.test"
    SigningKeys.reset!
    example.run
  ensure
    ENV.delete("IDENTITY_SIGNING_KEY")
    ENV.delete("IDENTITY_ISSUER")
    SigningKeys.reset!
  end

  def origin = { "Origin" => "https://app.example.com" }

  # The real round trip: a browser with a realm session hits /authorize and the
  # code comes back in the Location.
  def code_from_authorize(for_identity: identity, app: client, uri: callback)
    _session, raw = SsoSession.issue!(identity: for_identity)
    cookies[SsoCookie::COOKIE_NAME] = raw

    get "/sso/authorize", params: {
      client_id: app.client_id, redirect_uri: uri, response_type: "code",
      state: "s", code_challenge: challenge, code_challenge_method: "S256"
    }

    URI.decode_www_form(URI.parse(response.headers["Location"]).query).to_h.fetch("code")
  end

  def exchange(app: client, **overrides)
    post "/api/apps/#{app.client_id}/auth/token",
         params: {
           grant_type: "authorization_code",
           code: overrides.fetch(:code, nil),
           code_verifier: overrides.fetch(:code_verifier, verifier),
           redirect_uri: overrides.fetch(:redirect_uri, callback)
         }.merge(overrides.except(:code, :code_verifier, :redirect_uri)),
         headers: origin
    response.parsed_body
  end

  describe "the whole round trip" do
    it "turns a code into a working session" do
      code = code_from_authorize
      body = exchange(code: code)

      expect(response).to have_http_status(:ok)
      expect(body["access_token"]).to be_present
      expect(body["refresh_token"]).to be_present
      expect(body["token_type"]).to eq("Bearer")
    end

    # The same token fields sign_in returns, so the client library needs no new
    # handling for a single-sign-on login.
    #
    # The ONE deliberate difference is the bootstrap fields: sign_in offers a way
    # to establish the realm session, and the exchange does not, because a
    # browser redeeming a code demonstrably already holds the cookie. Asserted as
    # an exact difference rather than ignored, so neither side can drift.
    it "answers in the same shape as signing in, minus the bootstrap fields" do
      code = code_from_authorize
      sso_keys = exchange(code: code).keys

      post "/api/apps/#{client.client_id}/auth/sign_in",
           params: { email: identity.email, password: "correct horse battery staple" },
           headers: origin
      sign_in_keys = response.parsed_body.keys

      expect(sign_in_keys - sso_keys).to eq(%w[sso_bootstrap_token sso_bootstrap_expires_in])
      expect(sso_keys - sign_in_keys).to be_empty
    end

    it "offers no bootstrap token, because the browser already holds the cookie" do
      code = code_from_authorize

      body = exchange(code: code)

      expect(body).not_to have_key("sso_bootstrap_token")
      expect(SsoBootstrap.count).to eq(0)
    end

    it "mints a token the application can actually verify" do
      code = code_from_authorize
      token = exchange(code: code)["access_token"]

      payload, = JWT.decode(token, signing_key.public_key, true,
                            algorithm: "RS256", verify_aud: true,
                            aud: client.client_id, iss: "https://identity.test",
                            verify_iss: true)

      expect(payload["sub"]).to eq(identity.id)
      expect(payload["realm"]).to eq(realm.key)
    end

    it "records a session the identity can see and revoke" do
      code = code_from_authorize

      expect { exchange(code: code) }.to change { identity.sessions.active.count }.by(1)
    end

    # The realm session is NOT re-issued. Doing so would turn SsoSession's
    # absolute twelve-hour lifetime into a sliding one, pushed out every time
    # the person opened another application -- so it would never expire for an
    # active browser, which is the opposite of why that number was chosen.
    it "does not re-issue or extend the realm session" do
      code = code_from_authorize
      session = identity.sso_sessions.active.sole
      original_expiry = session.expires_at

      expect { exchange(code: code) }.not_to change(SsoSession, :count)
      expect(session.reload.expires_at).to eq(original_expiry)
    end

    it "sets no cookie on the exchange" do
      code = code_from_authorize

      exchange(code: code)

      names = Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
      expect(names).to be_empty
    end
  end

  # Every failure below answers identically. Telling them apart would say which
  # part a caller had right, and "was this code ever real?" is exactly what
  # somebody holding a leaked URL would ask.
  describe "refusals" do
    def expect_invalid_grant
      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body).to eq({ "error" => "invalid_grant" })
    end

    it "refuses an unknown code" do
      exchange(code: SecureRandom.urlsafe_base64(32))

      expect_invalid_grant
    end

    it "refuses a blank code" do
      exchange(code: nil)

      expect_invalid_grant
    end

    # THE single-use property, end to end.
    it "refuses a code that has already been redeemed" do
      code = code_from_authorize
      exchange(code: code)

      exchange(code: code)

      expect_invalid_grant
    end

    it "issues no second session on a replay" do
      code = code_from_authorize
      exchange(code: code)

      expect { exchange(code: code) }.not_to change(Session, :count)
    end

    it "refuses an expired code" do
      code = code_from_authorize
      AuthorizationCode.last.update_column(:expires_at, 1.second.ago)

      exchange(code: code)

      expect_invalid_grant
    end

    # Bound to the client, like the access token's audience. A code issued for
    # one application must not be redeemable by another in the same realm.
    it "refuses a code issued for another application" do
      other = create(:client, realm: realm, redirect_uris: callback,
                              allowed_origins: "https://app.example.com")
      identity.grants.create!(client: other)
      code = code_from_authorize

      exchange(app: other, code: code)

      expect_invalid_grant
    end

    it "refuses a redirect_uri other than the one the code was issued for" do
      client.update!(redirect_uris: "#{callback}\nhttps://app.example.com/other")
      code = code_from_authorize

      exchange(code: code, redirect_uri: "https://app.example.com/other")

      expect_invalid_grant
    end

    # PKCE. Without this a stolen code is redeemable by whoever stole it, which
    # is the entire reason the challenge is required at /authorize.
    it "refuses a wrong PKCE verifier" do
      code = code_from_authorize

      exchange(code: code, code_verifier: SecureRandom.urlsafe_base64(64))

      expect_invalid_grant
    end

    it "refuses a missing PKCE verifier" do
      code = code_from_authorize

      exchange(code: code, code_verifier: nil)

      expect_invalid_grant
    end

    # The challenge is the hash of the verifier, so sending the challenge back
    # is what someone who had only seen the authorize URL would try.
    it "refuses the challenge presented as the verifier" do
      code = code_from_authorize

      exchange(code: code, code_verifier: challenge)

      expect_invalid_grant
    end

    # Signing out has to reach a code already in flight, or there is a minute
    # in which a revoked session still yields a working token.
    it "refuses a code whose realm session was revoked" do
      code = code_from_authorize
      identity.sso_sessions.each(&:revoke!)

      exchange(code: code)

      expect_invalid_grant
    end

    # Revocable in the window between authorize and exchange. Small, not zero.
    it "refuses a code whose grant was revoked in the meantime" do
      code = code_from_authorize
      identity.grants.destroy_all

      exchange(code: code)

      expect_invalid_grant
    end

    it "issues no session for any refusal" do
      code = code_from_authorize

      expect {
        exchange(code: SecureRandom.urlsafe_base64(32))
        exchange(code: code, code_verifier: "wrong")
      }.not_to change(Session, :count)
    end

    it "refuses a grant_type it does not implement" do
      code = code_from_authorize

      exchange(code: code, grant_type: "password")

      expect(response).to have_http_status(:bad_request)
      expect(response.parsed_body).to eq({ "error" => "unsupported_grant_type" })
    end

    # Burned on the attempt, not on success. A code that survived a failed
    # redemption would be one an attacker could keep trying things against;
    # single-use is meant to be single-ATTEMPT.
    it "spends the code even when the verifier is wrong" do
      code = code_from_authorize
      exchange(code: code, code_verifier: SecureRandom.urlsafe_base64(64))

      exchange(code: code)

      expect_invalid_grant
    end
  end

  # This endpoint sits behind the same origin allowlist as every other
  # credential endpoint -- which is the reason it lives under /api with the
  # client in the path rather than at a single /sso/token URL.
  describe "the origin allowlist still applies" do
    it "refuses an origin the client has not registered" do
      code = code_from_authorize

      post "/api/apps/#{client.client_id}/auth/token",
           params: { grant_type: "authorization_code", code: code,
                     code_verifier: verifier, redirect_uri: callback },
           headers: { "Origin" => "https://attacker.test" }

      expect(response).to have_http_status(:forbidden)
    end

    it "answers a preflight for a registered origin" do
      process :options, "/api/apps/#{client.client_id}/auth/token", headers: origin

      expect(response).to have_http_status(:no_content)
      expect(response.headers["Access-Control-Allow-Origin"]).to eq("https://app.example.com")
    end

    it "refuses a preflight from an unregistered origin, stopping the real request" do
      process :options, "/api/apps/#{client.client_id}/auth/token",
              headers: { "Origin" => "https://attacker.test" }

      expect(response).to have_http_status(:forbidden)
    end

    it "echoes the allowed origin on a successful exchange" do
      code = code_from_authorize

      exchange(code: code)

      expect(response.headers["Access-Control-Allow-Origin"]).to eq("https://app.example.com")
    end
  end
end
