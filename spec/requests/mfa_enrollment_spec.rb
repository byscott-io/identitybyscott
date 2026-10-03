# frozen_string_literal: true

require "rails_helper"

# Enrolling and removing a second factor. These are the only AUTHENTICATED
# endpoints so far, so they also exercise access-token verification.
RSpec.describe "MFA enrollment" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false) }
  let(:client) { create(:client, realm: realm, allowed_origins: "https://app.example.com") }
  let(:password) { "correct horse battery staple" }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: client, email: "ada@example.com",
                      password: password, confirmed_at: Time.current)
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

  def access_token
    post "/api/apps/#{client.client_id}/auth/sign_in",
         params: { email: "ada@example.com", password: password },
         headers: { "Origin" => "https://app.example.com" }
    response.parsed_body["access_token"]
  end

  # Minted directly rather than by signing in, because once MFA is enabled
  # sign_in correctly returns a CHALLENGE instead of an access token -- which is
  # the whole point of it, and made an earlier version of these specs send
  # "Bearer " with nothing after it.
  def minted_token
    TokenIssuer.new(identity: identity, client: client).access_token
  end

  def authed(token = nil)
    { "Origin" => "https://app.example.com", "Authorization" => "Bearer #{token || minted_token}" }
  end

  def call(verb, path, token: nil, **params)
    public_send(verb, "/api/apps/#{client.client_id}/#{path}", params: params, headers: authed(token))
  end

  describe "access-token verification" do
    it "refuses a request with no token" do
      post "/api/apps/#{client.client_id}/auth/mfa/setup",
           headers: { "Origin" => "https://app.example.com" }

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses a token signed by another key" do
      stranger = OpenSSL::PKey::RSA.generate(2048)
      forged = JWT.encode({ sub: identity.id, iss: "https://identity.test",
                            aud: client.client_id, exp: 1.hour.from_now.to_i },
                          stranger, "RS256")

      call(:post, "auth/mfa/setup", token: forged)

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses a token minted for another client" do
      other = create(:client, realm: realm, allowed_origins: "https://app.example.com")
      wrong_aud = TokenIssuer.new(identity: identity, client: other).access_token

      call(:post, "auth/mfa/setup", token: wrong_aud)

      expect(response).to have_http_status(:unauthorized)
    end

    # An MFA challenge is signed with the same key and would otherwise pass
    # every check. It proves a correct password and nothing more -- accepting one
    # would make MFA skippable for every authenticated endpoint, including the
    # one that DISABLES MFA.
    it "refuses an MFA challenge presented as an access token" do
      challenge = MfaChallenge.issue(identity: identity, client: client)

      call(:post, "auth/mfa/setup", token: challenge)

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses an identity from another realm" do
      stranger = create(:identity, realm: create(:realm))
      token = JWT.encode({ sub: stranger.id, iss: "https://identity.test",
                           aud: client.client_id, exp: 1.hour.from_now.to_i },
                         signing_key, "RS256")

      call(:post, "auth/mfa/setup", token: token)

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "setup" do
    it "returns a secret and a provisioning URI" do
      call(:post, "auth/mfa/setup")

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["secret"]).to be_present
      expect(response.parsed_body["provisioning_uri"]).to start_with("otpauth://totp/")
    end

    # Enrolment is only complete once a code proves the authenticator actually
    # holds the secret. Enabling on setup would lock out anyone who mis-scanned.
    it "does NOT enable MFA yet" do
      call(:post, "auth/mfa/setup")

      expect(identity.reload.mfa_enabled).to be(false)
      expect(identity.mfa_secret).to be_present
    end
  end

  describe "enable" do
    it "requires a correct code" do
      call(:post, "auth/mfa/setup")
      call(:post, "auth/mfa/enable", code: "000000")

      expect(response).to have_http_status(:unauthorized)
      expect(identity.reload.mfa_enabled).to be(false)
    end

    it "enables and returns backup codes exactly once" do
      secret = (call(:post, "auth/mfa/setup") && response.parsed_body["secret"])

      call(:post, "auth/mfa/enable", code: ROTP::TOTP.new(secret).now)

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["backup_codes"].length).to eq(10)
      expect(identity.reload.mfa_enabled).to be(true)
    end

    it "stores only digests of those codes" do
      secret = (call(:post, "auth/mfa/setup") && response.parsed_body["secret"])
      call(:post, "auth/mfa/enable", code: ROTP::TOTP.new(secret).now)
      codes = response.parsed_body["backup_codes"]

      expect(identity.reload.backup_codes).not_to include(codes.first)
      expect(identity.backup_code_digests).to include(Digest::SHA256.hexdigest(codes.first))
    end
  end

  describe "disable" do
    let(:secret) { ROTP::Base32.random }

    before { identity.update!(mfa_enabled: true, mfa_secret: secret) }

    # A stolen access token must not be enough to remove the second factor it
    # was supposed to be protected by.
    it "requires a current code, not merely a valid session" do
      call(:post, "auth/mfa/disable")

      expect(response).to have_http_status(:unauthorized)
      expect(identity.reload.mfa_enabled).to be(true)
    end

    it "disables with a correct code and clears the secret" do
      call(:post, "auth/mfa/disable", code: ROTP::TOTP.new(secret).now)

      expect(response).to have_http_status(:ok)
      identity.reload
      expect(identity.mfa_enabled).to be(false)
      expect(identity.mfa_secret).to be_nil
      expect(identity.backup_codes).to be_nil
    end
  end

  describe "show" do
    it "reports status and how many backup codes remain" do
      identity.update!(mfa_enabled: true,
                       backup_codes: [ Digest::SHA256.hexdigest("a"), Digest::SHA256.hexdigest("b") ].to_json)

      call(:get, "auth/mfa")

      expect(response.parsed_body["enabled"]).to be(true)
      expect(response.parsed_body["backup_codes_remaining"]).to eq(2)
    end
  end

  describe "sign_out" do
    # Honest about being a no-op: tokens are stateless with a 15 minute life and
    # this server holds no session records yet, so there is nothing to revoke.
    # It becomes real with refresh tokens and session rows.
    it "accepts and returns no content" do
      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: authed

      expect(response).to have_http_status(:no_content)
    end
  end
end
