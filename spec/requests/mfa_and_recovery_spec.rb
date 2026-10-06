# frozen_string_literal: true

require "rails_helper"

RSpec.describe "MFA verification and password recovery" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false) }
  let(:client) { create(:client, realm: realm, allowed_origins: "https://app.example.com") }
  let(:password) { "correct horse battery staple" }
  let(:mfa_secret) { ROTP::Base32.random }
  let(:backup_code) { "abcd-1234" }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: client, email: "ada@example.com",
                      password: password, confirmed_at: Time.current, mfa_enabled: true,
                      mfa_secret: mfa_secret,
                      backup_codes: [ Digest::SHA256.hexdigest(backup_code) ].to_json)
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

  def headers
    { "Origin" => "https://app.example.com" }
  end

  def challenge
    post "/api/apps/#{client.client_id}/auth/sign_in",
         params: { email: "ada@example.com", password: password }, headers: headers
    response.parsed_body["mfa_token"]
  end

  def verify(code:, token: nil)
    post "/api/apps/#{client.client_id}/auth/verify_mfa",
         params: { mfa_token: token || challenge, code: code }, headers: headers
  end

  describe "a correct TOTP code" do
    it "completes the sign in" do
      verify(code: ROTP::TOTP.new(mfa_secret).now

)
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["access_token"]).to be_present
    end

    it "clears the failure counter" do
      verify(code: "000000")
      verify(code: ROTP::TOTP.new(mfa_secret).now)

      expect(identity.reload.failed_attempts).to eq(0)
    end
  end

  describe "a wrong code" do
    it "is refused" do
      verify(code: "000000")

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body["access_token"]).to be_nil
    end

    # Otherwise a six-digit code is a feasible brute force rather than a
    # theoretical one.
    it "counts toward the lock" do
      token = challenge
      3.times { verify(code: "000000", token: token) }

      expect(identity.reload.failed_attempts).to eq(3)
    end
  end

  describe "backup codes" do
    it "accepts one" do
      verify(code: backup_code)

      expect(response).to have_http_status(:ok)
    end

    # A reusable backup code is a permanent second factor that cannot be revoked
    # without regenerating the whole set.
    it "consumes it, so it cannot be used twice" do
      verify(code: backup_code)
      expect(response).to have_http_status(:ok)

      verify(code: backup_code)
      expect(response).to have_http_status(:unauthorized)
    end

    it "stores only digests, never the codes themselves" do
      expect(identity.backup_codes).not_to include(backup_code)
      expect(identity.backup_code_digests.first).to eq(Digest::SHA256.hexdigest(backup_code))
    end
  end

  describe "the challenge itself" do
    it "refuses a challenge minted for another client" do
      other = create(:client, realm: realm, allowed_origins: "https://app.example.com")
      token = MfaChallenge.issue(identity: identity, client: other)

      verify(code: ROTP::TOTP.new(mfa_secret).now, token: token)

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses an identity from another realm" do
      stranger = create(:identity, realm: create(:realm), mfa_enabled: true, mfa_secret: mfa_secret)
      token = MfaChallenge.issue(identity: stranger, client: client)

      verify(code: ROTP::TOTP.new(mfa_secret).now, token: token)

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses garbage" do
      verify(code: "000000", token: "not-a-token")

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "forgot password" do
    def forgot(email)
      post "/api/apps/#{client.client_id}/auth/forgot_password",
           params: { email: email }, headers: headers
    end

    # Easier to abuse than sign-in, since no password is needed, so the answer
    # must be identical either way.
    it "answers the same for a known and an unknown address" do
      forgot("ada@example.com")
      known = [ response.status, response.parsed_body ]

      forgot("nobody@example.com")
      expect([ response.status, response.parsed_body ]).to eq(known)
    end

    it "answers the same for an address in ANOTHER realm" do
      create(:identity, realm: create(:realm), email: "elsewhere@example.com")

      forgot("elsewhere@example.com")
      elsewhere = [ response.status, response.parsed_body ]

      forgot("nobody@example.com")
      expect([ response.status, response.parsed_body ]).to eq(elsewhere)
    end

    it "does send a token for a real address" do
      forgot("ada@example.com")

      expect(identity.reload.reset_password_token).to be_present
    end

    it "sends nothing for an address in another realm" do
      stranger = create(:identity, realm: create(:realm), email: "elsewhere@example.com")

      forgot("elsewhere@example.com")

      expect(stranger.reload.reset_password_token).to be_nil
    end
  end

  describe "reset password" do
    def reset(token, new_password)
      post "/api/apps/#{client.client_id}/auth/reset_password",
           params: { token: token, password: new_password }, headers: headers
    end

    it "changes the password" do
      raw = identity.send_reset_password_instructions

      reset(raw, "a brand new passphrase")

      expect(response).to have_http_status(:ok)
      expect(identity.reload.valid_password?("a brand new passphrase")).to be(true)
    end

    # Applications own the reset form and normally confirm there, so most
    # callers send only `password`. But the controller used to pass the password
    # as its OWN confirmation unconditionally, so a client that did send a
    # mismatched confirmation had it silently discarded and the password set
    # anyway. Accepting a parameter and ignoring it is worse than not accepting
    # it at all.
    it "honours a password_confirmation when the client sends one" do
      raw = identity.send_reset_password_instructions

      post "/api/apps/#{client.client_id}/auth/reset_password",
           params: { token: raw, password: "a brand new passphrase",
                     password_confirmation: "something else entirely" },
           headers: headers

      expect(response).to have_http_status(:unprocessable_content)
      expect(identity.reload.valid_password?("a brand new passphrase")).to be(false)
    end

    it "still accepts a reset with no confirmation sent at all" do
      raw = identity.send_reset_password_instructions

      reset(raw, "a brand new passphrase")

      expect(response).to have_http_status(:ok)
      expect(identity.reload.valid_password?("a brand new passphrase")).to be(true)
    end

    it "refuses a token that was never issued" do
      reset("made-up-token", "a brand new passphrase")

      expect(response).to have_http_status(:unprocessable_content)
    end

    it "cannot be replayed" do
      raw = identity.send_reset_password_instructions
      reset(raw, "a brand new passphrase")

      reset(raw, "another passphrase entirely")

      expect(response).to have_http_status(:unprocessable_content)
    end

    # Someone who can read the inbox has proved more than a password would.
    # Leaving them locked out is a support call with no security benefit.
    it "clears a lock" do
      identity.lock_access!
      raw = identity.send_reset_password_instructions

      reset(raw, "a brand new passphrase")

      expect(identity.reload).not_to be_access_locked
    end
  end
end
