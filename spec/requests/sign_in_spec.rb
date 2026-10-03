# frozen_string_literal: true

require "rails_helper"

# Sign in. Credentials arrive from a form the APPLICATION renders and posts
# here; this server has none of its own.
RSpec.describe "POST auth/sign_in" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false) }
  let(:client) { create(:client, realm: realm, allowed_origins: "https://app.example.com") }
  let(:password) { "correct horse battery staple" }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: client,
                      email: "ada@example.com", password: password, confirmed_at: Time.current)
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

  def sign_in(email: "ada@example.com", pass: nil, client_id: nil, origin: "https://app.example.com")
    post "/api/apps/#{client_id || client.client_id}/auth/sign_in",
         params: { email: email, password: pass || password },
         headers: { "Origin" => origin }
  end

  describe "correct credentials" do
    it "returns a Bearer access token" do
      sign_in

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["token_type"]).to eq("Bearer")
      expect(response.parsed_body["expires_in"]).to eq(900)
    end

    it "issues a token scoped to THIS client" do
      sign_in

      payload, = JWT.decode(response.parsed_body["access_token"], signing_key.public_key, true,
                            algorithm: "RS256", aud: client.client_id, verify_aud: true)

      expect(payload["sub"]).to eq(identity.id)
      expect(payload["aud"]).to eq(client.client_id)
    end

    # The gate that stops one authentication granting everything.
    it "issues a token ANOTHER client cannot accept" do
      other = create(:client, realm: realm)
      sign_in

      expect do
        JWT.decode(response.parsed_body["access_token"], signing_key.public_key, true,
                   algorithm: "RS256", aud: other.client_id, verify_aud: true)
      end.to raise_error(JWT::InvalidAudError)
    end
  end

  # The responses must be indistinguishable, or the endpoint becomes a way to
  # ask which realm an address exists in -- the cross-realm fact realms isolate.
  describe "uniform failure" do
    it "answers the same for a wrong password and an unknown address" do
      sign_in(pass: "wrong")
      wrong_password = [ response.status, response.parsed_body ]

      sign_in(email: "nobody@example.com")
      unknown_address = [ response.status, response.parsed_body ]

      expect(wrong_password).to eq(unknown_address)
    end

    it "answers the same for an address that exists only in ANOTHER realm" do
      other_realm = create(:realm)
      create(:identity, realm: other_realm, email: "elsewhere@example.com", password: password)

      sign_in(email: "elsewhere@example.com")
      elsewhere = [ response.status, response.parsed_body ]

      sign_in(email: "nobody@example.com")
      expect(elsewhere).to eq([ response.status, response.parsed_body ])
    end
  end

  describe "lockable" do
    it "locks after the configured number of failures" do
      Devise.maximum_attempts.times { sign_in(pass: "wrong") }

      expect(identity.reload).to be_access_locked
    end

    it "clears the counter after a success" do
      3.times { sign_in(pass: "wrong") }
      sign_in

      expect(identity.reload.failed_attempts).to eq(0)
    end

    # Reporting a lock to someone who does not know the password would tell them
    # the address exists.
    it "does not reveal a lock to a wrong password" do
      identity.lock_access!

      sign_in(pass: "wrong")

      expect(response).to have_http_status(:unauthorized)
      expect(response.parsed_body["error"]).to eq("Invalid email or password")
    end

    it "reports the lock once the password is right" do
      identity.lock_access!

      sign_in

      expect(response).to have_http_status(:locked)
    end
  end

  describe "confirmable" do
    it "refuses an unconfirmed identity where the realm requires it" do
      realm.update!(require_email_confirmation: true)
      identity.update_columns(confirmed_at: nil)

      sign_in

      expect(response).to have_http_status(:forbidden)
    end

    it "allows an unconfirmed identity where the realm does not" do
      identity.update_columns(confirmed_at: nil)

      sign_in

      expect(response).to have_http_status(:ok)
    end
  end

  describe "MFA step-up" do
    before { identity.update!(mfa_enabled: true) }

    it "returns a challenge rather than an access token" do
      sign_in

      expect(response.parsed_body["mfa_required"]).to be(true)
      expect(response.parsed_body["access_token"]).to be_nil
      expect(response.parsed_body["mfa_token"]).to be_present
    end

    # Without the purpose claim an interim token would BE an access token, and
    # MFA would be decorative.
    it "issues a challenge that is not usable as an access token" do
      sign_in
      challenge = response.parsed_body["mfa_token"]

      payload, = JWT.decode(challenge, signing_key.public_key, true,
                            algorithm: "RS256", aud: client.client_id, verify_aud: true)

      expect(payload["purpose"]).to eq("mfa_challenge")
    end

    it "refuses an access token presented as a challenge" do
      identity.update!(mfa_enabled: false)
      sign_in
      access_token = response.parsed_body["access_token"]

      expect { MfaChallenge.identity_for(access_token, client: client, realm: realm) }
        .to raise_error(MfaChallenge::InvalidChallenge, /Not an MFA challenge/)
    end
  end

  describe "the client and origin still gate the request" do
    it "refuses an unknown client_id" do
      sign_in(client_id: "cid_nope")

      expect(response).to have_http_status(:not_found)
    end

    it "refuses an origin not on the client's allowlist" do
      sign_in(origin: "https://evil.example.com")

      expect(response).to have_http_status(:forbidden)
    end

    it "allows a non-browser caller, which sends no Origin" do
      post "/api/apps/#{client.client_id}/auth/sign_in",
           params: { email: "ada@example.com", password: password }

      expect(response).to have_http_status(:ok)
    end
  end
end
