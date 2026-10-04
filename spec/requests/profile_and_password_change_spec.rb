# frozen_string_literal: true

require "rails_helper"

# The three endpoints corebyscott's client routes here but that did not exist,
# found by preparing churchcare as the first adopter: a client in identity mode
# called them and got 404 from this server while its own copies were suppressed
# by the guard, so each feature was dead in both directions.
RSpec.describe "profile, password change and backup-code status" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false) }
  let(:client) { create(:client, realm: realm, allowed_origins: "https://app.example.com") }
  let(:password) { "correct horse battery staple" }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: client, email: "ada@example.com",
                      password: password, confirmed_at: Time.current,
                      first_name: "Ada", last_name: "Lovelace")
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

  def minted_token(for_identity = identity)
    TokenIssuer.new(identity: for_identity, client: client).access_token
  end

  def authed(token = nil)
    { "Origin" => "https://app.example.com", "Authorization" => "Bearer #{token || minted_token}" }
  end

  describe "PUT /auth/change_password" do
    it "changes the password when the current one is correct" do
      put "/api/apps/#{client.client_id}/auth/change_password",
          params: { current_password: password, password: "a-brand-new-passphrase" },
          headers: authed

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["message"]).to match(/changed/i)
      expect(identity.reload.valid_password?("a-brand-new-passphrase")).to be true
      expect(identity.valid_password?(password)).to be false
    end

    it "refuses a wrong current password and leaves the old one working" do
      put "/api/apps/#{client.client_id}/auth/change_password",
          params: { current_password: "not-the-password", password: "a-brand-new-passphrase" },
          headers: authed

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body["error"]).to match(/current password/i)
      expect(identity.reload.valid_password?(password)).to be true
    end

    it "enforces the byte-based password rules on the new password" do
      put "/api/apps/#{client.client_id}/auth/change_password",
          params: { current_password: password, password: "short" },
          headers: authed

      expect(response).to have_http_status(:unprocessable_content)
      expect(identity.reload.valid_password?(password)).to be true
    end

    it "clears a lock, since knowing the current password proves more than the lock protected" do
      identity.update!(failed_attempts: 10)
      identity.lock_access!
      expect(identity.reload.access_locked?).to be true

      put "/api/apps/#{client.client_id}/auth/change_password",
          params: { current_password: password, password: "a-brand-new-passphrase" },
          headers: authed

      expect(response).to have_http_status(:ok)
      expect(identity.reload.access_locked?).to be false
    end

    it "requires authentication" do
      put "/api/apps/#{client.client_id}/auth/change_password",
          params: { current_password: password, password: "a-brand-new-passphrase" },
          headers: { "Origin" => "https://app.example.com" }

      expect(response).to have_http_status(:unauthorized)
      expect(identity.reload.valid_password?(password)).to be true
    end

    # An MFA challenge is signed with the same key. Accepting one here would let
    # a correct password alone change the password of an MFA-protected account.
    it "refuses an MFA challenge token" do
      challenge = MfaChallenge.issue(identity: identity, client: client)

      put "/api/apps/#{client.client_id}/auth/change_password",
          params: { current_password: password, password: "a-brand-new-passphrase" },
          headers: authed(challenge)

      expect(response).to have_http_status(:unauthorized)
      expect(identity.reload.valid_password?(password)).to be true
    end
  end

  describe "PUT /auth/profile" do
    it "accepts core's { user: { ... } } shape" do
      put "/api/apps/#{client.client_id}/auth/profile",
          params: { user: { first_name: "Augusta", nickname: "Ada", time_zone: "America/New_York" } },
          headers: authed

      expect(response).to have_http_status(:ok)
      body = response.parsed_body
      expect(body["user"]).to include("first_name" => "Augusta", "nickname" => "Ada")
      expect(identity.reload.first_name).to eq("Augusta")
      expect(identity.time_zone).to eq("America/New_York")
    end

    it "accepts a bare body too, for a client that is not corebyscott" do
      put "/api/apps/#{client.client_id}/auth/profile",
          params: { last_name: "Byron" }, headers: authed

      expect(response).to have_http_status(:ok)
      expect(identity.reload.last_name).to eq("Byron")
    end

    it "never lets a client set fields that would be privilege escalation" do
      other_realm = create(:realm)

      put "/api/apps/#{client.client_id}/auth/profile",
          params: { user: { first_name: "Augusta", realm_id: other_realm.id,
                            confirmed_at: 1.year.ago, mfa_enabled: true, failed_attempts: 99 } },
          headers: authed

      expect(response).to have_http_status(:ok)
      identity.reload
      expect(identity.first_name).to eq("Augusta")
      expect(identity.realm_id).to eq(realm.id)
      expect(identity.mfa_enabled).to be false
      expect(identity.failed_attempts).to eq(0)
    end

    it "requires authentication" do
      put "/api/apps/#{client.client_id}/auth/profile",
          params: { user: { first_name: "Nope" } },
          headers: { "Origin" => "https://app.example.com" }

      expect(response).to have_http_status(:unauthorized)
      expect(identity.reload.first_name).to eq("Ada")
    end

    context "when the realm does NOT require confirmation" do
      it "applies an email change immediately rather than leaving it pending" do
        put "/api/apps/#{client.client_id}/auth/profile",
            params: { user: { email: "ada@newdomain.example" } }, headers: authed

        expect(response).to have_http_status(:ok)
        identity.reload
        expect(identity.email).to eq("ada@newdomain.example")
        expect(identity.unconfirmed_email).to be_nil
      end
    end

    context "when the realm DOES require confirmation" do
      let(:realm) { create(:realm, require_email_confirmation: true) }

      it "holds the new address pending confirmation and keeps the old one in effect" do
        put "/api/apps/#{client.client_id}/auth/profile",
            params: { user: { email: "ada@newdomain.example" } }, headers: authed

        expect(response).to have_http_status(:ok)
        identity.reload
        expect(identity.email).to eq("ada@example.com")
        expect(identity.unconfirmed_email).to eq("ada@newdomain.example")
        expect(response.parsed_body["pending_email"]).to eq("ada@newdomain.example")
      end
    end

    it "rejects an email already taken in the same realm" do
      create(:identity, realm: realm, email: "taken@example.com", confirmed_at: Time.current)

      put "/api/apps/#{client.client_id}/auth/profile",
          params: { user: { email: "taken@example.com" } }, headers: authed

      expect(response).to have_http_status(:unprocessable_content)
      expect(identity.reload.email).to eq("ada@example.com")
    end

    # The realm boundary: the same address in another realm is a different
    # person, so it must not collide.
    it "allows an email that exists in a DIFFERENT realm" do
      other = create(:realm)
      create(:identity, realm: other, email: "elsewhere@example.com", confirmed_at: Time.current)

      put "/api/apps/#{client.client_id}/auth/profile",
          params: { user: { email: "elsewhere@example.com" } }, headers: authed

      expect(response).to have_http_status(:ok)
      expect(identity.reload.email).to eq("elsewhere@example.com")
    end
  end

  describe "GET /auth/mfa/backup_codes" do
    it "refuses when MFA is not enabled, matching core" do
      get "/api/apps/#{client.client_id}/auth/mfa/backup_codes", headers: authed

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body["error"]).to match(/not enabled/i)
    end

    context "with MFA enabled" do
      # regenerate_backup_codes requires a live second factor, so the codes are
      # obtained the way a person would: with a real TOTP from the enrolled
      # secret. An earlier version of this spec omitted the code, got
      # "Invalid code", and every assertion below failed on a nil array.
      before do
        secret = ROTP::Base32.random
        identity.update!(mfa_secret: secret, mfa_enabled: true)
        post "/api/apps/#{client.client_id}/auth/mfa/regenerate_backup_codes",
             params: { code: ROTP::TOTP.new(secret).now }, headers: authed
        @issued = response.parsed_body["backup_codes"]
      end

      it "issues codes once, at generation" do
        expect(@issued.length).to eq(10)
      end

      # The deliberate contract difference from core: core returns the raw codes
      # because it stores them in plaintext. This server stores digests, so the
      # codes cannot be read back by anyone -- including whoever reads the
      # database, which is the point.
      it "reports a COUNT and never the codes themselves" do
        get "/api/apps/#{client.client_id}/auth/mfa/backup_codes", headers: authed

        expect(response).to have_http_status(:ok)
        body = response.parsed_body
        expect(body["backup_codes_remaining"]).to eq(10)
        expect(body).not_to have_key("backup_codes")
        expect(body["detail"]).to match(/cannot be retrieved/i)
        expect(body["backup_codes_generated_at"]).to be_present
      end

      it "does not leak a stored digest in the response" do
        digest = identity.reload.backup_code_digests.first

        get "/api/apps/#{client.client_id}/auth/mfa/backup_codes", headers: authed

        expect(response.body).not_to include(digest)
      end

      it "reflects a consumed code in the count" do
        identity.reload.consume_backup_code!(@issued.first)

        get "/api/apps/#{client.client_id}/auth/mfa/backup_codes", headers: authed

        expect(response.parsed_body["backup_codes_remaining"]).to eq(9)
      end

      it "requires authentication" do
        get "/api/apps/#{client.client_id}/auth/mfa/backup_codes",
            headers: { "Origin" => "https://app.example.com" }

        expect(response).to have_http_status(:unauthorized)
      end
    end
  end
end
