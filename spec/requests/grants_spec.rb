# frozen_string_literal: true

require "rails_helper"

# Grants decide which applications an identity may use. Authentication says who
# someone is; a grant says where they may take that.
#
# Without this, every identity in a realm could sign in to every application in
# it, which would make a realm one blast radius rather than a shared set of
# credentials.
RSpec.describe "grants" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false) }
  let(:client) { create(:client, realm: realm, allowed_origins: "https://app.example.com") }
  let(:other_client) { create(:client, realm: realm, allowed_origins: "https://other.example.com") }
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

  def origin(app) = { "Origin" => app.allowed_origins_list.first }

  def sign_in(app = client, email: "ada@example.com", pass: nil)
    post "/api/apps/#{app.client_id}/auth/sign_in",
         params: { email: email, password: pass || password }, headers: origin(app)
    response.parsed_body
  end

  describe "signing in to an application the identity is not granted" do
    it "is refused, even with the correct password" do
      sign_in(other_client)

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body["error"]).to eq("Not granted")
    end

    # Distinguishable from a bad password ON PURPOSE. The usual reason to make
    # failures uniform is to avoid revealing that an address exists -- but this
    # response is only reachable by someone who has already proved the password,
    # so it tells them nothing they did not just demonstrate they knew. Saying
    # "wrong password" here would send a person to reset a password that works.
    it "says something different from a wrong password" do
      sign_in(other_client)
      not_granted = [ response.status, response.parsed_body["error"] ]

      sign_in(client, pass: "wrong")
      bad_password = [ response.status, response.parsed_body["error"] ]

      expect(not_granted).not_to eq(bad_password)
    end

    it "issues no session" do
      expect { sign_in(other_client) }.not_to change(Session, :count)
    end
  end

  describe "signing in to a granted application" do
    it "succeeds once the grant exists" do
      create(:grant, identity: identity, client: other_client)

      body = sign_in(other_client)

      expect(response).to have_http_status(:ok)
      expect(body["access_token"]).to be_present
    end
  end

  describe "signing up" do
    # Otherwise every new person registers and is immediately refused.
    it "grants the application signed up through" do
      post "/api/apps/#{other_client.client_id}/auth/sign_up",
           params: { email: "grace@example.com", password: password, first_name: "Grace" },
           headers: origin(other_client)

      expect(response).to have_http_status(:created)
      new_identity = Identity.find_by(email: "grace@example.com")
      expect(Grant.permits?(identity: new_identity, client: other_client)).to be(true)
    end

    it "does not grant the realm's other applications" do
      post "/api/apps/#{other_client.client_id}/auth/sign_up",
           params: { email: "grace@example.com", password: password, first_name: "Grace" },
           headers: origin(other_client)

      new_identity = Identity.find_by(email: "grace@example.com")
      expect(Grant.permits?(identity: new_identity, client: client)).to be(false)
    end
  end

  describe "revoking a grant" do
    # The point of checking on refresh as well as sign-in. Without it a live
    # session keeps minting access tokens for up to the refresh token's 30 days,
    # so the grant would be gone and the access would not.
    it "stops the existing session refreshing" do
      refresh_token = sign_in["refresh_token"]
      identity.grants.destroy_all

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: refresh_token }, headers: origin(client)

      expect(response).to have_http_status(:unauthorized)
    end

    it "stops further sign-ins" do
      identity.grants.destroy_all

      sign_in

      expect(response).to have_http_status(:forbidden)
    end
  end

  describe "MFA" do
    before do
      identity.update!(mfa_enabled: true, mfa_secret: ROTP::Base32.random)
      create(:grant, identity: identity, client: other_client)
    end

    # Refused BEFORE the challenge, so nobody completes a second factor only to
    # be told they were never allowed in.
    it "refuses an ungranted application without issuing a challenge" do
      identity.grants.where(granted_client_id: other_client.id).destroy_all

      body = sign_in(other_client)

      expect(response).to have_http_status(:forbidden)
      expect(body["mfa_token"]).to be_nil
    end

    it "issues a challenge for a granted application" do
      body = sign_in(other_client)

      expect(body["mfa_required"]).to be(true)
      expect(body["mfa_token"]).to be_present
    end

    # Revoked between the password and the code. Rare, but the alternative is a
    # session issued down a path that never checked.
    it "refuses at verification if the grant went away mid-flow" do
      mfa_token = sign_in(other_client)["mfa_token"]
      identity.grants.where(granted_client_id: other_client.id).destroy_all

      post "/api/apps/#{other_client.client_id}/auth/verify_mfa",
           params: { mfa_token: mfa_token, code: ROTP::TOTP.new(identity.mfa_secret).now },
           headers: origin(other_client)

      expect(response).to have_http_status(:forbidden)
    end
  end
end
