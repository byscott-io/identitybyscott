# frozen_string_literal: true

require "rails_helper"

# Exchanging one application's token for another's, for the same identity.
#
# Access tokens are audience-scoped so a token leaked from one application is
# useless at another. This endpoint keeps that -- every token still names one
# audience -- while letting an application's backend call another's API for the
# person using it, if that person is granted there.
RSpec.describe "POST auth/exchange" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false) }
  let(:caller_app) { create(:client, realm: realm, allowed_origins: "https://a.example.com") }
  let(:target_app) { create(:client, realm: realm, allowed_origins: "https://b.example.com") }
  let(:password) { "correct horse battery staple" }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: caller_app, email: "ada@example.com",
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

  def sign_in(app = caller_app)
    post "/api/apps/#{app.client_id}/auth/sign_in",
         params: { email: "ada@example.com", password: password }, headers: origin(app)
    response.parsed_body["access_token"]
  end

  def exchange(token, audience:, at: caller_app)
    post "/api/apps/#{at.client_id}/auth/exchange",
         params: { audience: audience }, headers: origin(at).merge("Authorization" => "Bearer #{token}")
    response.parsed_body
  end

  def claims(token)
    JWT.decode(token, signing_key.public_key, true,
               algorithm: SigningKeys::ALGORITHM, verify_aud: false, verify_iss: false).first
  end

  describe "when the identity is granted the target" do
    before { create(:grant, identity: identity, client: target_app) }

    it "issues a token audienced to the target, not the caller" do
      body = exchange(sign_in, audience: target_app.client_id)

      expect(response).to have_http_status(:ok)
      expect(claims(body["access_token"])["aud"]).to eq(target_app.client_id)
    end

    it "names the calling application as the actor" do
      body = exchange(sign_in, audience: target_app.client_id)

      expect(claims(body["access_token"])["act"]).to eq("client_id" => caller_app.client_id)
    end

    it "is the same identity" do
      body = exchange(sign_in, audience: target_app.client_id)

      expect(claims(body["access_token"])["sub"]).to eq(identity.id)
    end

    # The claim the whole endpoint rests on. Asserting the aud string proves the
    # token SAYS the right thing; this proves the target actually accepts it.
    it "produces a token the target accepts" do
      body = exchange(sign_in, audience: target_app.client_id)

      get "/api/apps/#{target_app.client_id}/auth/sessions",
          headers: origin(target_app).merge("Authorization" => "Bearer #{body['access_token']}")

      expect(response).to have_http_status(:ok)
    end

    # The containment this endpoint is careful not to break: the token it hands
    # back must not work where it was minted, or an exchange would widen reach
    # rather than redirect it.
    it "produces a token the CALLER does not accept" do
      body = exchange(sign_in, audience: target_app.client_id)

      get "/api/apps/#{caller_app.client_id}/auth/sessions",
          headers: origin(caller_app).merge("Authorization" => "Bearer #{body['access_token']}")

      expect(response).to have_http_status(:unauthorized)
    end

    # An exchanged token is a delegated, short-lived thing. Handing back a
    # refresh token would let one application mint a 30-day foothold in another.
    it "returns no refresh token" do
      body = exchange(sign_in, audience: target_app.client_id)

      expect(body).not_to have_key("refresh_token")
    end
  end

  describe "refusals" do
    it "refuses when the identity holds no grant for the target" do
      exchange(sign_in, audience: target_app.client_id)

      expect(response).to have_http_status(:forbidden)
    end

    it "refuses a target in another realm, even with a token" do
      foreign = create(:client, realm: create(:realm), allowed_origins: "https://x.example.com")

      exchange(sign_in, audience: foreign.client_id)

      expect(response).to have_http_status(:forbidden)
    end

    # The case the realm check actually defends, and the only one that proves
    # it: a grant created legitimately, then the application moved realms.
    #
    # Grant validates the realm when the GRANT is saved, and nothing
    # revalidates existing grants when a client changes realm -- so the row
    # survives as a cross-realm permission that Grant.permits? answers yes to.
    # Without the realm check here, that stale row would mint a token for an
    # application in a realm this identity does not belong to.
    it "refuses a granted application that has since moved realms" do
      create(:grant, identity: identity, client: target_app)
      target_app.update_column(:realm_id, create(:realm).id)

      exchange(sign_in, audience: target_app.client_id)

      expect(response).to have_http_status(:forbidden)
    end

    # A malformed request must land on the same uniform refusal, not a 500.
    # A different shape is a signal in itself, and it is the one response an
    # attacker can provoke without knowing anything.
    it "refuses a nested audience parameter without erroring" do
      post "/api/apps/#{caller_app.client_id}/auth/exchange",
           params: { audience: { nested: "value" } },
           headers: origin(caller_app).merge("Authorization" => "Bearer #{sign_in}")

      expect(response).to have_http_status(:forbidden)
    end

    it "refuses an unknown audience" do
      exchange(sign_in, audience: "no-such-application")

      expect(response).to have_http_status(:forbidden)
    end

    it "refuses an inactive target" do
      create(:grant, identity: identity, client: target_app)
      target_app.update!(active: false)

      exchange(sign_in, audience: target_app.client_id)

      expect(response).to have_http_status(:forbidden)
    end

    it "refuses exchanging for the caller itself" do
      exchange(sign_in, audience: caller_app.client_id)

      expect(response).to have_http_status(:forbidden)
    end

    # Every refusal reads the same. Separating them would let any application
    # holding a token enumerate which applications exist, which realm they are
    # in, and which of them this person can reach -- a map of someone's whole
    # suite, readable by any one application they use.
    it "answers identically whatever the reason" do
      ungranted = exchange(sign_in, audience: target_app.client_id)
      unknown = exchange(sign_in, audience: "no-such-application")

      expect(ungranted).to eq(unknown)
    end
  end

  describe "the presented token" do
    before { create(:grant, identity: identity, client: target_app) }

    # An application may only exchange ITS OWN token. Without this, an
    # application that got hold of a token for somewhere else could launder it
    # into a third application.
    it "is refused when it was minted for a different application" do
      other_token = sign_in(target_app)

      exchange(other_token, audience: target_app.client_id, at: caller_app)

      expect(response).to have_http_status(:unauthorized)
    end

    it "is refused when absent" do
      post "/api/apps/#{caller_app.client_id}/auth/exchange",
           params: { audience: target_app.client_id }, headers: origin(caller_app)

      expect(response).to have_http_status(:unauthorized)
    end

    # Revocation is eventual everywhere else, because applications verify
    # offline. Here the call reaches this server, so a revoked session can be
    # caught -- and should be, or its remaining minutes buy a WIDER reach than
    # the session ever had.
    it "is refused once its session is revoked" do
      token = sign_in
      identity.sessions.each(&:revoke!)

      exchange(token, audience: target_app.client_id)

      expect(response).to have_http_status(:forbidden)
    end
  end

  describe "chaining" do
    before { create(:grant, identity: identity, client: target_app) }

    # An exchanged token carries no sid, because it is minted without a session.
    # The live-session check treats a missing sid as "nothing to check", so a
    # second hop would skip it silently -- reopening the offline-verification
    # window this endpoint exists to close, while the README promises revocation
    # is caught immediately here.
    it "refuses a token that was itself obtained by exchange" do
      first = exchange(sign_in, audience: target_app.client_id)["access_token"]
      third = create(:client, realm: realm, allowed_origins: "https://c.example.com")
      create(:grant, identity: identity, client: third)

      exchange(first, audience: third.client_id, at: target_app)

      expect(response).to have_http_status(:forbidden)
    end

    # The guarantee that would otherwise be quietly false. Revoke the session,
    # then try to spend an already-exchanged token for a further hop.
    it "cannot be used to outlive a revoked session" do
      first = exchange(sign_in, audience: target_app.client_id)["access_token"]
      third = create(:client, realm: realm, allowed_origins: "https://c.example.com")
      create(:grant, identity: identity, client: third)
      identity.sessions.each(&:revoke!)

      exchange(first, audience: third.client_id, at: target_app)

      expect(response).to have_http_status(:forbidden)
    end
  end

  describe "revoking the grant" do
    it "stops further exchanges" do
      create(:grant, identity: identity, client: target_app)
      token = sign_in
      identity.grants.where(granted_client_id: target_app.id).destroy_all

      exchange(token, audience: target_app.client_id)

      expect(response).to have_http_status(:forbidden)
    end
  end
end
