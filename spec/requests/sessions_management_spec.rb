# frozen_string_literal: true

require "rails_helper"

# IDENTITY M4. Before this, an accepted credential minted a bare access token
# and recorded nothing: no sessions list, no revocation, and sign_out answered
# 204 while the token kept working. An app switched to :identity_server lost
# capabilities it had under :local, which is why no app with real users could go
# first.
RSpec.describe "central session management" do
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

  def origin(c = client)
    { "Origin" => c.allowed_origins }
  end

  def sign_in(c = client, agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36")
    post "/api/apps/#{c.client_id}/auth/sign_in",
         params: { email: "ada@example.com", password: password },
         headers: origin(c).merge("User-Agent" => agent)
    response.parsed_body
  end

  def authed(token, c = client)
    origin(c).merge("Authorization" => "Bearer #{token}")
  end

  def claims(token)
    JWT.decode(token, signing_key.public_key, true, algorithm: "RS256",
               iss: "https://identity.test", verify_iss: true,
               aud: client.client_id, verify_aud: true).first
  end

  describe "signing in" do
    it "creates a session and returns a refresh token alongside the access token" do
      expect { sign_in }.to change(Session, :count).by(1)

      body = response.parsed_body
      expect(body["access_token"]).to be_present
      expect(body["refresh_token"]).to be_present
      expect(body["refresh_token_expires_in"]).to eq(Session::REFRESH_TOKEN_TTL.to_i)
    end

    it "records the device so a person can recognise it in the list" do
      sign_in
      session = Session.last

      expect(session.identity).to eq(identity)
      expect(session.client).to eq(client)
      expect(session.user_agent).to include("Chrome")
      expect(session.last_used_at).to be_present
      expect(session.expires_at).to be_future
    end

    # The refresh token is a long-lived bearer credential, so a readable copy in
    # the database is worth more to an attacker than a password hash -- it needs
    # no cracking at all.
    it "stores only a DIGEST of the refresh token" do
      raw = sign_in["refresh_token"]
      session = Session.last

      expect(session.refresh_token_digest).not_to eq(raw)
      expect(session.refresh_token_digest).to eq(Digest::SHA256.hexdigest(raw))
      expect(Session.column_names).not_to include("refresh_token")
    end

    it "ties the access token to the session with a sid claim" do
      token = sign_in["access_token"]

      expect(claims(token)["sid"]).to eq(Session.last.id)
    end
  end

  describe "POST /auth/refresh" do
    it "exchanges a refresh token for a fresh access token" do
      raw = sign_in["refresh_token"]

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: raw }, headers: origin

      expect(response).to have_http_status(:ok)
      expect(claims(response.parsed_body["access_token"])["sub"]).to eq(identity.id)
    end

    it "updates last_used_at, so the list shows real activity" do
      raw = sign_in["refresh_token"]
      Session.last.update_column(:last_used_at, 3.days.ago)

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: raw }, headers: origin

      expect(Session.last.last_used_at).to be_within(5.seconds).of(Time.current)
    end

    it "refuses a nonsense token" do
      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: "not-a-real-token" }, headers: origin

      expect(response).to have_http_status(:unauthorized)
    end

    # The same reason an access token is audience-scoped: a credential leaked
    # from one application must not be usable at another.
    it "refuses a refresh token at a DIFFERENT client" do
      raw = sign_in["refresh_token"]

      post "/api/apps/#{other_client.client_id}/auth/refresh",
           params: { refresh_token: raw }, headers: origin(other_client)

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses a revoked session" do
      raw = sign_in["refresh_token"]
      Session.last.revoke!

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: raw }, headers: origin

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses an expired session" do
      raw = sign_in["refresh_token"]
      Session.last.update_column(:expires_at, 1.minute.ago)

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: raw }, headers: origin

      expect(response).to have_http_status(:unauthorized)
    end

    # Unknown, revoked, expired and wrong-client all answer identically.
    # Distinguishing them would turn this endpoint into a revocation oracle.
    it "gives the same answer for revoked and never-existed" do
      raw = sign_in["refresh_token"]
      Session.last.revoke!

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: raw }, headers: origin
      revoked = [ response.status, response.parsed_body ]

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: "never-existed" }, headers: origin

      expect([ response.status, response.parsed_body ]).to eq(revoked)
    end
  end

  describe "GET /auth/sessions" do
    it "lists this identity's sessions across applications" do
      sign_in
      sign_in(other_client)

      token = sign_in["access_token"]
      get "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      expect(response).to have_http_status(:ok)
      sessions = response.parsed_body["sessions"]
      expect(sessions.length).to eq(3)
      expect(sessions.map { |s| s["client_id"] }).to include(client.client_id, other_client.client_id)
    end

    it "renders the fields corebyscott's SessionsList already expects" do
      token = sign_in["access_token"]

      get "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      expect(response.parsed_body["sessions"].first).to include(
        "id", "device_name", "browser", "browser_version", "os",
        "device_type", "is_mobile", "ip_address", "created_at",
        "last_used_at", "current"
      )
    end

    it "flags which row is the device being used to read the list" do
      token = sign_in["access_token"]
      sign_in(other_client)

      get "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      current = response.parsed_body["sessions"].select { |s| s["current"] }
      expect(current.length).to eq(1)
      expect(current.first["id"]).to eq(claims(token)["sid"])
    end

    it "never renders the refresh token digest" do
      token = sign_in["access_token"]
      digest = Session.last.refresh_token_digest

      get "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      expect(response.body).not_to include(digest)
    end

    it "omits revoked sessions" do
      token = sign_in["access_token"]
      sign_in(other_client)
      Session.where.not(id: claims(token)["sid"]).find_each(&:revoke!)

      get "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      expect(response.parsed_body["sessions"].length).to eq(1)
    end

    it "requires authentication" do
      get "/api/apps/#{client.client_id}/auth/sessions", headers: origin

      expect(response).to have_http_status(:unauthorized)
    end

    it "shows only this identity's sessions" do
      stranger = create(:identity, realm: realm, email: "stranger@example.com",
                                   password: password, confirmed_at: Time.current)
      Session.issue!(identity: stranger, client: client)

      token = sign_in["access_token"]
      get "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      ids = response.parsed_body["sessions"].map { |s| s["id"] }
      expect(ids).not_to include(*stranger.sessions.pluck(:id))
    end
  end

  describe "DELETE /auth/sessions/:id" do
    it "revokes one session, and its refresh token stops working" do
      doomed_raw = sign_in["refresh_token"]
      doomed_id = Session.last.id

      token = sign_in["access_token"]
      delete "/api/apps/#{client.client_id}/auth/sessions/#{doomed_id}", headers: authed(token)

      expect(response).to have_http_status(:ok)
      expect(Session.find(doomed_id)).to be_revoked

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: doomed_raw }, headers: origin
      expect(response).to have_http_status(:unauthorized)
    end

    # Otherwise the endpoint is a way to log an arbitrary person out.
    it "will not revoke someone else's session" do
      stranger = create(:identity, realm: realm, email: "stranger@example.com",
                                   password: password, confirmed_at: Time.current)
      stranger_session, = Session.issue!(identity: stranger, client: client)

      token = sign_in["access_token"]
      delete "/api/apps/#{client.client_id}/auth/sessions/#{stranger_session.id}",
             headers: authed(token)

      expect(response).to have_http_status(:not_found)
      expect(stranger_session.reload).not_to be_revoked
    end
  end

  describe "DELETE /auth/sessions (log out everywhere)" do
    it "revokes every live session across every application" do
      sign_in
      sign_in(other_client)
      token = sign_in["access_token"]

      delete "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["revoked"]).to eq(3)
      expect(identity.sessions.active).to be_empty
    end

    it "leaves another identity's sessions alone" do
      stranger = create(:identity, realm: realm, email: "stranger@example.com",
                                   password: password, confirmed_at: Time.current)
      stranger_session, = Session.issue!(identity: stranger, client: client)

      token = sign_in["access_token"]
      delete "/api/apps/#{client.client_id}/auth/sessions", headers: authed(token)

      expect(stranger_session.reload).not_to be_revoked
    end
  end

  describe "DELETE /auth/sign_out" do
    # This is the finding from the live proof: it used to answer 204 for a valid
    # token, no token and a garbage token alike, and the token still worked
    # afterwards.
    it "revokes the session the presented token was minted from" do
      body = sign_in
      token = body["access_token"]
      raw = body["refresh_token"]

      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: authed(token)

      expect(response).to have_http_status(:no_content)
      expect(Session.find(claims(token)["sid"])).to be_revoked

      post "/api/apps/#{client.client_id}/auth/refresh",
           params: { refresh_token: raw }, headers: origin
      expect(response).to have_http_status(:unauthorized)
    end

    it "leaves OTHER sessions alone -- signing out here is not signing out everywhere" do
      other_raw = sign_in(other_client)["refresh_token"]
      token = sign_in["access_token"]

      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: authed(token)

      post "/api/apps/#{other_client.client_id}/auth/refresh",
           params: { refresh_token: other_raw }, headers: origin(other_client)
      expect(response).to have_http_status(:ok)
    end

    it "now requires authentication, instead of answering 204 to anyone" do
      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: origin

      expect(response).to have_http_status(:unauthorized)
    end

    it "refuses a garbage token rather than pretending to succeed" do
      delete "/api/apps/#{client.client_id}/auth/sign_out",
             headers: authed("not.a.token")

      expect(response).to have_http_status(:unauthorized)
    end
  end
end
