# frozen_string_literal: true

require "rails_helper"

# A sessions list should show DEVICES, not application-and-device pairs.
#
# Before this, one row existed per (identity, application, device), so someone
# using three applications in one browser saw three entries with nothing saying
# they were one laptop -- and no way to end that laptop's access without either
# revoking one application at a time or signing out everywhere.
#
# The grouping is the browser session that authorised each application session.
# Deliberately NOT a realm-wide refresh token, which was the other way to get a
# single row: that would make a token stolen from one application redeemable at
# every other one in the realm. Each application still holds its own
# client-scoped refresh token; only the GROUPING is shared.
RSpec.describe "device-grouped sessions" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: true) }
  let(:client) do
    create(:client, realm: realm, allowed_origins: "https://app.example.com",
                    redirect_uris: "https://app.example.com/callback")
  end
  let(:second_client) do
    create(:client, realm: realm, allowed_origins: "https://second.example.com",
                    redirect_uris: "https://second.example.com/callback")
  end
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

  before { identity.grants.create!(client: second_client) }

  def origin(app) = { "Origin" => app.allowed_origins_list.first }

  def sign_in(app)
    post "/api/apps/#{app.client_id}/auth/sign_in",
         params: { email: "ada@example.com", password: password }, headers: origin(app)
    response.parsed_body
  end

  # One browser, several applications: the flow where grouping actually
  # applies. A direct credential sign-in cannot group (see the spec for that
  # below), so this is what the device list is for.
  def verifier = "a" * 64
  def challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)

  def browser_session
    @browser_session ||= begin
      session, raw = SsoSession.issue!(identity: identity)
      cookies[SsoCookie.cookie_name(realm)] = raw
      session
    end
  end

  def sign_in_via_sso(app)
    callback = "#{app.allowed_origins_list.first}/callback"
    browser_session

    get "/sso/authorize", params: {
      client_id: app.client_id, redirect_uri: callback, response_type: "code",
      state: "s", code_challenge: challenge, code_challenge_method: "S256"
    }
    code = URI.decode_www_form(URI.parse(response.headers["Location"]).query).to_h.fetch("code")

    post "/api/apps/#{app.client_id}/auth/token",
         params: { grant_type: "authorization_code", code: code,
                   code_verifier: verifier, redirect_uri: callback },
         headers: origin(app)
    response.parsed_body
  end

  def list(app, token)
    get "/api/apps/#{app.client_id}/auth/sessions",
        headers: origin(app).merge("Authorization" => "Bearer #{token}")
    response.parsed_body["sessions"]
  end

  describe "a session minted from a credential" do
    it "is grouped by the browser session issued alongside it" do
      sign_in(client)

      session = Session.order(:created_at).last
      expect(session.sso_session).to be_present
      expect(session.device_group_id).to eq(session.sso_session_id)
    end

    # Two DIRECT credential sign-ins are two devices, and that is correct
    # rather than a gap being tolerated.
    #
    # The single sign-on cookie is path-scoped to /sso, so a sign-in posted to
    # /api never carries it and this server cannot know the browser already
    # holds a session. Widening that path to make the grouping work would hand
    # the realm-wide credential to every credential endpoint, which is the one
    # thing its path scope exists to prevent. A tidier device list is not worth
    # that, so each credential sign-in mints its own browser session and groups
    # as itself.
    it "treats two direct credential sign-ins as separate devices" do
      sign_in(client)
      sign_in(second_client)

      sessions = identity.sessions.active.to_a
      expect(sessions.size).to eq(2)
      expect(sessions.map(&:device_group_id).uniq.size).to eq(2)
    end

    it "keeps each application's refresh token scoped to its own application" do
      first = sign_in(client)

      # Grouping must not have widened the credential. The refresh token from
      # one application stays useless at another even though they share a device.
      post "/api/apps/#{second_client.client_id}/auth/refresh",
           params: { refresh_token: first["refresh_token"] }, headers: origin(second_client)

      expect(response).not_to have_http_status(:ok)
    end
  end

  describe "single sign-on, where one browser authorises several applications" do
    it "groups them under one device" do
      first = sign_in_via_sso(client)
      second = sign_in_via_sso(second_client)

      expect(first["access_token"]).to be_present
      expect(second["access_token"]).to be_present

      sessions = identity.sessions.active.to_a
      expect(sessions.size).to eq(2)
      expect(sessions.map(&:client_id).uniq.size).to eq(2)

      # The point of the whole change: two applications, one device.
      expect(sessions.map(&:device_group_id).uniq).to eq([ browser_session.id ])
    end

    it "does not re-issue the browser session on the exchange" do
      sign_in_via_sso(client)
      sign_in_via_sso(second_client)

      # An absolute twelve-hour lifetime, not a sliding one: exchanging a code
      # must not extend the browser session that authorised it.
      expect(identity.sso_sessions.count).to eq(1)
    end
  end

  describe "a realm with single sign-on disabled" do
    let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: false) }

    it "mints a session that groups as itself rather than failing" do
      sign_in(client)

      session = Session.order(:created_at).last
      expect(session.sso_session_id).to be_nil
      expect(session.device_group_id).to eq(session.id)
    end
  end

  describe "the sessions list" do
    it "reports a device_id so a client can group the rows it is given" do
      body = sign_in_via_sso(client)
      sign_in_via_sso(second_client)

      rows = list(client, body["access_token"])

      expect(rows.size).to eq(2)
      expect(rows.map { |r| r["device_id"] }.uniq.size).to eq(1)
      expect(rows.map { |r| r["client_id"] }.uniq.size).to eq(2)
    end
  end

  describe "revoking a device" do
    it "ends every application on that device, and only that device" do
      first = sign_in_via_sso(client)
      sign_in_via_sso(second_client)
      device_id = identity.sessions.active.first.device_group_id

      # A second browser, which must survive.
      other_browser = SsoSession.issue!(identity: identity).first
      survivor = Session.issue!(identity: identity, client: client, sso_session: other_browser).first

      delete "/api/apps/#{client.client_id}/auth/devices/#{device_id}",
             headers: origin(client).merge("Authorization" => "Bearer #{first["access_token"]}")

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["revoked"]).to eq(2)
      expect(survivor.reload).to be_active
      expect(other_browser.reload).to be_active
    end

    it "revokes the browser session too, so /authorize cannot mint a new one" do
      first = sign_in_via_sso(client)
      sso_session = Session.order(:created_at).last.sso_session

      delete "/api/apps/#{client.client_id}/auth/devices/#{sso_session.id}",
             headers: origin(client).merge("Authorization" => "Bearer #{first["access_token"]}")

      expect(response).to have_http_status(:ok)
      expect(sso_session.reload).to be_revoked
    end

    it "accepts an ungrouped session's own id" do
      standalone = Session.issue!(identity: identity, client: client).first
      body = sign_in(client)

      delete "/api/apps/#{client.client_id}/auth/devices/#{standalone.id}",
             headers: origin(client).merge("Authorization" => "Bearer #{body["access_token"]}")

      expect(response).to have_http_status(:ok)
      expect(standalone.reload).to be_revoked
    end

    it "is a 404 for a device belonging to someone else" do
      other = create(:identity, realm: realm, signup_client: client, confirmed_at: Time.current)
      theirs = SsoSession.issue!(identity: other).first
      Session.issue!(identity: other, client: client, sso_session: theirs)
      body = sign_in(client)

      delete "/api/apps/#{client.client_id}/auth/devices/#{theirs.id}",
             headers: origin(client).merge("Authorization" => "Bearer #{body["access_token"]}")

      expect(response).to have_http_status(:not_found)
      expect(theirs.reload).to be_active
    end
  end

  describe "revoking the browser session directly" do
    it "cascades to the application sessions it authorised" do
      sign_in_via_sso(client)
      sign_in_via_sso(second_client)

      sso_session = identity.sso_sessions.active.first
      sso_session.revoke!

      expect(identity.sessions.active).to be_empty
    end

    it "leaves another browser's sessions alone" do
      sign_in_via_sso(client)
      first_browser = identity.sso_sessions.active.first

      second_browser = SsoSession.issue!(identity: identity).first
      survivor = Session.issue!(identity: identity, client: client, sso_session: second_browser).first

      first_browser.revoke!

      expect(survivor.reload).to be_active
    end
  end
end
