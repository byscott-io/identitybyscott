# frozen_string_literal: true

require "rails_helper"

# The single sign-on cookie: the one cookie this server sets.
#
# This repository's "API only" rule forbids cookies precisely because an ambient
# credential is one that can be used without being presented deliberately. This
# is the exception, so the exception is what gets specced -- and the central
# claim is NEGATIVE: the cookie exists, and authenticates nothing.
#
# The attribute assertions read the raw Set-Cookie header rather than the
# `cookies` jar, because the jar reports the value and drops exactly the flags
# that matter. HttpOnly, SameSite and Path are enforced by the browser from that
# header, so the header is the thing worth asserting on.
RSpec.describe "the single sign-on cookie" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: true) }
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

  def origin(app = client) = { "Origin" => app.allowed_origins_list.first }

  def sign_in(app = client, email: "ada@example.com", pass: nil)
    post "/api/apps/#{app.client_id}/auth/sign_in",
         params: { email: email, password: pass || password }, headers: origin(app)
    response.parsed_body
  end

  # The Set-Cookie line for our cookie, as the browser will receive it.
  def set_cookie_header
    Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
                                        .find { |h| h.start_with?("#{SsoCookie.cookie_name(realm)}=") }
  end

  describe "when the realm has single sign-on enabled" do
    it "is set on sign-in" do
      sign_in

      expect(set_cookie_header).to be_present
      expect(identity.sso_sessions.active.count).to eq(1)
    end

    # Each flag here is a separate way the cookie could leak or be driven by
    # someone else's page, so each is asserted on its own.
    describe "its attributes" do
      before { sign_in }

      # An XSS anywhere in the realm would otherwise read a credential good at
      # every other application in it.
      it "is HttpOnly, so script cannot read it" do
        expect(set_cookie_header).to match(/;\s*HttpOnly/i)
      end

      # Lax, never None. Lax still rides a top-level navigation, which is how
      # /authorize will be reached; None would hand the cookie to any site that
      # embeds us, and Strict would break the navigation the flow depends on.
      it "is SameSite=Lax" do
        expect(set_cookie_header).to match(/;\s*SameSite=Lax/i)
        expect(set_cookie_header).not_to match(/SameSite=None/i)
      end

      # The browser will not attach it to /api at all, so no credential
      # endpoint, token endpoint or authenticated call ever sees it.
      it "is scoped to the SSO path and not to the API" do
        expect(set_cookie_header).to match(%r{;\s*path=/sso}i)
        expect(SsoCookie::COOKIE_PATH).to eq("/sso")
      end

      # Host-only. A Domain attribute would broadcast the realm's credential to
      # every sibling host under that parent.
      it "sets no Domain, so it stays host-only" do
        expect(set_cookie_header).not_to match(/;\s*domain=/i)
      end

      it "carries an explicit expiry rather than lasting as long as the browser" do
        expect(set_cookie_header).to match(/;\s*expires=/i)
      end

      # Only the digest is persisted, so the header value must not appear in the
      # table. A dump of sso_sessions is then worth nothing on its own.
      it "sends a value the database does not contain" do
        value = set_cookie_header[/#{SsoCookie.cookie_name(realm)}=([^;]+)/, 1]

        expect(value).to be_present
        expect(SsoSession.where(token_digest: value)).to be_empty
        expect(SsoSession.last.token_digest).to eq(Digest::SHA256.hexdigest(CGI.unescape(value)))
      end
    end
  end

  # The flag is the control. A realm that has not asked for single sign-on must
  # not acquire a realm-wide credential as a side effect of someone signing in.
  describe "when the realm has single sign-on disabled" do
    let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: false) }

    it "sets no cookie" do
      sign_in

      expect(set_cookie_header).to be_nil
    end

    it "records no realm session" do
      expect { sign_in }.not_to change(SsoSession, :count)
    end
  end

  # The cookie belongs to a COMPLETED authentication. Issuing it beside the
  # password would make the second factor optional for anyone who then walked
  # to another application in the realm.
  describe "with MFA enabled" do
    before { identity.update!(mfa_enabled: true, mfa_secret: ROTP::Base32.random) }

    it "sets no cookie at the challenge stage" do
      body = sign_in

      expect(body["mfa_required"]).to be(true)
      expect(set_cookie_header).to be_nil
      expect(SsoSession.count).to eq(0)
    end

    it "sets it once the second factor is accepted" do
      token = sign_in["mfa_token"]
      code = ROTP::TOTP.new(identity.mfa_secret).now

      post "/api/apps/#{client.client_id}/auth/verify_mfa",
           params: { mfa_token: token, code: code }, headers: origin

      expect(response).to have_http_status(:ok)
      expect(set_cookie_header).to be_present
    end
  end

  # The heart of this slice. The cookie is issued, and it is not a credential
  # for anything -- no endpoint reads it, and presenting it buys nothing.
  describe "what the cookie can be used for" do
    it "authenticates nothing: the API still demands a bearer token" do
      _session, raw = SsoSession.issue!(identity: identity)
      cookies[SsoCookie.cookie_name(realm)] = raw

      get "/api/apps/#{client.client_id}/auth/sessions", headers: origin

      expect(response).to have_http_status(:unauthorized)
    end

    it "cannot stand in for a bearer token on any authenticated route" do
      _session, raw = SsoSession.issue!(identity: identity)
      cookies[SsoCookie.cookie_name(realm)] = raw

      [
        [ :get, "auth/sessions" ],
        [ :delete, "auth/sessions" ],
        [ :delete, "auth/sign_out" ]
      ].each do |method, path|
        public_send(method, "/api/apps/#{client.client_id}/#{path}", headers: origin)

        expect(response).to have_http_status(:unauthorized),
                            "#{method.to_s.upcase} #{path} accepted the SSO cookie as authentication"
      end
    end

    # Guards against the cookie being read anywhere in the API by accident --
    # a `cookies[...]` added to a controller later would show up here.
    it "is not read by any controller under app/controllers/api" do
      readers = Dir[Rails.root.join("app/controllers/api/**/*.rb")].select do |file|
        File.read(file).match?(/cookies\s*\[/)
      end

      expect(readers).to be_empty
    end
  end

  describe "revocation" do
    def bearer = { "Authorization" => "Bearer #{sign_in["access_token"]}" }

    # Otherwise signing out would be decorative: the application would bounce
    # through /authorize, the cookie would still be good, and the person would
    # be signed straight back in without a password.
    it "signing out of one application ends the realm session" do
      headers = bearer.merge(origin)
      expect(identity.sso_sessions.active.count).to eq(1)

      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: headers

      expect(response).to have_http_status(:no_content)
      expect(identity.sso_sessions.active.count).to eq(0)
    end

    it "clears the cookie from the browser as well as revoking the row" do
      headers = bearer.merge(origin)

      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: headers

      # A clearing Set-Cookie has to carry the same path, or the browser keeps
      # the original and only shadows it.
      expect(set_cookie_header).to match(%r{path=/sso}i)
      expect(set_cookie_header).to match(/\A#{SsoCookie.cookie_name(realm)}=;/)
      # An expiry in the past is what actually removes it.
      expect(set_cookie_header).to match(/expires=Thu, 01 Jan 1970/i)
    end

    it "logging out everywhere ends the realm session too" do
      headers = bearer.merge(origin)

      delete "/api/apps/#{client.client_id}/auth/sessions", headers: headers

      expect(response).to have_http_status(:ok)
      expect(identity.sso_sessions.active.count).to eq(0)
    end

    # It is revoked, not deleted: the row stays as a record that the browser
    # session existed and when it ended.
    it "revokes rather than deletes" do
      headers = bearer.merge(origin)

      expect { delete "/api/apps/#{client.client_id}/auth/sign_out", headers: headers }
        .not_to change(SsoSession, :count)

      expect(SsoSession.last.revoked_at).to be_present
    end
  end

  # Still no Rails session, no flash and no CSRF token. The middleware came back
  # for one cookie; it did not bring an ambient credential for the API with it.
  describe "the rest of the cookie-free design" do
    it "adds no session or flash middleware" do
      middleware = Rails.application.middleware.map(&:name)

      expect(middleware).to include("ActionDispatch::Cookies")
      expect(middleware).not_to include("ActionDispatch::Session::CookieStore")
      expect(middleware).not_to include("ActionDispatch::Flash")
    end

    it "sets no other cookie on sign-in" do
      sign_in

      names = Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
                                                   .map { |h| h[/\A([^=]+)=/, 1] }

      expect(names).to eq([ SsoCookie.cookie_name(realm) ])
    end
  end
end
