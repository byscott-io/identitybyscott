# frozen_string_literal: true

require "rails_helper"

# Two realms, one browser.
#
# The single sign-on cookie lives on this server's host, so every realm's cookie
# shares a host and a path. A single shared NAME would therefore give them one
# slot, and the second realm's sign-in would evict the first's.
#
# That failure is quiet, which is why it is specced. Nothing leaks -- /authorize
# refuses a cookie whose identity belongs to another realm -- but single sign-on
# stops working for whichever realm the browser touched least recently, and the
# symptom is "it asks me to log in again sometimes".
#
# Nothing exercised this before, because production has only ever had one realm.
# These examples are the reason the name carries the realm key.
RSpec.describe "single sign-on across two realms" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }

  let(:realm_a) { create(:realm, key: "suite-a", require_email_confirmation: false, sso_enabled: true) }
  let(:realm_b) { create(:realm, key: "suite-b", require_email_confirmation: false, sso_enabled: true) }

  let(:callback_a) { "https://a.example.com/auth/callback" }
  let(:callback_b) { "https://b.example.com/auth/callback" }

  let(:client_a) do
    create(:client, realm: realm_a, redirect_uris: callback_a, allowed_origins: "https://a.example.com")
  end
  let(:client_b) do
    create(:client, realm: realm_b, redirect_uris: callback_b, allowed_origins: "https://b.example.com")
  end

  let(:password) { "correct horse battery staple" }

  # The SAME address in both realms, deliberately. Email is unique per realm, so
  # these are two unrelated people as far as this server is concerned -- which is
  # exactly the case where sharing one cookie slot would be most confusing.
  let!(:identity_a) do
    create(:identity, realm: realm_a, signup_client: client_a, email: "ada@example.com",
                      password: password, confirmed_at: Time.current)
  end
  let!(:identity_b) do
    create(:identity, realm: realm_b, signup_client: client_b, email: "ada@example.com",
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

  def verifier = @verifier ||= SecureRandom.urlsafe_base64(64)
  def challenge
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(verifier), padding: false)
  end

  # A realm session for this browser, exactly as the hosted login page would
  # leave one.
  def sign_in_browser(identity, realm)
    _session, raw = SsoSession.issue!(identity: identity)
    cookies[SsoCookie.cookie_name(realm)] = raw
  end

  def authorize(client, redirect_uri)
    get "/sso/authorize", params: {
      client_id: client.client_id, redirect_uri: redirect_uri, response_type: "code",
      state: "opaque-state", code_challenge: challenge, code_challenge_method: "S256"
    }
  end

  def outcome
    location = URI.parse(response.headers["Location"].to_s)
    return :form if location.path == "/sso/login"

    query = URI.decode_www_form(location.query.to_s).to_h
    query["code"].present? ? :code : query["error"]&.to_sym
  end

  describe "the cookie names" do
    it "differ, and carry the realm key" do
      expect(SsoCookie.cookie_name(realm_a)).to eq("identity_sso_suite-a")
      expect(SsoCookie.cookie_name(realm_b)).to eq("identity_sso_suite-b")
      expect(SsoCookie.cookie_name(realm_a)).not_to eq(SsoCookie.cookie_name(realm_b))
    end

    # No unsuffixed fallback. A fallback would be the shared slot again, reached
    # by whichever path forgot to pass a realm.
    it "cannot be derived without a realm" do
      expect { SsoCookie.cookie_name(nil) }.to raise_error(ArgumentError, /realm is required/)
    end

    # Realm validates its key, but that is model-level: update_column and raw
    # SQL bypass it, and this is where a key becomes part of an HTTP header.
    # Rack refuses a malformed name anyway, so the point of checking here is a
    # failure that names the realm rather than one raised from inside Rack.
    it "refuses a key that bypassed validation" do
      realm_a.update_column(:key, "bad key;Path=/;x")

      expect { SsoCookie.cookie_name(realm_a.reload) }
        .to raise_error(ArgumentError, /cannot be used in a cookie name/)
    end

    it "accepts the shapes a realm key is allowed to take" do
      %w[churchcare suite-a suite_b a1 0x].each do |key|
        realm_a.update_column(:key, key)
        expect(SsoCookie.cookie_name(realm_a.reload)).to eq("identity_sso_#{key}")
      end
    end
  end

  describe "signing in to the second realm" do
    # THE regression this change exists to prevent.
    it "leaves the first realm's session usable" do
      sign_in_browser(identity_a, realm_a)
      sign_in_browser(identity_b, realm_b)

      authorize(client_a, callback_a)
      expect(outcome).to eq(:code)
    end

    it "and the second realm's session works too, in the same browser" do
      sign_in_browser(identity_a, realm_a)
      sign_in_browser(identity_b, realm_b)

      authorize(client_b, callback_b)
      expect(outcome).to eq(:code)
    end

    it "keeps both cookies, rather than one slot" do
      sign_in_browser(identity_a, realm_a)
      sign_in_browser(identity_b, realm_b)

      expect(cookies[SsoCookie.cookie_name(realm_a)]).to be_present
      expect(cookies[SsoCookie.cookie_name(realm_b)]).to be_present
      expect(cookies[SsoCookie.cookie_name(realm_a)]).not_to eq(cookies[SsoCookie.cookie_name(realm_b)])
    end
  end

  # Isolation still holds: separate names are a usability fix, not the security
  # boundary, and the realm check remains the thing that stops a crossing.
  describe "realm isolation" do
    it "will not answer one realm's client from the other realm's session" do
      sign_in_browser(identity_b, realm_b)

      authorize(client_a, callback_a)

      expect(outcome).to eq(:form)
    end

    it "shows the form rather than disclosing that another realm's session exists" do
      sign_in_browser(identity_b, realm_b)

      authorize(client_a, callback_a)

      expect(response).to have_http_status(:see_other)
      expect(URI.parse(response.headers["Location"]).path).to eq("/sso/login")
    end
  end

  describe "signing out of one realm" do
    it "does not disturb the other realm's session" do
      sign_in_browser(identity_a, realm_a)
      sign_in_browser(identity_b, realm_b)

      token = JSON.parse(
        begin
          post "/api/apps/#{client_a.client_id}/auth/sign_in",
               params: { email: "ada@example.com", password: password },
               headers: { "Origin" => "https://a.example.com" }
          response.body
        end
      )["access_token"]

      delete "/api/apps/#{client_a.client_id}/auth/sign_out",
             headers: { "Authorization" => "Bearer #{token}", "Origin" => "https://a.example.com" }

      expect(response).to have_http_status(:ok)
      expect(identity_b.sso_sessions.active.count).to eq(1)

      authorize(client_b, callback_b)
      expect(outcome).to eq(:code)
    end
  end
end
