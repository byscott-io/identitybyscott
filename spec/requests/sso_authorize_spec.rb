# frozen_string_literal: true

require "rails_helper"

# GET /sso/authorize -- the only endpoint that reads the single sign-on cookie.
#
# It is silent or nothing: this server has no hosted login page, so /authorize
# either answers from an existing realm session or returns login_required and
# the application shows its own form.
#
# Two properties dominate these specs. First, the ORDER of validation: nothing
# is ever redirected until the redirect_uri is known to be registered to the
# client, because an open redirect on an endpoint that mints credentials is how
# codes reach an attacker. Second, REALM ISOLATION: the cookie proves a browser
# is someone in some realm, and says nothing about whether it is this client's.
RSpec.describe "GET /sso/authorize" do
  let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: true) }
  let(:callback) { "https://app.example.com/auth/callback" }
  let(:client) { create(:client, realm: realm, redirect_uris: callback) }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: client, confirmed_at: Time.current)
  end

  let(:verifier) { SecureRandom.urlsafe_base64(64) }
  let(:challenge) do
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(verifier), padding: false)
  end

  def params(**overrides)
    {
      client_id: client.client_id,
      redirect_uri: callback,
      response_type: "code",
      state: "opaque-state",
      code_challenge: challenge,
      code_challenge_method: "S256"
    }.merge(overrides)
  end

  def sign_in_browser(for_identity = identity)
    _session, raw = SsoSession.issue!(identity: for_identity)
    cookies[SsoCookie::COOKIE_NAME] = raw
  end

  def authorize(**overrides)
    get "/sso/authorize", params: params(**overrides)
  end

  def location = URI.parse(response.headers["Location"].to_s)
  def query = URI.decode_www_form(location.query.to_s).to_h

  # ---------------------------------------------------------------------------
  # Answered locally, because there is nowhere safe to redirect yet.
  # ---------------------------------------------------------------------------
  describe "before the redirect_uri is trusted" do
    it "refuses an unknown client without redirecting" do
      authorize(client_id: "no-such-app")

      expect(response).to have_http_status(:bad_request)
      expect(response.headers["Location"]).to be_nil
    end

    it "refuses an inactive client" do
      client.update!(active: false)
      authorize

      expect(response).to have_http_status(:bad_request)
      expect(response.headers["Location"]).to be_nil
    end

    # THE open-redirect property. An unregistered URI must never appear in a
    # Location header -- not even carrying an error -- or this endpoint becomes
    # a way to bounce a browser anywhere, on a host the realm trusts.
    it "refuses an unregistered redirect_uri WITHOUT redirecting to it" do
      authorize(redirect_uri: "https://attacker.test/steal")

      expect(response).to have_http_status(:bad_request)
      expect(response.headers["Location"]).to be_nil
      expect(response.body).not_to include("attacker.test")
    end

    # The same near-misses slice 1 specced on the model, now proven to be
    # refused by the endpoint rather than merely refusable.
    {
      "a suffix on the host" => "https://app.example.com.attacker.test/auth/callback",
      "a different path" => "https://app.example.com/anything-else",
      "a trailing slash" => "https://app.example.com/auth/callback/",
      "an appended query" => "https://app.example.com/auth/callback?next=//attacker.test",
      "an appended fragment" => "https://app.example.com/auth/callback#x",
      "plain http" => "http://app.example.com/auth/callback",
      "another port" => "https://app.example.com:8443/auth/callback",
      "a case-changed host" => "https://APP.example.com/auth/callback",
      "a prefix of the registered URI" => "https://app.example.com/auth"
    }.each do |description, uri|
      it "refuses #{description}, and sends nothing to it" do
        sign_in_browser
        authorize(redirect_uri: uri)

        expect(response).to have_http_status(:bad_request)
        expect(response.headers["Location"]).to be_nil
      end
    end

    it "mints no code when the redirect_uri is unregistered" do
      sign_in_browser

      expect { authorize(redirect_uri: "https://attacker.test/steal") }
        .not_to change(AuthorizationCode, :count)
    end

    it "refuses a missing redirect_uri" do
      authorize(redirect_uri: nil)

      expect(response).to have_http_status(:bad_request)
    end

    # Byte-identical, not merely similar. The credential endpoints already
    # refuse to let an unknown client_id be distinguished so this server cannot
    # be used to enumerate applications; the same must hold here, or a real
    # client with a wrong URI and an invented client could be told apart.
    it "answers an unknown client and an unregistered URI identically" do
      authorize(client_id: "no-such-app")
      unknown = [ response.status, response.body ]

      authorize(redirect_uri: "https://attacker.test/steal")

      expect([ response.status, response.body ]).to eq(unknown)
    end

    it "leaks no reason into the body at all" do
      authorize(redirect_uri: "https://attacker.test/steal")

      expect(response.parsed_body).to eq({ "error" => "invalid_request" })
    end
  end

  # ---------------------------------------------------------------------------
  # Answered by redirect, to a URI this client registered.
  # ---------------------------------------------------------------------------
  describe "request validation" do
    it "refuses a response_type other than code" do
      sign_in_browser
      authorize(response_type: "token")

      expect(response).to have_http_status(:found)
      expect(query["error"]).to eq("unsupported_response_type")
    end

    it "requires state" do
      sign_in_browser
      authorize(state: nil)

      expect(query["error"]).to eq("invalid_request")
      # Nothing to echo, and nothing invented.
      expect(query).not_to have_key("state")
    end

    it "requires a PKCE challenge" do
      sign_in_browser
      authorize(code_challenge: nil)

      expect(query["error"]).to eq("invalid_request")
    end

    # plain puts the verifier in the same request as the code, which defeats the
    # only thing PKCE is for.
    it "refuses the plain challenge method" do
      sign_in_browser
      authorize(code_challenge_method: "plain")

      expect(query["error"]).to eq("invalid_request")
    end

    # OAuth defaults an absent method to plain. Defaulting it to S256 instead
    # would silently accept a client that thinks it is doing something weaker.
    it "refuses an absent challenge method rather than assuming S256" do
      sign_in_browser
      authorize(code_challenge_method: nil)

      expect(query["error"]).to eq("invalid_request")
    end

    it "refuses a prompt it does not implement" do
      sign_in_browser
      authorize(prompt: "consent")

      expect(query["error"]).to eq("invalid_request")
    end

    it "echoes state on an error so the application can correlate it" do
      sign_in_browser
      authorize(response_type: "token")

      expect(query["state"]).to eq("opaque-state")
    end

    it "mints no code for any malformed request" do
      sign_in_browser

      expect {
        authorize(response_type: "token")
        authorize(code_challenge: nil)
        authorize(code_challenge_method: "plain")
        authorize(prompt: "consent")
      }.not_to change(AuthorizationCode, :count)
    end
  end

  describe "when the browser holds no realm session" do
    it "answers login_required so the application can show its own form" do
      authorize

      expect(response).to have_http_status(:found)
      expect(location.host).to eq("app.example.com")
      expect(query["error"]).to eq("login_required")
      expect(query).not_to have_key("code")
    end

    it "answers login_required for a revoked session" do
      _s, raw = SsoSession.issue!(identity: identity)
      SsoSession.authenticate(raw).revoke!
      cookies[SsoCookie::COOKIE_NAME] = raw

      authorize

      expect(query["error"]).to eq("login_required")
    end

    it "answers login_required for an expired session" do
      session, raw = SsoSession.issue!(identity: identity)
      session.update_column(:expires_at, 1.second.ago)
      cookies[SsoCookie::COOKIE_NAME] = raw

      authorize

      expect(query["error"]).to eq("login_required")
    end

    it "answers login_required for a garbage cookie" do
      cookies[SsoCookie::COOKIE_NAME] = SecureRandom.urlsafe_base64(32)

      authorize

      expect(query["error"]).to eq("login_required")
    end
  end

  # The flag is a real control at the endpoint, not only in the model.
  describe "when the realm has single sign-on disabled" do
    it "answers login_required even with a live session" do
      sign_in_browser
      realm.update!(sso_enabled: false)

      authorize

      expect(query["error"]).to eq("login_required")
      expect(query).not_to have_key("code")
    end

    it "mints no code" do
      sign_in_browser
      realm.update!(sso_enabled: false)

      expect { authorize }.not_to change(AuthorizationCode, :count)
    end
  end

  describe "prompt=login" do
    it "refuses to answer from the cookie, even though it is good" do
      sign_in_browser

      authorize(prompt: "login")

      expect(query["error"]).to eq("login_required")
      expect(query).not_to have_key("code")
    end

    it "mints no code" do
      sign_in_browser

      expect { authorize(prompt: "login") }.not_to change(AuthorizationCode, :count)
    end
  end

  # ---------------------------------------------------------------------------
  # Realm isolation. The cookie says "someone in SOME realm".
  # ---------------------------------------------------------------------------
  describe "a session in a different realm" do
    let(:other_realm) { create(:realm, sso_enabled: true) }
    let(:other_identity) { create(:identity, realm: other_realm) }

    it "is refused, and told nothing about the other realm" do
      sign_in_browser(other_identity)

      authorize

      # Identical to having no session at all. A distinct answer would tell the
      # application this browser is signed in to a realm it cannot see.
      expect(query["error"]).to eq("login_required")
      expect(query).not_to have_key("code")
    end

    it "mints no code" do
      sign_in_browser(other_identity)

      expect { authorize }.not_to change(AuthorizationCode, :count)
    end

    # Even if the same address exists in both realms, they are different people
    # and one's session must not authorise the other's applications.
    it "is refused when the same email exists in both realms" do
      shared = create(:identity, realm: other_realm, email: identity.email)
      sign_in_browser(shared)

      authorize

      expect(query["error"]).to eq("login_required")
    end
  end

  describe "an identity with no grant for the application" do
    let(:ungranted_client) do
      create(:client, realm: realm, redirect_uris: "https://other.example.com/cb")
    end

    it "is refused with access_denied, not login_required" do
      sign_in_browser

      get "/sso/authorize", params: params(
        client_id: ungranted_client.client_id, redirect_uri: "https://other.example.com/cb"
      )

      # access_denied because signing in again would change nothing -- a
      # login_required here would send the application round a loop.
      expect(query["error"]).to eq("access_denied")
      expect(query).not_to have_key("code")
    end

    it "mints no code" do
      sign_in_browser

      expect {
        get "/sso/authorize", params: params(
          client_id: ungranted_client.client_id, redirect_uri: "https://other.example.com/cb"
        )
      }.not_to change(AuthorizationCode, :count)
    end
  end

  # ---------------------------------------------------------------------------
  describe "the silent success" do
    before { sign_in_browser }

    it "redirects to the registered callback with a code and the state" do
      authorize

      expect(response).to have_http_status(:found)
      expect(location.host).to eq("app.example.com")
      expect(location.path).to eq("/auth/callback")
      expect(query["code"]).to be_present
      expect(query["state"]).to eq("opaque-state")
      expect(query).not_to have_key("error")
    end

    it "mints exactly one code" do
      expect { authorize }.to change(AuthorizationCode, :count).by(1)
    end

    # The code is in a URL, so only its digest may be stored.
    it "sends a code the database does not contain" do
      authorize
      raw = query["code"]

      expect(AuthorizationCode.where(code_digest: raw)).to be_empty
      expect(AuthorizationCode.last.code_digest).to eq(Digest::SHA256.hexdigest(raw))
    end

    it "binds the code to the client, the URI, the challenge and the session" do
      authorize
      code = AuthorizationCode.last

      expect(code.client).to eq(client)
      expect(code.identity).to eq(identity)
      expect(code.redirect_uri).to eq(callback)
      expect(code.code_challenge).to eq(challenge)
      expect(code.code_challenge_method).to eq("S256")
      expect(code.sso_session).to eq(identity.sso_sessions.active.first)
    end

    it "stores nonce and scope when given" do
      authorize(nonce: "n-123", scope: "openid profile")
      code = AuthorizationCode.last

      expect(code.nonce).to eq("n-123")
      expect(code.scope).to eq("openid profile")
    end

    it "expires the code in a minute" do
      authorize

      expect(AuthorizationCode.last.expires_at).to be_within(5.seconds).of(1.minute.from_now)
    end

    it "records that the realm session was used" do
      session = identity.sso_sessions.active.first
      session.update_column(:last_used_at, 2.hours.ago)

      authorize

      expect(session.reload.last_used_at).to be_within(5.seconds).of(Time.current)
    end

    # A registered callback may legitimately carry its own parameters, and
    # replacing its query would break it in a way that looks like the
    # application's bug.
    context "when the registered URI already has a query" do
      let(:callback) { "https://app.example.com/auth/callback?tenant=north" }

      it "appends rather than clobbering" do
        authorize

        expect(query["tenant"]).to eq("north")
        expect(query["code"]).to be_present
      end
    end

    it "treats an absent prompt as the silent case" do
      authorize(prompt: nil)

      expect(query["code"]).to be_present
    end

    it "accepts prompt=none explicitly" do
      authorize(prompt: "none")

      expect(query["code"]).to be_present
    end

    # No token may ever come back in a fragment. That is the implicit flow, and
    # it puts credentials in a place the browser hands to script.
    it "returns no token, only a code" do
      authorize

      expect(location.fragment).to be_nil
      expect(query).not_to have_key("access_token")
      expect(query).not_to have_key("id_token")
    end
  end

  describe "discovery" do
    around do |example|
      ENV["IDENTITY_ISSUER"] = "https://identity.test"
      example.run
    ensure
      ENV.delete("IDENTITY_ISSUER")
    end

    it "advertises the endpoint, S256 only, and no implicit flow" do
      get "/.well-known/openid-configuration"
      body = response.parsed_body

      expect(body["authorization_endpoint"]).to eq("https://identity.test/sso/authorize")
      expect(body["response_types_supported"]).to eq([ "code" ])
      expect(body["code_challenge_methods_supported"]).to eq([ "S256" ])
      expect(body["prompt_values_supported"]).to eq(%w[none login])
    end

    # Not an omission waiting to be filled. The exchange exists, but this
    # server's token endpoint is per-application, because a preflight can see
    # only the URL and the client has to be in the path for the origin check to
    # work. OIDC publishes one token_endpoint, so there is no single URL to
    # publish -- and a placeholder would be worse than silence.
    it "advertises no token_endpoint, because there is no single URL to give" do
      get "/.well-known/openid-configuration"

      expect(response.parsed_body).not_to have_key("token_endpoint")
    end
  end
end
