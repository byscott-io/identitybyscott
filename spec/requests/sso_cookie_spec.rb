# frozen_string_literal: true

require "rails_helper"

# The single sign-on cookie: the one cookie this server sets.
#
# This repository's "API only" rule forbids cookies precisely because an ambient
# credential is one that can be used without being presented deliberately. This
# is the exception, so the exception is what gets specced -- and the central
# claim is NEGATIVE: the cookie exists, and authenticates nothing.
#
# It is established at /sso/bootstrap and NOWHERE ELSE, during a top-level
# navigation. It cannot be established at sign-in, and these specs assert that it
# is not: this server is on a different registrable domain from every application
# it serves, so a cookie set in reply to a cross-site XHR is refused by Safari's
# tracking prevention and partitioned by Firefox's -- filed under the
# application's own top-level site, invisible to every other application in the
# realm, which is the only thing single sign-on is for.
#
# The attribute assertions read the raw Set-Cookie header rather than the
# `cookies` jar, because the jar reports the value and drops exactly the flags
# that matter.
RSpec.describe "the single sign-on cookie" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: true) }
  let(:return_to) { "https://app.example.com/signed-in" }
  let(:client) do
    create(:client, realm: realm, allowed_origins: "https://app.example.com",
                    redirect_uris: return_to)
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

  def origin(app = client) = { "Origin" => app.allowed_origins_list.first }

  def sign_in(app = client, email: "ada@example.com", pass: nil)
    post "/api/apps/#{app.client_id}/auth/sign_in",
         params: { email: email, password: pass || password }, headers: origin(app)
    response.parsed_body
  end

  # The real two-step: sign in for a token, then submit it as a top-level POST
  # from a page on the application's own origin.
  #
  # A POST because only a POST carries an Origin header, which is what stops
  # anyone who can make a browser follow a link from planting a session in it.
  def bootstrap(token: nil, to: nil, from: "https://app.example.com")
    token ||= sign_in["sso_bootstrap_token"]
    headers = from.nil? ? {} : { "Origin" => from }
    post "/sso/bootstrap", params: { token: token, return_to: to || return_to },
                           headers: headers
  end

  def set_cookie_header
    Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
                                        .find { |h| h.start_with?("#{SsoCookie::COOKIE_NAME}=") }
  end

  # ---------------------------------------------------------------------------
  # Sign-in cannot establish it, and must not pretend to.
  # ---------------------------------------------------------------------------
  describe "signing in" do
    it "sets no cookie, because a cross-site response cannot establish one" do
      sign_in

      expect(set_cookie_header).to be_nil
      expect(SsoSession.count).to eq(0)
    end

    it "returns a one-use bootstrap token instead" do
      body = sign_in

      expect(body["sso_bootstrap_token"]).to be_present
      expect(body["sso_bootstrap_expires_in"]).to eq(60)
    end

    # The token is the credential that establishes a realm session, so only its
    # digest may be stored.
    it "stores only a digest of the bootstrap token" do
      raw = sign_in["sso_bootstrap_token"]

      expect(SsoBootstrap.where(token_digest: raw)).to be_empty
      expect(SsoBootstrap.last.token_digest).to eq(Digest::SHA256.hexdigest(raw))
    end

    # The flag is the control. A realm that has not asked for single sign-on
    # gets no realm-wide credential as a side effect of someone signing in.
    context "when the realm has single sign-on disabled" do
      let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: false) }

      it "offers no bootstrap token at all" do
        body = sign_in

        expect(body).not_to have_key("sso_bootstrap_token")
        expect(SsoBootstrap.count).to eq(0)
      end
    end

    # A completed authentication only. Issuing this beside the password would
    # make the second factor optional for anyone who then walked to another
    # application in the realm.
    context "with MFA enabled" do
      before { identity.update!(mfa_enabled: true, mfa_secret: ROTP::Base32.random) }

      it "offers nothing at the challenge stage" do
        body = sign_in

        expect(body["mfa_required"]).to be(true)
        expect(body).not_to have_key("sso_bootstrap_token")
        expect(SsoBootstrap.count).to eq(0)
      end

      it "offers it once the second factor is accepted" do
        token = sign_in["mfa_token"]
        code = ROTP::TOTP.new(identity.mfa_secret).now

        post "/api/apps/#{client.client_id}/auth/verify_mfa",
             params: { mfa_token: token, code: code }, headers: origin

        expect(response.parsed_body["sso_bootstrap_token"]).to be_present
      end
    end
  end

  # ---------------------------------------------------------------------------
  describe "the bootstrap navigation" do
    it "establishes the cookie and sends the browser back" do
      bootstrap

      expect(response).to have_http_status(:see_other)
      expect(response.headers["Location"]).to eq(return_to)
      expect(set_cookie_header).to be_present
      expect(identity.sso_sessions.active.count).to eq(1)
    end

    describe "the cookie's attributes" do
      before { bootstrap }

      # An XSS anywhere in the realm would otherwise read a credential good at
      # every other application in it.
      it "is HttpOnly, so script cannot read it" do
        expect(set_cookie_header).to match(/;\s*HttpOnly/i)
      end

      # Lax, never None. Lax still rides a top-level navigation, which is how
      # /authorize is reached; None would hand the cookie to any site that
      # embeds us, and Strict would break that navigation.
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

      it "sends a value the database does not contain" do
        value = set_cookie_header[/#{SsoCookie::COOKIE_NAME}=([^;]+)/, 1]

        expect(value).to be_present
        expect(SsoSession.where(token_digest: value)).to be_empty
        expect(SsoSession.last.token_digest).to eq(Digest::SHA256.hexdigest(CGI.unescape(value)))
      end
    end

    describe "refusals" do
      def expect_refused
        expect(response).to have_http_status(:bad_request)
        expect(response.parsed_body).to eq({ "error" => "invalid_request" })
        expect(response.headers["Location"]).to be_nil
      end

      # THE login-CSRF case, and the reason this endpoint is a POST.
      #
      # An attacker signs in to their OWN account server-side -- where the Origin
      # check deliberately does not apply, a caller without an Origin not being a
      # browser -- and gets a valid bootstrap token for their own identity. If
      # they could then make a victim's browser spend it, that browser would hold
      # a twelve-hour cookie for the ATTACKER'S identity: silently signed in to
      # real applications as somebody else, with everything typed afterwards
      # going into the attacker's account.
      #
      # The Origin header is what closes it. A browser attaches one to a
      # top-level POST, script cannot forge it, and a referrer policy cannot
      # suppress it -- so the submission has to come from a page on an origin the
      # issuing application registered.
      it "refuses a token presented from an origin the application never registered" do
        token = sign_in["sso_bootstrap_token"]

        bootstrap(token: token, from: "https://attacker.test")

        expect_refused
      end

      it "plants no session when the origin is not allowed" do
        token = sign_in["sso_bootstrap_token"]

        bootstrap(token: token, from: "https://attacker.test")

        expect(set_cookie_header).to be_nil
        expect(SsoSession.count).to eq(0)
      end

      # A GET navigation carries no Origin at all, which is exactly why this is
      # not reachable by one. Routing must not quietly answer a link.
      it "is not reachable by a link" do
        token = sign_in["sso_bootstrap_token"]

        get "/sso/bootstrap", params: { token: token, return_to: return_to }

        expect(response).to have_http_status(:not_found)
        expect(response.headers["Location"]).to be_nil
        expect(SsoSession.count).to eq(0)
      end

      # A missing Origin is refused rather than treated as a non-browser caller.
      # Everywhere else that reasoning is right -- a server has no Origin and is
      # constrained by its credentials instead -- but here the whole question is
      # WHICH BROWSER is about to be given a session, and a request that will not
      # say is not one to answer.
      it "refuses a submission with no origin at all" do
        token = sign_in["sso_bootstrap_token"]

        bootstrap(token: token, from: nil)

        expect_refused
        expect(SsoSession.count).to eq(0)
      end

      # Another application in the same realm is still not this token's
      # application. The allowlist consulted is the issuing client's.
      it "refuses an origin belonging to a different application in the realm" do
        create(:client, realm: realm, allowed_origins: "https://sibling.example.com",
                        redirect_uris: return_to)
        token = sign_in["sso_bootstrap_token"]

        bootstrap(token: token, from: "https://sibling.example.com")

        expect_refused
      end

      it "spends the token even when the origin is refused" do
        token = sign_in["sso_bootstrap_token"]
        bootstrap(token: token, from: "https://attacker.test")

        bootstrap(token: token)

        expect_refused
      end

      it "refuses an unknown token" do
        bootstrap(token: SecureRandom.urlsafe_base64(32))

        expect_refused
      end

      it "refuses a blank token" do
        bootstrap(token: "")

        expect_refused
      end

      # Single use, and single ATTEMPT -- spent before return_to is even looked
      # at, so a failed try cannot be repeated against a different return_to.
      it "refuses a token that has already been spent" do
        token = sign_in["sso_bootstrap_token"]
        bootstrap(token: token)

        bootstrap(token: token)

        expect_refused
      end

      it "establishes no second session on a replay" do
        token = sign_in["sso_bootstrap_token"]
        bootstrap(token: token)

        expect { bootstrap(token: token) }.not_to change(SsoSession, :count)
      end

      it "refuses an expired token" do
        token = sign_in["sso_bootstrap_token"]
        SsoBootstrap.last.update_column(:expires_at, 1.second.ago)

        bootstrap(token: token)

        expect_refused
      end

      # The open-redirect property, on an endpoint that has just been asked to
      # set a credential cookie.
      it "refuses an unregistered return_to WITHOUT redirecting to it" do
        bootstrap(to: "https://attacker.test/steal")

        expect_refused
        expect(response.body).not_to include("attacker.test")
      end

      it "sets no cookie when return_to is unregistered" do
        bootstrap(to: "https://attacker.test/steal")

        expect(set_cookie_header).to be_nil
        expect(SsoSession.count).to eq(0)
      end

      # Near-misses, as everywhere else a URI is matched here.
      [
        "https://app.example.com.attacker.test/signed-in",
        "https://app.example.com/signed-in/",
        "https://app.example.com/signed-in?x=1",
        "http://app.example.com/signed-in",
        "https://APP.example.com/signed-in"
      ].each do |uri|
        it "refuses #{uri}" do
          bootstrap(to: uri)

          expect_refused
        end
      end

      it "spends the token even when return_to is refused" do
        token = sign_in["sso_bootstrap_token"]
        bootstrap(token: token, to: "https://attacker.test/steal")

        bootstrap(token: token)

        expect_refused
      end

      # The realm could have had single sign-on turned off in the minute since
      # the token was issued, and this is the request that would otherwise hand
      # out the cookie anyway.
      it "refuses once the realm has single sign-on turned off" do
        token = sign_in["sso_bootstrap_token"]
        realm.update!(sso_enabled: false)

        bootstrap(token: token)

        expect_refused
        expect(SsoSession.count).to eq(0)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # The heart of it. The cookie is established, and is a credential for nothing.
  # ---------------------------------------------------------------------------
  describe "what the cookie can be used for" do
    it "authenticates nothing: the API still demands a bearer token" do
      _session, raw = SsoSession.issue!(identity: identity)
      cookies[SsoCookie::COOKIE_NAME] = raw

      get "/api/apps/#{client.client_id}/auth/sessions", headers: origin

      expect(response).to have_http_status(:unauthorized)
    end

    it "cannot stand in for a bearer token on any authenticated route" do
      _session, raw = SsoSession.issue!(identity: identity)
      cookies[SsoCookie::COOKIE_NAME] = raw

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

    # Guards against the cookie being read anywhere in the API by accident -- a
    # `cookies[...]` added to a controller later would show up here.
    it "is not read by any controller under app/controllers/api" do
      readers = Dir[Rails.root.join("app/controllers/api/**/*.rb")].select do |file|
        File.read(file).match?(/cookies\s*\[/)
      end

      expect(readers).to be_empty
    end
  end

  describe "revocation" do
    # One full browser cycle: sign in, then spend the bootstrap token. Returns
    # the headers that browser would use, and leaves its realm session linked to
    # the session the token was issued for.
    def bearer_and_cookie
      body = sign_in
      post "/sso/bootstrap",
           params: { token: body["sso_bootstrap_token"], return_to: return_to },
           headers: origin
      { "Authorization" => "Bearer #{body['access_token']}" }.merge(origin)
    end

    # The link is what makes a narrow sign-out possible at all: a sign-out
    # arrives at /api, where the cookie's path scope keeps it from ever being
    # seen, so the session being revoked is the only thing that identifies the
    # browser.
    describe "the link between a session and its realm session" do
      it "is recorded when the bootstrap navigation establishes the cookie" do
        bearer_and_cookie

        session = identity.sessions.sole
        expect(session.sso_session).to eq(identity.sso_sessions.active.sole)
      end

      it "is absent for a realm without single sign-on" do
        other_realm = create(:realm, require_email_confirmation: false, sso_enabled: false)
        other_client = create(:client, realm: other_realm, allowed_origins: "https://app.example.com")
        person = create(:identity, realm: other_realm, signup_client: other_client,
                                   password: password, confirmed_at: Time.current)

        post "/api/apps/#{other_client.client_id}/auth/sign_in",
             params: { email: person.email, password: password }, headers: origin(other_client)

        expect(person.sessions.sole.sso_session).to be_nil
      end
    end

    # THE property this exists for. Signing out on one browser must not sign
    # the person out on their phone.
    describe "signing out of one application on one browser" do
      it "leaves another browser's realm session alone" do
        first = bearer_and_cookie
        bearer_and_cookie
        expect(identity.sso_sessions.active.count).to eq(2)

        delete "/api/apps/#{client.client_id}/auth/sign_out", headers: first

        expect(response).to have_http_status(:no_content)
        expect(identity.sso_sessions.active.count).to eq(1)
      end

      it "revokes the one belonging to the browser that asked" do
        first = bearer_and_cookie
        mine = identity.sessions.order(:created_at).first.sso_session
        bearer_and_cookie

        delete "/api/apps/#{client.client_id}/auth/sign_out", headers: first

        expect(mine.reload).to be_revoked
      end

      # Proven by using the other browser's cookie rather than by inspecting a
      # row: after the first browser signs out, the second still gets a code
      # from /authorize, which is what "still signed in" actually means.
      #
      # The second realm session is created directly so the spec holds its raw
      # cookie value, and linked to its own application session the way the
      # bootstrap navigation would. Going through the navigation twice would
      # share one cookie jar between the two simulated browsers, and the first
      # sign-out's clearing header would wipe the second's cookie -- an artefact
      # of the test, not of the server.
      it "leaves the other browser still able to authorize" do
        first = bearer_and_cookie

        other_realm_session, other_cookie = SsoSession.issue!(identity: identity)
        other_session, = Session.issue!(identity: identity, client: client,
                                        sso_session: other_realm_session)
        expect(other_session.sso_session).to eq(other_realm_session)

        delete "/api/apps/#{client.client_id}/auth/sign_out", headers: first
        expect(response).to have_http_status(:no_content)

        verifier = SecureRandom.urlsafe_base64(64)
        challenge = Base64.urlsafe_encode64(
          OpenSSL::Digest::SHA256.digest(verifier), padding: false
        )
        cookies[SsoCookie::COOKIE_NAME] = other_cookie
        get "/sso/authorize", params: {
          client_id: client.client_id, redirect_uri: return_to, response_type: "code",
          state: "s", code_challenge: challenge, code_challenge_method: "S256"
        }

        query = URI.decode_www_form(URI.parse(response.headers["Location"]).query).to_h
        expect(query["code"]).to be_present
        expect(query).not_to have_key("error")
      end

      # Revoking is an update, so it cannot cascade -- which is the point: the
      # other applications on this browser keep their refresh tokens and stay
      # signed in, they just cannot reach a NEW one without a password.
      #
      # This asserts that outcome, not the association's dependent: option --
      # that only fires on destroy and is covered in the model spec.
      it "leaves the application sessions in place" do
        headers = bearer_and_cookie

        expect { delete "/api/apps/#{client.client_id}/auth/sign_out", headers: headers }
          .not_to change(Session, :count)
      end

      # A normal outcome, not a failure: a realm without single sign-on, or a
      # session predating the link.
      it "revokes nothing, and still succeeds, when there is no link" do
        headers = bearer_and_cookie
        identity.sessions.update_all(sso_session_id: nil)

        delete "/api/apps/#{client.client_id}/auth/sign_out", headers: headers

        expect(response).to have_http_status(:no_content)
        expect(identity.sso_sessions.active.count).to eq(1)
      end
    end

    # The one case where reaching every browser IS the point.
    describe "logging out everywhere" do
      it "revokes every browser's realm session" do
        first = bearer_and_cookie
        bearer_and_cookie
        expect(identity.sso_sessions.active.count).to eq(2)

        delete "/api/apps/#{client.client_id}/auth/sessions", headers: first

        expect(identity.sso_sessions.active.count).to eq(0)
      end
    end

    # Otherwise signing out would be decorative: the application would bounce
    # through /authorize, the cookie would still be good, and the person would
    # be signed straight back in without a password.
    it "signing out of one application ends the realm session" do
      headers = bearer_and_cookie
      expect(identity.sso_sessions.active.count).to eq(1)

      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: headers

      expect(response).to have_http_status(:no_content)
      expect(identity.sso_sessions.active.count).to eq(0)
    end

    it "clears the cookie from the browser as well as revoking the row" do
      headers = bearer_and_cookie

      delete "/api/apps/#{client.client_id}/auth/sign_out", headers: headers

      # A clearing Set-Cookie has to carry the same path, or the browser keeps
      # the original and the deletion only shadows it elsewhere.
      expect(set_cookie_header).to match(%r{path=/sso}i)
      expect(set_cookie_header).to match(/\A#{SsoCookie::COOKIE_NAME}=;/)
      expect(set_cookie_header).to match(/expires=Thu, 01 Jan 1970/i)
    end

    it "logging out everywhere ends the realm session too" do
      headers = bearer_and_cookie

      delete "/api/apps/#{client.client_id}/auth/sessions", headers: headers

      expect(response).to have_http_status(:ok)
      expect(identity.sso_sessions.active.count).to eq(0)
    end

    it "revokes rather than deletes" do
      headers = bearer_and_cookie

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

    it "sets no other cookie on the bootstrap" do
      bootstrap

      names = Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
                                                   .map { |h| h[/\A([^=]+)=/, 1] }

      expect(names).to eq([ SsoCookie::COOKIE_NAME ])
    end
  end
end
