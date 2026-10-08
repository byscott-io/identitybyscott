# frozen_string_literal: true

require "rails_helper"

# The hosted login page: the only HTML this server renders outside mailers.
#
# It exists because every alternative leaves the password field in an
# application's own origin, and that application's XSS then steals the
# CREDENTIAL rather than a session -- which no token binding fixes, since script
# on a registered origin can do whatever the real page can. An embedded form
# does not fix it either: an iframe stops script READING the field but not
# drawing a convincing fake over it.
#
# A top-level page on this server's origin is the only shape that fixes both,
# because it is the only one that gives somebody an address bar.
#
# Two properties dominate these specs:
#
#   * the cookie is set in reply to a credential submission FROM THIS BROWSER,
#     so there is no token to transplant and session fixation is structurally
#     impossible rather than mitigated
#   * CSRF is what stops LOGIN CSRF -- an attacker submitting their OWN
#     credentials through a victim's browser, leaving the victim signed in as
#     the attacker with everything they type going to the attacker's account
RSpec.describe "the hosted login page" do
  include ActiveSupport::Testing::TimeHelpers

  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: true) }
  let(:callback) { "https://app.example.com/auth/callback" }
  let(:client) do
    create(:client, realm: realm, redirect_uris: callback,
                    allowed_origins: "https://app.example.com")
  end
  let(:password) { "correct horse battery staple" }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: client, email: "ada@example.com",
                      password: password, confirmed_at: Time.current)
  end

  let(:verifier) { SecureRandom.urlsafe_base64(64) }
  let(:challenge) do
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(verifier), padding: false)
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

  def pending_token(**overrides)
    PendingAuthorization.encode(**{
      client_id: client.client_id, redirect_uri: callback,
      state: "opaque-state", code_challenge: challenge
    }.merge(overrides))
  end

  # The real two-step: GET the page to be issued a CSRF cookie and a token,
  # then POST what the form would have carried.
  def visit_login(token: nil)
    get "/sso/login", params: { authorization: token || pending_token }
    response.body
  end

  def form_value(name)
    response.body[/name="#{name}" value="([^"]+)"/, 1]
  end

  def submit(path: "/sso/login", **fields)
    post path, params: {
      authenticity_token: fields.fetch(:authenticity_token, form_value("authenticity_token")),
      authorization: fields.fetch(:authorization, form_value("authorization")),
      email: fields[:email], password: fields[:password],
      code: fields[:code], mfa_token: fields[:mfa_token]
    }.compact
  end

  def location = URI.parse(response.headers["Location"].to_s)
  def query = URI.decode_www_form(location.query.to_s).to_h

  describe "the page itself" do
    before { visit_login }

    it "renders" do
      expect(response).to have_http_status(:ok)
      expect(response.body).to include('name="email"', 'name="password"')
    end

    # THE property that makes serving HTML acceptable in the process holding the
    # signing key and every password hash. No script means views created no XSS
    # surface at all.
    it "carries no script, and forbids it" do
      expect(response.body).not_to match(/<script|javascript:|\bon(?:click|load|error|submit)=/i)
      expect(response.headers["Content-Security-Policy"]).to include("script-src 'none'")
    end

    # An embedded login page cannot show whose it is, which is the whole reason
    # this is a top-level page.
    it "refuses to be framed" do
      expect(response.headers["Content-Security-Policy"]).to include("frame-ancestors 'none'")
    end

    it "may post only to this server" do
      expect(response.headers["Content-Security-Policy"]).to include("form-action 'self'")
    end

    it "loads nothing by default and no remote images" do
      csp = response.headers["Content-Security-Policy"]

      expect(csp).to include("default-src 'none'")
      expect(csp).to include("img-src 'self' data:")
      expect(csp).to include("base-uri 'none'")
    end

    # The URL carries state and the PKCE challenge, so it must not reach the
    # application in a Referer.
    it "sends no referrer and is not cached" do
      expect(response.headers["Referrer-Policy"]).to eq("no-referrer")
      expect(response.headers["Cache-Control"]).to include("no-store")
      expect(response.headers["X-Content-Type-Options"]).to eq("nosniff")
    end

    # By nonce rather than 'unsafe-inline', so a hypothetical injection could
    # not add a second style block.
    it "allows its one style block by nonce only" do
      nonce = response.headers["Content-Security-Policy"][/style-src 'nonce-([^']+)'/, 1]

      expect(nonce).to be_present
      expect(response.body).to include(%(<style nonce="#{nonce}">))
      expect(response.headers["Content-Security-Policy"]).not_to include("unsafe-inline")
    end

    it "names the host it is signing in at, in the page as well as the bar" do
      expect(response.body).to include("Signing in at")
    end
  end

  describe "theming" do
    it "renders the client's tokens as custom properties" do
      client.update!(theme: { "display_name" => "ChurchCare", "primary_color" => "#2563eb" })

      visit_login

      expect(response.body).to include("--identity-primary: #2563eb")
      expect(response.body).to include("<h1>ChurchCare</h1>")
    end

    it "falls back to the realm's" do
      realm.update!(theme: { "primary_color" => "#aa0000" })

      visit_login

      expect(response.body).to include("--identity-primary: #aa0000")
    end

    # The display name is escaped, so a name cannot become markup. It is capped
    # and validated too, but the renderer must not depend on that.
    it "escapes the display name" do
      client.update!(theme: { "display_name" => "A & B <tag>" })

      visit_login

      expect(response.body).to include("A &amp; B &lt;tag&gt;")
      expect(response.body).not_to include("<tag>")
    end

    # Belt and braces: Theme validates on the way in, and ThemeCss refuses on
    # the way out. A value could reach the column by a route that skips
    # validation, and the consequence here would be CSS injection.
    it "refuses a bad colour that reached the column anyway" do
      client.update_column(:theme, { "primary_color" => "#fff; } body { display: none" })

      visit_login

      expect(response.body).not_to include("display: none")
      expect(response.body).to include("--identity-primary: #{Theme::DEFAULTS[:primary_color]}")
    end
  end

  describe "the signed authorization request" do
    it "refuses a missing one" do
      get "/sso/login"

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.body).to include("expired")
    end

    it "refuses a tampered one" do
      token = pending_token
      get "/sso/login", params: { authorization: "#{token}x" }

      expect(response).to have_http_status(:unprocessable_content)
    end

    it "refuses an expired one" do
      token = pending_token
      travel(PendingAuthorization::EXPIRY + 1.minute) do
        get "/sso/login", params: { authorization: token }

        expect(response).to have_http_status(:unprocessable_content)
      end
    end

    # The whole reason it is signed. If the POST took the redirect_uri from its
    # own parameters, every check /authorize made would have to be redone
    # against fresh user input -- and the redirect_uri check is the one that
    # must never be skipped.
    it "takes the redirect_uri from the signed statement, not from the POST" do
      visit_login
      post "/sso/login", params: {
        authenticity_token: form_value("authenticity_token"),
        authorization: form_value("authorization"),
        redirect_uri: "https://attacker.test/steal",
        email: identity.email, password: password
      }

      expect(response).to have_http_status(:see_other)
      expect(location.host).to eq("app.example.com")
      expect(response.headers["Location"]).not_to include("attacker.test")

      # And what the CODE is bound to, not just where the browser was sent.
      # Checking only the Location left this half untested: a version that took
      # the POST's redirect_uri still redirected correctly and merely bound the
      # code to the attacker's URI, which the exchange would then demand.
      expect(AuthorizationCode.last.redirect_uri).to eq(callback)
    end
  end

  # ---------------------------------------------------------------------------
  # Login CSRF. Without this, an attacker's page submits THEIR credentials
  # through a victim's browser and the victim is signed in as the attacker.
  # ---------------------------------------------------------------------------
  describe "cross-site submission" do
    it "is refused without the browser's token" do
      visit_login
      token = form_value("authorization")
      cookies.delete(DoubleSubmitCsrf::COOKIE_NAME)

      post "/sso/login", params: {
        authorization: token, email: identity.email, password: password
      }

      expect(response).to have_http_status(:unprocessable_content)
    end

    it "plants no session when the token is absent" do
      visit_login
      token = form_value("authorization")
      cookies.delete(DoubleSubmitCsrf::COOKIE_NAME)

      expect {
        post "/sso/login", params: {
          authorization: token, email: identity.email, password: password
        }
      }.not_to change(SsoSession, :count)
    end

    # The attacker's own valid token is no use: it does not match the victim's
    # cookie.
    it "is refused with a token from another browser" do
      visit_login

      submit(authenticity_token: SecureRandom.urlsafe_base64(32),
             email: identity.email, password: password)

      expect(response).to have_http_status(:unprocessable_content)
      expect(SsoSession.count).to eq(0)
    end

    # Rails' own InvalidAuthenticityToken is what raises now, so this renders a
    # dedicated page rather than the login form's generic error. The property is
    # unchanged: a cross-site submission and a tab left open too long say the
    # same thing, and neither names the cause to whoever sent it.
    it "says nothing about which half was wrong" do
      visit_login
      submit(authenticity_token: "nope", email: identity.email, password: password)

      expect(response.body).to include("no longer valid")
      expect(response.body).not_to match(/csrf|forgery|authenticity|cookie/i)
    end

    # Protection is ON rather than skipped, so an action added to this controller
    # later is covered by Rails' own before_action instead of waiting for
    # somebody to remember a manual check. CodeQL flagged the previous
    # skip_forgery_protection for exactly that reason, and was right to.
    #
    # Asserted on the CALLBACK CHAIN, not on forgery_protection_strategy: that
    # strategy is inherited and reads the same whether or not this controller
    # skips the check, so it would pass even with protection turned off. The
    # callback is what skip_forgery_protection removes.
    it "does not skip Rails' forgery protection" do
      filters = Sso::LoginsController._process_action_callbacks.map { |cb| cb.filter.to_s }

      expect(filters).to include("verify_authenticity_token")
    end

    it "also guards the second factor" do
      identity.update!(mfa_enabled: true, mfa_secret: ROTP::Base32.random)
      visit_login
      submit(email: identity.email, password: password)
      mfa_token = form_value("mfa_token")

      post "/sso/login/mfa", params: {
        authenticity_token: "nope", authorization: form_value("authorization"),
        mfa_token: mfa_token, code: ROTP::TOTP.new(identity.mfa_secret).now
      }

      expect(response).to have_http_status(:unprocessable_content)
      expect(SsoSession.count).to eq(0)
    end
  end

  describe "credentials" do
    before { visit_login }

    # Identical for a wrong password and an unknown address. Telling them apart
    # would make this a way to ask which realm an address exists in.
    #
    # Compared on the VISIBLE message and the status, not the whole body: each
    # render embeds a freshly signed authorization and a CSRF token, so two
    # bodies differ byte for byte even when they say exactly the same thing.
    # Comparing the whole body would fail for a reason that is not the property.
    def error_shown
      [ response.status, response.body[%r{<p class="error">(.*?)</p>}m, 1].to_s.strip ]
    end

    it "answers a wrong password and an unknown address identically" do
      submit(email: identity.email, password: "wrong")
      wrong_password = error_shown

      visit_login
      submit(email: "nobody@example.com", password: "wrong")

      expect(error_shown).to eq(wrong_password)
      expect(error_shown.last).to include("Incorrect email or password")
    end

    it "issues nothing for a wrong password" do
      expect { submit(email: identity.email, password: "wrong") }
        .not_to change(SsoSession, :count)
      expect(AuthorizationCode.count).to eq(0)
    end

    # Reported only AFTER the password verifies. Telling somebody who does not
    # know the password that an account is locked tells them it exists.
    it "reports a lock only to somebody who knew the password" do
      identity.lock_access!

      submit(email: identity.email, password: "wrong")
      expect(response.body).to include("Incorrect email or password")

      visit_login
      submit(email: identity.email, password: password)
      expect(response.body).to include("locked")
    end

    it "refuses an identity with no grant for this application" do
      identity.grants.destroy_all

      submit(email: identity.email, password: password)

      expect(response.body).to include("not been enabled")
      expect(SsoSession.count).to eq(0)
    end
  end

  describe "a successful sign-in" do
    before { visit_login }

    it "redirects to the registered callback with a code and the state" do
      submit(email: identity.email, password: password)

      expect(response).to have_http_status(:see_other)
      expect(location.host).to eq("app.example.com")
      expect(query["code"]).to be_present
      expect(query["state"]).to eq("opaque-state")
    end

    # THE point of the hosted page: the cookie is set in reply to a credential
    # submission from this browser, so it is first-party by construction and
    # there is no token to transplant into anybody else's.
    it "establishes the realm session in reply to the credentials" do
      expect { submit(email: identity.email, password: password) }
        .to change { identity.sso_sessions.active.count }.by(1)

      set_cookie = Array(response.headers["Set-Cookie"]).flat_map { |h| h.split("\n") }
                                                        .find { |h| h.start_with?("#{SsoCookie.cookie_name(realm)}=") }
      expect(set_cookie).to match(/;\s*HttpOnly/i)
      expect(set_cookie).to match(/;\s*SameSite=Lax/i)
      expect(set_cookie).to match(%r{;\s*path=/sso}i)
    end

    it "binds the code to the browser session it just established" do
      submit(email: identity.email, password: password)

      code = AuthorizationCode.last
      expect(code.sso_session).to eq(identity.sso_sessions.active.sole)
      expect(code.redirect_uri).to eq(callback)
      expect(code.code_challenge).to eq(challenge)
    end

    # The code is exchangeable, which is what makes the flow actually work.
    it "mints a code the application can redeem" do
      submit(email: identity.email, password: password)
      code = query["code"]

      post "/api/apps/#{client.client_id}/auth/token",
           params: { grant_type: "authorization_code", code: code,
                     code_verifier: verifier, redirect_uri: callback },
           headers: { "Origin" => "https://app.example.com" }

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["access_token"]).to be_present
    end

    # And the session it established makes the NEXT application silent, which is
    # the whole purpose.
    it "makes a second authorize silent" do
      submit(email: identity.email, password: password)

      get "/sso/authorize", params: {
        client_id: client.client_id, redirect_uri: callback, response_type: "code",
        state: "second", code_challenge: challenge, code_challenge_method: "S256"
      }

      expect(response).to have_http_status(:found)
      expect(query["code"]).to be_present
      expect(query["state"]).to eq("second")
    end
  end

  describe "the second factor" do
    before do
      identity.update!(mfa_enabled: true, mfa_secret: ROTP::Base32.random)
      visit_login
    end

    # The password alone must not complete the flow, or MFA would be optional
    # for anyone reaching this page.
    it "does not sign in on the password alone" do
      submit(email: identity.email, password: password)

      expect(response).to have_http_status(:ok)
      expect(response.body).to include('name="code"')
      expect(SsoSession.count).to eq(0)
      expect(AuthorizationCode.count).to eq(0)
    end

    it "completes with a valid code" do
      submit(email: identity.email, password: password)

      post "/sso/login/mfa", params: {
        authenticity_token: form_value("authenticity_token"),
        authorization: form_value("authorization"),
        mfa_token: form_value("mfa_token"),
        code: ROTP::TOTP.new(identity.mfa_secret).now
      }

      expect(response).to have_http_status(:see_other)
      expect(query["code"]).to be_present
      expect(identity.sso_sessions.active.count).to eq(1)
    end

    it "refuses a wrong code and establishes nothing" do
      submit(email: identity.email, password: password)

      post "/sso/login/mfa", params: {
        authenticity_token: form_value("authenticity_token"),
        authorization: form_value("authorization"),
        mfa_token: form_value("mfa_token"), code: "000000"
      }

      expect(response).to have_http_status(:unprocessable_content)
      expect(SsoSession.count).to eq(0)
    end

    # The challenge proves the password was correct and nothing more. It must
    # not be usable as an access token.
    it "refuses a fabricated challenge" do
      submit(email: identity.email, password: password)

      post "/sso/login/mfa", params: {
        authenticity_token: form_value("authenticity_token"),
        authorization: form_value("authorization"),
        mfa_token: SecureRandom.urlsafe_base64(32), code: "000000"
      }

      expect(response).to have_http_status(:unprocessable_content)
      expect(SsoSession.count).to eq(0)
    end
  end

  describe "the logo" do
    let(:png) { "\x89PNG\r\n\x1a\n#{'x' * 32}".b }

    it "is served from this server, so img-src 'self' holds" do
      client.update!(theme_logo_data: png, theme_logo_content_type: "image/png")

      get "/sso/logo", params: { client_id: client.client_id }

      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("image/png")
      expect(response.headers["X-Content-Type-Options"]).to eq("nosniff")
      expect(response.headers["Content-Security-Policy"]).to include("default-src 'none'")
    end

    it "is 404 when neither client nor realm has one" do
      get "/sso/logo", params: { client_id: client.client_id }

      expect(response).to have_http_status(:not_found)
    end

    it "is 404 for an unknown client" do
      get "/sso/logo", params: { client_id: "nope" }

      expect(response).to have_http_status(:not_found)
    end
  end
end
