# frozen_string_literal: true

require "rails_helper"

# Where somebody goes after signing out.
#
# Registered on the client record rather than chosen by the caller, because the
# caller may NAME one and an unvalidated redirect on a sign-out endpoint is an
# open redirect -- on the one endpoint whose link people mail to each other.
#
# The problem it solves: signing out of an application with single sign-on on
# clears its session, the app's own guard sends the person to its login route,
# and that route starts single sign-on again. So signing out put you straight
# back on a login form. The destination has to be somewhere public, and this is
# where the server says which.
RSpec.describe "the post-logout redirect" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false, sso_enabled: true) }
  let(:home) { "https://app.example.com/" }
  let(:farewell) { "https://app.example.com/signed-out" }
  let(:client) do
    create(:client, realm: realm, allowed_origins: "https://app.example.com",
                    post_logout_redirect_uris: "#{home} #{farewell}")
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

  def origin = { "Origin" => "https://app.example.com" }

  def token
    post "/api/apps/#{client.client_id}/auth/sign_in",
         params: { email: "ada@example.com", password: password }, headers: origin
    response.parsed_body["access_token"]
  end

  def sign_out(requested = nil)
    params = requested ? { post_logout_redirect_uri: requested } : {}
    delete "/api/apps/#{client.client_id}/auth/sign_out",
           params: params, headers: origin.merge("Authorization" => "Bearer #{token}")
    response.parsed_body["post_logout_redirect_uri"]
  end

  describe "with nothing requested" do
    it "answers the first registered uri" do
      expect(sign_out).to eq(home)
    end
  end

  describe "with a registered uri requested" do
    it "answers that one" do
      expect(sign_out(farewell)).to eq(farewell)
    end
  end

  # THE security property. A sign-out link is mailed around, so whatever it can
  # be made to redirect to is whatever an attacker can send somebody to while
  # they are mid-flow and trusting the domain they just left.
  describe "with an UNREGISTERED uri requested" do
    it "refuses it and answers the registered default instead" do
      expect(sign_out("https://evil.example.com/collect")).to eq(home)
    end

    it "refuses one that merely starts with a registered uri" do
      expect(sign_out("#{home}../evil")).to eq(home)
    end

    it "refuses a lookalike host" do
      expect(sign_out("https://app.example.com.evil.test/")).to eq(home)
    end

    it "still signs the person out" do
      sign_out("https://evil.example.com/collect")

      expect(response).to have_http_status(:ok)
      expect(identity.sso_sessions.active.count).to eq(0)
    end
  end

  # A client that never registered one gets no opinion from this server, rather
  # than a guess.
  describe "a client with none registered" do
    let(:client) do
      create(:client, realm: realm, allowed_origins: "https://app.example.com")
    end

    it "answers nothing" do
      expect(sign_out).to be_nil
    end

    it "answers nothing even when one is requested" do
      expect(sign_out("https://evil.example.com/")).to be_nil
    end
  end

  describe "the model, directly" do
    it "treats an exact registered match as allowed and anything else as refused" do
      expect(client.post_logout_redirect_refused?(farewell)).to be(false)
      expect(client.post_logout_redirect_refused?("https://evil.example.com/")).to be(true)
      expect(client.post_logout_redirect_refused?(nil)).to be(false)
    end
  end
end
