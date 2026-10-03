# frozen_string_literal: true

require "rails_helper"

# The client is resolved from the URL PATH and nothing else.
#
# This matters because the CORS preflight approved an Origin for the client in
# the path. If a body or query parameter could name a different client, a page
# could pass the preflight as one application and then be served as another.
RSpec.describe "client resolution" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:realm) { create(:realm, require_email_confirmation: false) }
  let!(:target) do
    create(:client, realm: realm, client_id: "target-app", allowed_origins: "https://a.example.com")
  end
  let!(:other) do
    create(:client, realm: realm, client_id: "other-app", allowed_origins: "https://b.example.com")
  end
  let(:password) { "correct horse battery staple" }
  let!(:identity) do
    create(:identity, realm: realm, signup_client: target,
                      email: "ada@example.com", password: password, confirmed_at: Time.current)
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

  def audience_of(token)
    JWT.decode(token, signing_key.public_key, false).first["aud"]
  end

  it "ignores a client_id in the body" do
    post "/api/apps/target-app/auth/sign_in",
         params: { email: "ada@example.com", password: password, client_id: "other-app" },
         headers: { "Origin" => "https://a.example.com" }

    expect(audience_of(response.parsed_body["access_token"])).to eq("target-app")
  end

  it "ignores a client_id in the query string" do
    post "/api/apps/target-app/auth/sign_in?client_id=other-app",
         params: { email: "ada@example.com", password: password },
         headers: { "Origin" => "https://a.example.com" }

    expect(audience_of(response.parsed_body["access_token"])).to eq("target-app")
  end

  it "still enforces the PATH client's origin list, not the body client's" do
    # https://b.example.com belongs to other-app. Naming other-app in the body
    # must not make its origin acceptable here.
    post "/api/apps/target-app/auth/sign_in",
         params: { email: "ada@example.com", password: password, client_id: "other-app" },
         headers: { "Origin" => "https://b.example.com" }

    expect(response).to have_http_status(:forbidden)
  end

  it "resolves the preflight from the path too" do
    process :options, "/api/apps/target-app/auth/sign_in?client_id=other-app",
            headers: { "Origin" => "https://b.example.com", "Access-Control-Request-Method" => "POST" }

    expect(response).to have_http_status(:forbidden)
  end
end
