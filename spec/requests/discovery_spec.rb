# frozen_string_literal: true

require "rails_helper"

# The published key set is how every application verifies this server's tokens,
# and it is served unauthenticated. Both facts drive what is tested here.
RSpec.describe "discovery" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }

  around do |example|
    ENV["IDENTITY_SIGNING_KEY"] = signing_key.to_pem
    ENV["IDENTITY_ISSUER"] = "https://identity.test"
    SigningKeys.reset!
    example.run
  ensure
    ENV.delete("IDENTITY_SIGNING_KEY")
    ENV.delete("IDENTITY_ISSUER")
    ENV.delete("IDENTITY_RETIRED_PUBLIC_KEYS")
    SigningKeys.reset!
  end

  describe "GET /.well-known/jwks.json" do
    before { get "/.well-known/jwks.json" }

    it "publishes one key with the required JWK members" do
      jwk = response.parsed_body["keys"].first

      expect(jwk["kty"]).to eq("RSA")
      expect(jwk["use"]).to eq("sig")
      expect(jwk["alg"]).to eq("RS256")
      expect(jwk["kid"]).to be_present
    end

    it "is publicly cacheable" do
      expect(response.headers["Cache-Control"]).to include("public")
    end

    # The test that proves the document is USABLE rather than merely
    # well-shaped: rebuild a key from the published n and e, as a real consumer
    # does, and verify a token this server actually signed.
    it "publishes material that verifies a real token" do
      realm = create(:realm)
      client = create(:client, realm: realm)
      identity = create(:identity, realm: realm, signup_client: client)
      token = TokenIssuer.new(identity: identity, client: client).access_token

      jwk = response.parsed_body["keys"].first
      rebuilt = OpenSSL::PKey::RSA.new(
        OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(Base64.urlsafe_decode64(jwk["n"]), 2)),
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(Base64.urlsafe_decode64(jwk["e"]), 2))
        ]).to_der
      )

      payload, header = JWT.decode(token, rebuilt, true, algorithm: "RS256", aud: client.client_id,
                                                         verify_aud: true, iss: "https://identity.test", verify_iss: true)

      expect(payload["sub"]).to eq(identity.id)
      expect(header["kid"]).to eq(jwk["kid"])
    end

    # Served unauthenticated, so this is the assertion that matters most.
    it "never emits private key material" do
      jwk = response.parsed_body["keys"].first

      expect(jwk.keys).to contain_exactly("kty", "use", "alg", "kid", "n", "e")
      %w[d p q dp dq qi].each { |param| expect(jwk).not_to have_key(param) }
      expect(response.body).not_to include("PRIVATE KEY")
      expect(response.body).not_to include("BEGIN")
    end
  end

  describe "rotation" do
    it "publishes a retired key alongside the current one" do
      retired = OpenSSL::PKey::RSA.generate(2048)
      ENV["IDENTITY_RETIRED_PUBLIC_KEYS"] = retired.public_key.to_pem

      get "/.well-known/jwks.json"

      expect(response.parsed_body["keys"].length).to eq(2)
      expect(response.parsed_body["keys"].pluck("kid").uniq.length).to eq(2)
    end

    it "lists the signing key first" do
      ENV["IDENTITY_RETIRED_PUBLIC_KEYS"] = OpenSSL::PKey::RSA.generate(2048).public_key.to_pem

      get "/.well-known/jwks.json"

      expect(response.parsed_body["keys"].first["kid"]).to eq(SigningKeys.key_id)
    end
  end

  describe "when no signing key is configured" do
    it "answers 503 rather than crashing a public endpoint" do
      ENV.delete("IDENTITY_SIGNING_KEY")
      SigningKeys.reset!

      get "/.well-known/jwks.json"

      expect(response).to have_http_status(:service_unavailable)
      expect(response.body).not_to include("IDENTITY_SIGNING_KEY")
    end
  end

  describe "GET /.well-known/openid-configuration" do
    before { get "/.well-known/openid-configuration" }

    it "points at the key set" do
      expect(response.parsed_body["jwks_uri"]).to eq("https://identity.test/.well-known/jwks.json")
      expect(response.parsed_body["id_token_signing_alg_values_supported"]).to eq([ "RS256" ])
    end

    # OAuth 2.1 removes the password grant and the Security BCP advises against
    # it. Credential endpoints here are a plain API, which is honest about not
    # being OAuth; advertising the grant would claim otherwise.
    it "does not advertise a password grant" do
      expect(response.body).not_to include("password")
    end
  end
end
