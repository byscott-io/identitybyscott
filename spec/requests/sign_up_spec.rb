# frozen_string_literal: true

require "rails_helper"

# Self-signup. The one endpoint whose disclosure depends on the realm's
# confirmation setting, which is worth pinning rather than discovering.
RSpec.describe "POST auth/sign_up" do
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:client) { create(:client, realm: realm, allowed_origins: "https://app.example.com") }

  around do |example|
    ENV["IDENTITY_SIGNING_KEY"] = signing_key.to_pem
    ENV["IDENTITY_ISSUER"] = "https://identity.test"
    SigningKeys.reset!
    example.run
  ensure
    ENV.delete("IDENTITY_SIGNING_KEY")
    ENV.delete("IDENTITY_ISSUER")
    SigningKeys.reset!
    Current.reset
  end

  def sign_up(email: "new@example.com", password: "correct horse battery staple")
    post "/api/apps/#{client.client_id}/auth/sign_up",
         params: { email: email, password: password, first_name: "Ada" },
         headers: { "Origin" => "https://app.example.com" }
  end

  context "when the realm does NOT require confirmation" do
    let(:realm) { create(:realm, require_email_confirmation: false) }

    it "creates the identity and returns a token" do
      expect { sign_up }.to change(Identity, :count).by(1)

      expect(response).to have_http_status(:created)
      expect(response.parsed_body["access_token"]).to be_present
    end

    it "records the client it signed up through" do
      sign_up

      expect(Identity.last.signup_client).to eq(client)
    end

    it "puts the identity in the client's realm" do
      sign_up

      expect(Identity.last.realm).to eq(realm)
    end

    # The unavoidable disclosure. A caller is owed a token on success, so
    # failure has to be distinguishable -- which makes this the one endpoint
    # that answers "does this address exist in this realm".
    it "reveals a taken address, because it must" do
      create(:identity, realm: realm, email: "taken@example.com", signup_client: client)

      sign_up(email: "taken@example.com")

      expect(response).to have_http_status(:unprocessable_content)
      expect(response.parsed_body["errors"]).to be_present
    end

    # The exposure is bounded, which is the part that matters.
    it "says nothing about an address in ANOTHER realm" do
      other = create(:realm)
      create(:identity, realm: other, email: "elsewhere@example.com")

      expect { sign_up(email: "elsewhere@example.com") }.to change(Identity, :count).by(1)
      expect(response).to have_http_status(:created)
    end
  end

  context "when the realm DOES require confirmation" do
    let(:realm) { create(:realm, require_email_confirmation: true) }

    it "returns no token, because the person cannot sign in yet" do
      sign_up

      expect(response).to have_http_status(:accepted)
      expect(response.parsed_body["access_token"]).to be_nil
      expect(response.parsed_body["status"]).to eq("confirmation_sent")
    end

    it "leaves the identity unconfirmed" do
      sign_up

      expect(Identity.last.confirmed_at).to be_nil
    end

    # Here a taken address CAN be hidden, and is.
    it "answers a taken address identically to a new one" do
      create(:identity, realm: realm, email: "taken@example.com", signup_client: client)

      sign_up(email: "taken@example.com")
      taken = [ response.status, response.parsed_body ]

      sign_up(email: "brand-new@example.com")
      expect([ response.status, response.parsed_body ]).to eq(taken)
    end

    it "creates no second identity for a taken address" do
      create(:identity, realm: realm, email: "taken@example.com", signup_client: client)

      expect { sign_up(email: "taken@example.com") }.not_to change(Identity, :count)
    end

    # The owner of the address learns what happened; the caller does not.
    it "tells the address owner instead of the caller" do
      create(:identity, realm: realm, email: "taken@example.com", signup_client: client)

      expect { sign_up(email: "taken@example.com") }
        .to have_enqueued_mail(IdentityMailer, :existing_account)
    end
  end

  context "validation" do
    let(:realm) { create(:realm, require_email_confirmation: false) }

    it "refuses a malformed address" do
      sign_up(email: "not-an-email")

      expect(response).to have_http_status(:unprocessable_content)
    end

    it "refuses a blank password" do
      sign_up(password: "")

      expect(response).to have_http_status(:unprocessable_content)
    end
  end
end
