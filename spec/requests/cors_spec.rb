# frozen_string_literal: true

require "rails_helper"

# CORS is the browser-facing security boundary for credential endpoints. A
# browser presents only the public client_id, so the Origin check against that
# client's allowlist is what constrains who may post a password.
RSpec.describe "CORS preflight" do
  let(:client) do
    create(:client, allowed_origins: "https://app.example.com https://admin.example.com")
  end

  def preflight(client_id, origin, path: "auth/sign_in")
    process :options, "/api/clients/#{client_id}/#{path}",
            headers: { "Origin" => origin, "Access-Control-Request-Method" => "POST" }
  end

  describe "an allowed origin" do
    before { preflight(client.client_id, "https://app.example.com") }

    it "is approved" do
      expect(response).to have_http_status(:no_content)
    end

    # The SPECIFIC origin, not "*". A wildcard cannot carry credentials and
    # would let any site read these responses.
    it "echoes the origin rather than a wildcard" do
      expect(response.headers["Access-Control-Allow-Origin"]).to eq("https://app.example.com")
      expect(response.headers["Access-Control-Allow-Origin"]).not_to eq("*")
    end

    it "varies on Origin, so a cache cannot serve one app's answer to another" do
      expect(response.headers["Vary"]).to include("Origin")
    end

    it "permits the headers a JSON credential post needs" do
      expect(response.headers["Access-Control-Allow-Headers"]).to include("Content-Type", "Authorization")
    end
  end

  describe "a second allowed origin on the same client" do
    it "is also approved" do
      preflight(client.client_id, "https://admin.example.com")

      expect(response).to have_http_status(:no_content)
    end
  end

  describe "an origin that is not on the list" do
    before { preflight(client.client_id, "https://evil.example.com") }

    # Refusing the preflight stops the real request being SENT, not merely
    # hides its response. That is what makes this a control rather than a
    # formality for a JSON post.
    it "is refused" do
      expect(response).to have_http_status(:forbidden)
    end

    it "grants nothing" do
      expect(response.headers["Access-Control-Allow-Origin"]).to be_nil
    end
  end

  describe "another realm's origin" do
    # The isolation that matters: an origin registered in one realm must not
    # work against a different realm's client.
    it "is refused" do
      other = create(:client, allowed_origins: "https://other-realm.example.com")

      preflight(client.client_id, "https://other-realm.example.com")

      expect(response).to have_http_status(:forbidden)
      expect(other.realm).not_to eq(client.realm)
    end
  end

  describe "an unknown or inactive client" do
    it "refuses an unknown client_id" do
      preflight("cid_does_not_exist", "https://app.example.com")

      expect(response).to have_http_status(:forbidden)
    end

    it "refuses a deactivated client even for a listed origin" do
      client.update!(active: false)

      preflight(client.client_id, "https://app.example.com")

      expect(response).to have_http_status(:forbidden)
    end
  end

  describe "the preflight itself is unauthenticated" do
    # The browser sends it before the real request, with no credentials.
    # Demanding any would block every legitimate call.
    it "needs no token" do
      preflight(client.client_id, "https://app.example.com")

      expect(response).to have_http_status(:no_content)
    end
  end
end
