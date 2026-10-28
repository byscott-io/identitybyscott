# frozen_string_literal: true

require "rails_helper"

# This endpoint exists so a deploy-sync monitor can tell whether this server is
# running current code. Before it, the monitor polled /up, got HTML, recorded
# "response not JSON" and stayed green no matter how stale the deploy was.
#
# Two properties are load-bearing and both are asserted below: the commit is
# withheld from an unauthorized caller, and an unauthorized caller cannot tell
# that it was withheld.
RSpec.describe "health" do
  let(:secret) { "a" * 64 }
  let(:sha)    { "0123456789abcdef0123456789abcdef01234567" }

  around do |example|
    ENV["HEALTH_CHECK_SECRET"] = secret
    ENV["KAMAL_VERSION"] = sha
    example.run
  ensure
    ENV.delete("HEALTH_CHECK_SECRET")
    ENV.delete("KAMAL_VERSION")
  end

  describe "GET /api/health" do
    it "answers JSON, not the HTML /up answers" do
      get "/api/health"

      expect(response).to have_http_status(:ok)
      expect(response.media_type).to eq("application/json")
      expect(response.parsed_body).to include("status" => "ok")
      expect(response.parsed_body["timestamp"]).to be_present
    end

    it "serves the short commit to a caller presenting the secret as a bearer token" do
      get "/api/health", headers: { "Authorization" => "Bearer #{secret}" }

      expect(response.parsed_body["commit_sha"]).to eq(sha[0, 8])
    end

    it "accepts the secret as a query parameter too" do
      get "/api/health", params: { token: secret }

      expect(response.parsed_body["commit_sha"]).to eq(sha[0, 8])
    end

    it "withholds the commit from a caller presenting nothing" do
      get "/api/health"

      expect(response.parsed_body).not_to have_key("commit_sha")
    end

    it "withholds the commit from a caller presenting the wrong secret" do
      get "/api/health", headers: { "Authorization" => "Bearer #{'b' * 64}" }

      expect(response.parsed_body).not_to have_key("commit_sha")
    end

    it "answers a wrong secret exactly as it answers no secret, so the endpoint cannot test a guess" do
      get "/api/health", headers: { "Authorization" => "Bearer wrong" }
      refused = response.parsed_body.except("timestamp")
      refused_status = response.status

      get "/api/health"
      anonymous = response.parsed_body.except("timestamp")

      expect(refused).to eq(anonymous)
      expect(refused_status).to eq(response.status)
    end

    it "withholds the commit when no secret is configured, rather than serving it to everyone" do
      ENV.delete("HEALTH_CHECK_SECRET")

      get "/api/health", headers: { "Authorization" => "Bearer #{secret}" }

      expect(response.parsed_body).not_to have_key("commit_sha")
    end

    it "omits the commit rather than erroring when KAMAL_VERSION is absent (local, CI)" do
      ENV.delete("KAMAL_VERSION")

      get "/api/health", headers: { "Authorization" => "Bearer #{secret}" }

      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["commit_sha"]).to be_nil
    end

    it "needs no client_id, unlike every credential endpoint" do
      expect { get "/api/health" }.not_to raise_error
      expect(response).to have_http_status(:ok)
    end
  end
end
