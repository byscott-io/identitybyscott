# frozen_string_literal: true

require "rails_helper"

# Every link this server sends has to land the person back in the APP they
# started from. A link pointing here would be a dead end: this is an API-only
# server with no forms of its own.
RSpec.describe IdentityMailer do
  let(:client) { create(:client, app_base_url: "https://app.example.com/") }
  let(:identity) { create(:identity, realm: client.realm, signup_client: client) }

  after { Current.reset }

  describe "link targets" do
    it "points a reset at the app, not at this server" do
      mail = described_class.reset_password_instructions(identity, "tok123")

      expect(mail.body.encoded).to include("https://app.example.com/reset-password?token=tok123")
    end

    it "uses the CURRENT request's client in preference to the signup one" do
      other = create(:client, realm: client.realm, app_base_url: "https://other.example.com")
      Current.client = other

      mail = described_class.reset_password_instructions(identity, "tok123")

      expect(mail.body.encoded).to include("https://other.example.com/reset-password?token=tok123")
    end

    it "falls back to the signup client outside a request" do
      # A reset raised from a console or a job has no Current.client, and must
      # still produce a usable link.
      Current.client = nil

      mail = described_class.reset_password_instructions(identity, "tok123")

      expect(mail.body.encoded).to include("https://app.example.com")
    end

    it "honours a per-app path override" do
      client.update!(url_templates: { "password_reset" => "/account/new-password/{token}" })

      mail = described_class.reset_password_instructions(identity, "tok123")

      expect(mail.body.encoded).to include("https://app.example.com/account/new-password/tok123")
    end

    it "refuses to send a link it cannot build" do
      client.update_columns(app_base_url: nil)
      Current.client = nil

      expect { described_class.reset_password_instructions(identity, "tok").body }
        .to raise_error(ArgumentError, /app_base_url/)
    end
  end

  # Transactional mail is this server's entire user-visible output, and
  # HTML-only hurts deliverability.
  describe "format" do
    it "sends both a text and an HTML part" do
      mail = described_class.reset_password_instructions(identity, "tok123")

      expect(mail).to be_multipart
      expect(mail.parts.map(&:mime_type)).to include("text/plain", "text/html")
    end

    it "puts the link in the text part too" do
      mail = described_class.reset_password_instructions(identity, "tok123")
      text = mail.parts.find { |part| part.mime_type == "text/plain" }

      expect(text.body.encoded).to include("tok123")
    end
  end
end
