# frozen_string_literal: true

require "rails_helper"

# The realm-wide browser session behind single sign-on.
#
# Nothing reads it yet. These specs pin the properties that will be impossible
# to add later without a migration and a forced sign-out of everyone: that only
# a digest is stored, that the lifetime is bounded, and that revocation and
# expiry both actually stop it being usable.
RSpec.describe SsoSession do
  let(:realm) { create(:realm, sso_enabled: true) }
  let(:identity) { create(:identity, realm: realm) }

  describe ".issue!" do
    # The raw value leaves in the return value and nowhere else. If it were
    # stored, a database dump would hand over a working credential for every
    # signed-in browser in the realm -- which is why refresh tokens are kept
    # the same way.
    it "stores a digest and never the value itself" do
      session, raw = described_class.issue!(identity: identity)

      expect(raw).to be_present
      expect(session.token_digest).to eq(Digest::SHA256.hexdigest(raw))
      expect(described_class.where(token_digest: raw)).to be_empty
    end

    it "issues a value with real entropy" do
      _session, raw = described_class.issue!(identity: identity)

      # 32 random bytes, urlsafe-base64 encoded.
      expect(raw.length).to be >= 40
    end

    it "issues distinct values" do
      values = Array.new(5) { described_class.issue!(identity: identity).last }

      expect(values.uniq.length).to eq(5)
    end

    # Far shorter than a refresh token's 30 days, and that gap is the point:
    # this credential reaches every application in the realm, so it is the one
    # whose lifetime should be measured in hours.
    it "expires well before a refresh token would" do
      session, = described_class.issue!(identity: identity)

      expect(session.expires_at).to be_within(5.seconds).of(12.hours.from_now)
      expect(described_class::SSO_SESSION_TTL).to be < Session::REFRESH_TOKEN_TTL
    end

    it "records the browser it was issued to" do
      request = instance_double(ActionDispatch::Request, user_agent: "Firefox", remote_ip: "203.0.113.4")

      session, = described_class.issue!(identity: identity, request: request)

      expect(session.user_agent).to eq("Firefox")
      expect(session.ip_address).to eq("203.0.113.4")
    end
  end

  describe ".authenticate" do
    it "finds a live session by its presented value" do
      session, raw = described_class.issue!(identity: identity)

      expect(described_class.authenticate(raw)).to eq(session)
    end

    it "returns nil for a revoked session" do
      session, raw = described_class.issue!(identity: identity)
      session.revoke!

      expect(described_class.authenticate(raw)).to be_nil
    end

    it "returns nil for an expired session" do
      session, raw = described_class.issue!(identity: identity)
      session.update_column(:expires_at, 1.second.ago)

      expect(described_class.authenticate(raw)).to be_nil
    end

    it "returns nil for an unknown value" do
      described_class.issue!(identity: identity)

      expect(described_class.authenticate(SecureRandom.urlsafe_base64(32))).to be_nil
    end

    it "returns nil for a blank value" do
      expect(described_class.authenticate(nil)).to be_nil
      expect(described_class.authenticate("")).to be_nil
    end

    # Realm-wide is not realm-agnostic. There is no client scoping here on
    # purpose -- that is the difference from Session.authenticate -- so the
    # realm this resolves to is the fact /authorize will have to check a client
    # against. It must come from the identity, with no second copy to disagree.
    it "resolves the realm through the identity, with no stored copy" do
      _session, raw = described_class.issue!(identity: identity)

      expect(described_class.authenticate(raw).realm).to eq(realm)
      expect(described_class.column_names).not_to include("realm_id")
    end
  end

  describe "revocation" do
    it "stops the session being usable" do
      session, raw = described_class.issue!(identity: identity)

      expect { session.revoke! }
        .to change { described_class.authenticate(raw) }.from(session).to(nil)
    end

    it "is idempotent and keeps the original revocation time" do
      session, = described_class.issue!(identity: identity)
      session.revoke!
      first = session.revoked_at

      session.revoke!

      expect(session.reload.revoked_at).to eq(first)
    end

    it "goes away with the identity" do
      described_class.issue!(identity: identity)

      expect { identity.destroy! }.to change(described_class, :count).by(-1)
    end
  end
end
