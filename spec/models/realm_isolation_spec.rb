# frozen_string_literal: true

require "rails_helper"

# The constraint the whole design rests on: the same email address is a
# DIFFERENT identity in each realm, and the realm is never something a request
# can claim.
#
# This cuts against what Devise generates and against what every app in the
# byscott fleet carries -- a GLOBAL unique index on email -- so it is asserted
# against the real database rather than taken on trust.
RSpec.describe "realm isolation" do
  let(:sdk) { create(:realm, key: "sdk") }
  let(:church) { create(:realm, key: "church") }

  describe "the same email in two realms" do
    it "is permitted" do
      create(:identity, realm: sdk, email: "scott@example.com")

      expect { create(:identity, realm: church, email: "scott@example.com") }
        .to change(Identity, :count).by(1)
    end

    it "yields two distinct subs" do
      a = create(:identity, realm: sdk, email: "scott@example.com")
      b = create(:identity, realm: church, email: "scott@example.com")

      expect(a.id).not_to eq(b.id)
    end

    it "gives each its own password" do
      a = create(:identity, realm: sdk, email: "scott@example.com", password: "sdk-password-here")
      b = create(:identity, realm: church, email: "scott@example.com", password: "church-password!")

      expect(a.valid_password?("sdk-password-here")).to be(true)
      expect(a.valid_password?("church-password!")).to be(false)
      expect(b.valid_password?("church-password!")).to be(true)
    end

    it "gives each its own MFA state" do
      a = create(:identity, realm: sdk, email: "scott@example.com", mfa_enabled: true)
      create(:identity, realm: church, email: "scott@example.com")

      expect(a.mfa_enabled).to be(true)
      expect(church.identities.first.mfa_enabled).to be(false)
    end
  end

  describe "the same email twice in ONE realm" do
    it "is refused by the model" do
      create(:identity, realm: sdk, email: "scott@example.com")
      duplicate = build(:identity, realm: sdk, email: "scott@example.com")

      expect(duplicate).not_to be_valid
      expect(duplicate.errors[:email]).to be_present
    end

    it "is refused by the DATABASE even when validations are bypassed" do
      create(:identity, realm: sdk, email: "scott@example.com")

      # Skipping validation also skips the email normalizer, so this lands an
      # uppercase address straight at the index -- which is the point. The
      # constraint is lower(email), so it still collides.
      duplicate = build(:identity, realm: sdk, email: "SCOTT@example.com")

      expect { duplicate.save(validate: false) }
        .to raise_error(ActiveRecord::RecordNotUnique)
    end

    it "cannot be slipped past with different casing" do
      create(:identity, realm: sdk, email: "scott@example.com")

      expect(build(:identity, realm: sdk, email: "Scott@Example.COM")).not_to be_valid
    end

    it "cannot be slipped past with surrounding whitespace" do
      create(:identity, realm: sdk, email: "scott@example.com")

      expect(build(:identity, realm: sdk, email: "  scott@example.com  ")).not_to be_valid
    end
  end

  describe "realm-scoped authentication lookup" do
    # Devise looks an identity up by authentication_keys GLOBALLY, which here
    # would find the wrong realm's identity and authenticate against the wrong
    # suite entirely.
    it "finds only the identity in the realm asked for" do
      sdk_identity = create(:identity, realm: sdk, email: "scott@example.com")
      church_identity = create(:identity, realm: church, email: "scott@example.com")

      expect(Identity.find_for_authentication_in_realm(sdk, "scott@example.com")).to eq(sdk_identity)
      expect(Identity.find_for_authentication_in_realm(church, "scott@example.com")).to eq(church_identity)
    end

    it "is case and whitespace insensitive" do
      identity = create(:identity, realm: sdk, email: "scott@example.com")

      expect(Identity.find_for_authentication_in_realm(sdk, "  SCOTT@Example.com ")).to eq(identity)
    end

    it "finds nothing for a realm the address does not exist in" do
      create(:identity, realm: sdk, email: "scott@example.com")

      expect(Identity.find_for_authentication_in_realm(church, "scott@example.com")).to be_nil
    end

    it "refuses to look anything up without a realm" do
      create(:identity, realm: sdk, email: "scott@example.com")

      expect(Identity.find_for_authentication_in_realm(nil, "scott@example.com")).to be_nil
    end
  end

  describe "the realm is resolved from the client, never claimed" do
    it "comes from the client_id a request presents" do
      client = create(:client, realm: church)

      expect(Realm.for_client_id(client.client_id)).to eq(church)
    end

    it "is nil for an unknown client_id" do
      expect(Realm.for_client_id("cid_nonexistent")).to be_nil
    end

    it "is nil for a deactivated client" do
      client = create(:client, realm: church, active: false)

      expect(Realm.for_client_id(client.client_id)).to be_nil
    end
  end
end
