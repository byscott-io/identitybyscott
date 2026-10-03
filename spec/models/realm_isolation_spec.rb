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

# The public identifier. Readable rather than random, because it is public
# either way -- it ships in every application's JS bundle and is the aud claim
# in every token.
RSpec.describe "client_id" do
  it "accepts a readable slug" do
    expect(build(:client, client_id: "churchcare")).to be_valid
  end

  it "is unique across realms, not just within one" do
    create(:client, client_id: "churchcare")
    other_realm_client = build(:client, client_id: "churchcare")

    expect(other_realm_client).not_to be_valid
  end

  it "refuses characters that would need escaping in a URL" do
    %w[Church_Care church.care church/care church\ care].each do |bad|
      expect(build(:client, client_id: bad)).not_to be_valid
    end
  end

  it "refuses something too short to be meaningful" do
    expect(build(:client, client_id: "a")).not_to be_valid
  end

  # The path segment keeps a client_id from colliding with a top-level API
  # route, but reserving the obvious words as well costs nothing and removes a
  # class of confusing bug.
  it "refuses a reserved word" do
    %w[api apps auth admin health].each do |reserved|
      expect(build(:client, client_id: reserved)).not_to be_valid
    end
  end

  it "is required -- nothing is generated silently" do
    expect(build(:client, client_id: nil)).not_to be_valid
  end
end

# Password rules. Explicit rather than via Devise's :validatable, which would
# add a duplicate email-format validation.
RSpec.describe "password rules" do
  it "requires a password on create" do
    expect(build(:identity, password: nil)).not_to be_valid
    expect(build(:identity, password: "")).not_to be_valid
  end

  it "requires at least 12 characters" do
    expect(build(:identity, password: "a" * 11)).not_to be_valid
    expect(build(:identity, password: "a" * 12)).to be_valid
  end

  # bcrypt SILENTLY truncates at 72 bytes. Without this, two different long
  # passphrases sharing a 72-byte prefix would both unlock the account, and the
  # person would never be told their password was cut short.
  it "refuses more than 72 bytes, because bcrypt would truncate" do
    expect(build(:identity, password: "a" * 72)).to be_valid
    expect(build(:identity, password: "a" * 73)).not_to be_valid
  end

  it "counts BYTES, not characters" do
    # Each of these is 3 bytes in UTF-8, so 25 of them exceed 72 bytes while
    # being well under 72 characters.
    expect(build(:identity, password: "日" * 25)).not_to be_valid
  end

  it "does not demand a password on an unrelated update" do
    identity = create(:identity)

    expect(identity.update(first_name: "Ada")).to be(true)
  end

  it "does validate a password that is being changed" do
    identity = create(:identity)

    expect(identity.update(password: "short")).to be(false)
  end
end
