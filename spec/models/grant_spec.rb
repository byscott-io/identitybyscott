# frozen_string_literal: true

require "rails_helper"

# A grant is permission for one identity to use one application. Existing in a
# realm is not permission to use the applications in it.
RSpec.describe Grant do
  let(:realm) { create(:realm) }
  let(:client) { create(:client, realm: realm) }
  let(:identity) { create(:identity, realm: realm, signup_client: client) }

  describe "realm isolation" do
    # The check the whole design rests on. An application belongs to exactly one
    # realm, so a grant naming an application in a DIFFERENT realm would hand
    # someone access across the isolation boundary -- and nothing else in the
    # system would notice, because every other check resolves the realm from the
    # client and would find it perfectly consistent.
    it "refuses an application in another realm" do
      foreign_client = create(:client, realm: create(:realm))

      grant = described_class.new(identity: identity, client: foreign_client)

      expect(grant).not_to be_valid
      expect(grant.errors[:client]).to include("belongs to a different realm than the identity")
    end

    it "allows an application in the identity's own realm" do
      sibling = create(:client, realm: realm)

      expect(described_class.new(identity: identity, client: sibling)).to be_valid
    end
  end

  describe "uniqueness" do
    it "refuses a duplicate grant" do
      second = described_class.new(identity: identity, client: client)

      expect(second).not_to be_valid
    end

    # The validation alone loses a race: two concurrent requests both read "no
    # grant", both validate, both insert. The database index is what actually
    # holds, so assert it exists rather than trusting the model.
    it "refuses a duplicate at the database even when validation is skipped" do
      duplicate = described_class.new(identity: identity, client: client)

      expect { duplicate.save!(validate: false) }.to raise_error(ActiveRecord::RecordNotUnique)
    end
  end

  describe ".permits?" do
    it "is true for a granted application" do
      expect(described_class.permits?(identity: identity, client: client)).to be(true)
    end

    it "is false for an application in the same realm that was never granted" do
      expect(described_class.permits?(identity: identity, client: create(:client, realm: realm))).to be(false)
    end

    it "is false once the grant is revoked" do
      identity.grants.destroy_all

      expect(described_class.permits?(identity: identity, client: client)).to be(false)
    end

    # Guards against a caller passing nil from a failed lookup and getting a
    # truthy answer by accident -- the failure mode would be granting access on
    # the strength of a record that was never found.
    it "is false for a nil identity or client" do
      expect(described_class.permits?(identity: nil, client: client)).to be(false)
      expect(described_class.permits?(identity: identity, client: nil)).to be(false)
    end
  end

  describe "cleanup" do
    it "goes when the identity goes" do
      identity # create it, and the factory's grant, before counting

      expect { identity.destroy! }.to change(described_class, :count).by(-1)
    end

    it "goes when the application goes" do
      # A second application rather than the signup client: identities hold a
      # signup_client_id foreign key, so destroying that one fails for an
      # unrelated reason and would prove nothing about grants.
      sibling = create(:client, realm: realm)
      create(:grant, identity: identity, client: sibling)

      expect { sibling.destroy! }.to change(described_class, :count).by(-1)
    end
  end
end
