# frozen_string_literal: true

require "rails_helper"

# The two fields single sign-on needs, landed before any of it is built.
#
# Nothing reads them yet -- /authorize does not exist. They are specced now
# because the defaults are the security property: a realm that gained SSO by
# existing, or a client that accepted a code anywhere, would both be wrong in
# ways nothing downstream could correct.
RSpec.describe "SSO foundation" do
  describe "Realm#sso_enabled" do
    # Opt-in per suite, never a fleet-wide switch. A realm sharing identities
    # does not oblige it to share a browser session, and the cost of one -- a
    # session here that must stay revocable alongside every refresh token --
    # is only worth paying where people move between applications.
    it "is off for a newly created realm" do
      expect(create(:realm).sso_enabled).to be(false)
    end

    # The migration gave the column a false default AND null: false, so every
    # realm that already existed got false rather than NULL. Asserted at the
    # schema, because a nullable flag would make "not enabled" and "never
    # decided" indistinguishable to the endpoint that will read it.
    it "cannot be null, so there is no third state" do
      column = Realm.columns_hash["sso_enabled"]

      expect(column.null).to be(false)
      expect(column.default).to eq("false")
    end

    it "can be turned on deliberately" do
      realm = create(:realm)
      realm.update!(sso_enabled: true)

      expect(realm.reload).to be_sso
    end
  end

  describe "Client#redirect_uri_allowed?" do
    let(:client) do
      create(:client, redirect_uris: "https://app.example.com/auth/callback https://admin.example.com/auth/callback")
    end

    it "accepts a registered URI" do
      expect(client.redirect_uri_allowed?("https://app.example.com/auth/callback")).to be(true)
    end

    it "lists every registered URI" do
      expect(client.redirect_uris_list.length).to eq(2)
    end

    # A client that has registered nothing cannot complete a redirect flow at
    # all, which is the right default: the column is empty until someone makes
    # a deliberate decision about where codes may go.
    it "accepts nothing when none are registered" do
      expect(create(:client).redirect_uri_allowed?("https://anywhere.example.com/cb")).to be(false)
    end

    it "refuses a blank" do
      expect(client.redirect_uri_allowed?(nil)).to be(false)
      expect(client.redirect_uri_allowed?("")).to be(false)
    end

    # Each of these is a known way authorization codes reach the wrong party,
    # and each passes under a check that is merely "close enough". A code is a
    # credential; where it may be delivered is exact string equality or it is
    # nothing.
    {
      "a suffix on the host" => "https://app.example.com.attacker.test/auth/callback",
      "a different path" => "https://app.example.com/anything-else",
      "a trailing slash" => "https://app.example.com/auth/callback/",
      "a query string appended" => "https://app.example.com/auth/callback?next=//attacker.test",
      "a fragment appended" => "https://app.example.com/auth/callback#x",
      "plain http instead of https" => "http://app.example.com/auth/callback",
      "a different port" => "https://app.example.com:8443/auth/callback",
      "a case-changed host" => "https://APP.example.com/auth/callback",
      "a prefix of a registered URI" => "https://app.example.com/auth"
    }.each do |description, uri|
      it "refuses #{description}" do
        expect(client.redirect_uri_allowed?(uri)).to be(false)
      end
    end
  end
end
