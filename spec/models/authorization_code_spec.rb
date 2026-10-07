# frozen_string_literal: true

require "rails_helper"

# The authorization code: the most exposed credential this server issues.
#
# It travels in a URL, so it passes through the address bar, browser history,
# logs at the far end and any Referer the application leaks. These specs pin the
# properties that make seeing it insufficient -- single use, one minute, and
# bound to the client, the URI, the challenge and the browser session.
#
# `consume!` is not called by anything yet; the exchange is the next slice. It is
# specced now because its race is the kind that is invisible until it is
# exploited, and because a code that could be redeemed twice is two sessions
# from one authorisation.
RSpec.describe AuthorizationCode do
  let(:realm) { create(:realm, sso_enabled: true) }
  let(:client) { create(:client, realm: realm, redirect_uris: "https://app.example.com/cb") }
  let(:identity) { create(:identity, realm: realm, signup_client: client) }
  let(:sso_session) { SsoSession.issue!(identity: identity).first }
  let(:verifier) { SecureRandom.urlsafe_base64(64) }
  let(:challenge) do
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(verifier), padding: false)
  end

  def issue(**overrides)
    described_class.issue!(**{
      identity: identity, client: client, sso_session: sso_session,
      redirect_uri: "https://app.example.com/cb", code_challenge: challenge
    }.merge(overrides))
  end

  describe ".issue!" do
    it "stores a digest and never the code itself" do
      code, raw = issue

      expect(code.code_digest).to eq(Digest::SHA256.hexdigest(raw))
      expect(described_class.where(code_digest: raw)).to be_empty
    end

    it "lives for one minute" do
      code, = issue

      expect(code.expires_at).to be_within(2.seconds).of(1.minute.from_now)
      expect(described_class::CODE_TTL).to be <= 10.minutes
    end

    it "issues distinct codes" do
      values = Array.new(5) { issue.last }

      expect(values.uniq.length).to eq(5)
    end

    it "refuses a challenge method other than S256" do
      expect { issue.first.update!(code_challenge_method: "plain") }
        .to raise_error(ActiveRecord::RecordInvalid)
    end
  end

  describe ".consume!" do
    it "returns the code once" do
      code, raw = issue

      expect(described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri))
        .to eq(code)
    end

    # The whole point. A code redeemed twice is two sessions from one
    # authorisation, and a leaked URL becomes usable even after the real
    # application has already redeemed it.
    it "returns nothing the second time" do
      code, raw = issue
      described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri)

      expect(described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri))
        .to be_nil
    end

    it "marks it consumed rather than deleting it" do
      code, raw = issue

      expect { described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri) }
        .not_to change(described_class, :count)
      expect(code.reload).to be_consumed
    end

    # Bound to the client. A code issued for one application must not be
    # redeemable by another, even inside the same realm -- that is the same
    # audience-scoping the access token has.
    it "refuses a different client" do
      other = create(:client, realm: realm, redirect_uris: "https://other.example.com/cb")
      code, raw = issue

      expect(described_class.consume!(raw, client: other, redirect_uri: code.redirect_uri))
        .to be_nil
    end

    # Bound to the URI it was issued for, so a code intercepted at one
    # registered callback cannot be redeemed as though it arrived at another.
    it "refuses a different redirect_uri" do
      _code, raw = issue

      expect(described_class.consume!(raw, client: client, redirect_uri: "https://app.example.com/other"))
        .to be_nil
    end

    it "refuses an expired code" do
      code, raw = issue
      code.update_column(:expires_at, 1.second.ago)

      expect(described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri))
        .to be_nil
    end

    it "refuses an unknown code" do
      code, = issue

      expect(described_class.consume!(SecureRandom.urlsafe_base64(32), client: client,
                                      redirect_uri: code.redirect_uri)).to be_nil
    end

    it "refuses a blank code" do
      expect(described_class.consume!(nil, client: client, redirect_uri: "x")).to be_nil
      expect(described_class.consume!("", client: client, redirect_uri: "x")).to be_nil
    end

    # Signing out must reach a code already in flight. Otherwise there is a
    # minute in which a revoked session still yields a working token.
    it "refuses a code whose browser session was revoked" do
      code, raw = issue
      sso_session.revoke!

      expect(described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri))
        .to be_nil
    end

    it "refuses a code whose browser session expired" do
      code, raw = issue
      sso_session.update_column(:expires_at, 1.second.ago)

      expect(described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri))
        .to be_nil
    end

    # The claim is a single conditional UPDATE whose affected-row count decides
    # the outcome, so two simultaneous redemptions cannot both win.
    #
    # The window this guards is narrow and real: read the row, see it unconsumed,
    # then write. Two callers can both pass the read before either writes, and
    # both then believe they hold the code.
    #
    # Landing a competitor INSIDE that window is the whole difficulty of testing
    # it. The first version of this spec consumed the row before consume! had
    # read it, so the live scope simply excluded it and the claim was never
    # reached -- it passed against a deliberately broken read-then-write
    # implementation, which is how it was caught. This hooks the second use of
    # `live` instead, which is the claim itself, so the competitor lands after
    # the read and before the write.
    it "loses the claim when a competing redemption gets there first" do
      code, raw = issue
      uses = 0

      allow(described_class).to receive(:live).and_wrap_original do |original|
        uses += 1
        described_class.where(id: code.id).update_all(consumed_at: Time.current) if uses > 1
        original.call
      end

      expect(described_class.consume!(raw, client: client, redirect_uri: code.redirect_uri))
        .to be_nil
      expect(uses).to be >= 2, "consume! did not re-check the row when claiming it"
    end
  end

  describe "#verifies?" do
    it "accepts the verifier the challenge was derived from" do
      code, = issue

      expect(code.verifies?(verifier)).to be(true)
    end

    it "refuses a different verifier" do
      code, = issue

      expect(code.verifies?(SecureRandom.urlsafe_base64(64))).to be(false)
    end

    it "refuses a blank verifier" do
      code, = issue

      expect(code.verifies?(nil)).to be(false)
      expect(code.verifies?("")).to be(false)
    end

    # The challenge is the S256 of the verifier, base64url, unpadded. A padded
    # or hex encoding would never match a conformant client.
    it "expects base64url without padding" do
      code, = issue

      expect(code.code_challenge).not_to include("=")
      expect(code.code_challenge).to match(/\A[A-Za-z0-9_-]+\z/)
    end
  end

  describe "lifecycle" do
    it "goes away with the identity" do
      issue

      expect { identity.destroy! }.to change(described_class, :count).by(-1)
    end

    it "goes away with the browser session" do
      issue

      expect { sso_session.destroy! }.to change(described_class, :count).by(-1)
    end
  end
end
