# frozen_string_literal: true

# A browser's claim to be an identity across a whole realm.
#
# This is the credential single sign-on rests on, and the widest-reaching one
# this server issues: a `Session` holds a refresh token redeemable at exactly
# one application, while this says "whoever holds this cookie is this person"
# to every application in the realm. Everything below follows from that.
#
# NOTHING READS THIS YET. `/authorize` does not exist, no controller consults
# the cookie, and no request is authenticated by it. It is issued and revoked
# now so the credential's lifetime and revocation are settled before anything
# depends on them.
class SsoSession < ApplicationRecord
  # Deliberately far shorter than Session::REFRESH_TOKEN_TTL's 30 days.
  #
  # The usual instinct is to make an SSO session long, because that is what
  # saves people from retyping passwords. It is the wrong instinct here: this
  # cookie does not keep anyone signed in -- each application holds its own
  # 30-day refresh token for that -- so a short lifetime costs an occasional
  # password entry when someone opens an application they have not used today.
  #
  # What a long lifetime would cost is the thing worth protecting against:
  # silent authentication at applications the person never visited in this
  # browser. Twelve hours bounds that to about a working day.
  SSO_SESSION_TTL = 12.hours

  belongs_to :identity

  validates :token_digest, presence: true, uniqueness: true
  validates :expires_at, presence: true

  scope :active, -> { where(revoked_at: nil).where(expires_at: Time.current..) }

  # Derived, never stored. A realm column here could disagree with the
  # identity's own realm, and that disagreement is precisely the cross-realm
  # confusion the whole design exists to prevent.
  delegate :realm, to: :identity

  class << self
    # Mints a session and returns it with the RAW cookie value, which exists
    # only in this return value and in the Set-Cookie header built from it.
    # Nothing can read it back afterwards -- only the digest is stored.
    def issue!(identity:, request: nil)
      raw = SecureRandom.urlsafe_base64(32)

      session = create!(
        identity: identity,
        token_digest: digest(raw),
        user_agent: request&.user_agent,
        ip_address: request&.remote_ip,
        last_used_at: Time.current,
        expires_at: SSO_SESSION_TTL.from_now
      )

      [ session, raw ]
    end

    # Looks a session up by presented cookie value.
    #
    # Unused in this slice -- it exists so the lookup is defined in one place
    # when /authorize arrives, rather than being written inline there. Returns
    # nil for unknown, revoked and expired alike.
    #
    # Note there is no client scoping, unlike Session.authenticate, because that
    # is the whole difference between the two: this credential is realm-wide by
    # design. /authorize must therefore check that the client it is answering
    # belongs to this identity's realm, and fail closed if not -- being
    # realm-wide is not being realm-agnostic.
    def authenticate(raw_token)
      return nil if raw_token.blank?

      active.find_by(token_digest: digest(raw_token))
    end

    def digest(raw)
      Digest::SHA256.hexdigest(raw)
    end
  end

  def revoke!
    return if revoked_at.present?

    update!(revoked_at: Time.current)
  end

  def revoked?
    revoked_at.present?
  end

  def active?
    revoked_at.nil? && expires_at.future?
  end

  def touch_used!
    # update_column for the same reason Session does it: this would run on every
    # /authorize and must not bump updated_at, which would make "last used" and
    # "changed" indistinguishable.
    update_column(:last_used_at, Time.current)
  end
end
