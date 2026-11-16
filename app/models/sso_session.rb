# frozen_string_literal: true

# A browser's claim to be an identity across a whole realm.
#
# This is the credential single sign-on rests on, and the widest-reaching one
# this server issues: a `Session` holds a refresh token redeemable at exactly
# one application, while this says "whoever holds this cookie is this person"
# to every application in the realm. Everything below follows from that.
#
# `/sso/authorize` reads it, and only it -- the cookie's path scope keeps it
# away from every credential and API endpoint. An earlier version of this
# comment said nothing read it and that /authorize did not exist; both stopped
# being true when that endpoint landed, and a stale claim on the widest
# credential this server issues is worse than no comment.
#
# It also groups the application sessions it authorised, which is what lets a
# sessions list show devices rather than application-and-device pairs. Grouping
# is all it does there: each application still holds its own client-scoped
# refresh token, so this cookie cannot be exchanged for one.
class SsoSession < ApplicationRecord
  # It lasts WHILE THE PERSON IS ACTIVE on this device, not a fixed time.
  #
  # It used to expire twelve hours after sign-in whatever happened. But each
  # application holds its own 30-day refresh token, so someone could be signed
  # in to one application all week and still be asked for a password the
  # moment they opened a second one -- single sign-on that worked for half a
  # day. That was the wrong trade for the people using it.
  #
  # So it slides. IDLE_TIMEOUT is how long it survives with nothing on this
  # device in use; every use extends it (#touch_used!): an /authorize, or a
  # refresh by any application session it authorised, which a signed-in
  # application does every few minutes. MAX_LIFETIME caps it absolutely, at an
  # application session's own lifetime, so it can never outlast what it
  # authorised. What still bounds silent sign-in at other applications is
  # inactivity, and signing out, which ends this device (UserSessions#sign_out).
  IDLE_TIMEOUT = 12.hours
  MAX_LIFETIME = Session::REFRESH_TOKEN_TTL

  belongs_to :identity

  # Codes die with the session they were minted from, so signing out reaches
  # one already in flight rather than leaving it redeemable.
  has_many :authorization_codes, dependent: :destroy

  # The application sessions this browser session authorised.
  #
  # No dependent: option on purpose. Destroying this row must not delete the
  # refresh-token rows a sessions list and an audit trail depend on, and
  # revocation here revokes rather than deletes -- see #revoke!.
  has_many :sessions, inverse_of: :sso_session

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
        expires_at: IDLE_TIMEOUT.from_now
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

  # Revokes this browser session AND the application sessions it authorised.
  #
  # Cascading is the point rather than a convenience. Without it, revoking a
  # device would end the browser session while every application refresh token
  # minted on that device stayed live for up to thirty days -- so "sign this
  # laptop out" would leave the laptop signed in, which is the failure a
  # device list exists to prevent.
  #
  # Scoped to active rows so a second call cannot overwrite the time an
  # earlier revocation recorded.
  def revoke!
    return if revoked_at.present?

    transaction do
      update!(revoked_at: Time.current)
      sessions.active.each(&:revoke!)
    end
  end

  def revoked?
    revoked_at.present?
  end

  def active?
    revoked_at.nil? && expires_at.future?
  end

  # Records a use and extends the idle window, up to MAX_LIFETIME from
  # creation. A revoked or expired session is not revived: that would undo a
  # sign-out, or let a session idle out and then come back.
  #
  # update_columns for the same reason Session does it: this runs on every
  # /authorize and refresh and must not bump updated_at, which would make "last
  # used" and "changed" indistinguishable.
  def touch_used!
    return unless active?

    now = Time.current
    update_columns(last_used_at: now, expires_at: [ now + IDLE_TIMEOUT, created_at + MAX_LIFETIME ].min)
  end

  # When this browser session ends at the latest, whatever activity there is.
  def max_expires_at
    created_at + MAX_LIFETIME
  end
end
