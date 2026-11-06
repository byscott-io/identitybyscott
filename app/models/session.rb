# frozen_string_literal: true

# One row per (identity, application, device). Created when credentials are
# accepted; holds the refresh token that mints access tokens afterwards.
class Session < ApplicationRecord
  # Long enough to be worth having -- re-entering a password every fifteen
  # minutes is what a refresh token exists to avoid -- and short enough that an
  # abandoned session expires on its own. Matches what the applications used for
  # their own tokens before this server existed.
  REFRESH_TOKEN_TTL = 30.days

  belongs_to :identity
  belongs_to :client

  # The browser session this one was authorised by, where there was one.
  #
  # Optional permanently, not pending a backfill. A realm with single sign-on
  # off never mints a browser session, a mobile client holds no cookie, and
  # rows predating the column have nothing to point at. Those group as
  # themselves, which is the honest answer.
  belongs_to :sso_session, optional: true

  validates :refresh_token_digest, presence: true, uniqueness: true
  validates :expires_at, presence: true

  scope :active, -> { where(revoked_at: nil).where(expires_at: Time.current..) }

  delegate :realm, to: :identity

  class << self
    # Mints a session and returns it with the RAW refresh token, which exists
    # only in this return value and in the response built from it. Nothing can
    # read it back afterwards -- only the digest is stored.
    # sso_session groups this row with the others minted for the same browser,
    # so a sessions list can show one entry per device instead of one per
    # application-and-device pair.
    #
    # It is NOT what the refresh token is scoped to -- that stays the client,
    # below -- so a token stolen from one application is still useless at
    # another even when they share a device.
    def issue!(identity:, client:, request: nil, device_name: nil, sso_session: nil)
      raw = SecureRandom.urlsafe_base64(32)

      session = create!(
        identity: identity,
        client: client,
        sso_session: sso_session,
        refresh_token_digest: digest(raw),
        device_name: device_name.presence,
        user_agent: request&.user_agent,
        ip_address: request&.remote_ip,
        last_used_at: Time.current,
        expires_at: REFRESH_TOKEN_TTL.from_now
      )

      [ session, raw ]
    end

    # Looks a session up by presented token. Scoped to the client as well as the
    # digest: a refresh token issued for one application must not be redeemable
    # at another, for the same reason an access token is audience-scoped.
    #
    # Returns nil for unknown, revoked, expired, or wrong-client -- the caller
    # cannot tell which, deliberately.
    def authenticate(raw_token, client:)
      return nil if raw_token.blank?

      active.where(client: client).find_by(refresh_token_digest: digest(raw_token))
    end

    def digest(raw)
      Digest::SHA256.hexdigest(raw)
    end
  end

  # What a sessions list groups on: the browser session where there is one, and
  # this row's own id otherwise, so an ungrouped session is a device of one
  # rather than being lumped in with every other ungrouped row.
  def device_group_id
    sso_session_id || id
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
    # update_column, not update!: this runs on every refresh and must not fire
    # validations or bump updated_at, which would make "last used" and "changed"
    # indistinguishable in the sessions list.
    update_column(:last_used_at, Time.current)
  end
end
