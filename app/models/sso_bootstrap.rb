# frozen_string_literal: true

# The one-use token that lets a top-level navigation establish the SSO cookie.
#
# WHY THIS HAS TO EXIST, because it looks like a detour otherwise. The
# applications are on their own registrable domains, so this server is a third
# party to all of them. A cookie set in the response to a cross-site request --
# which is what POST /auth/sign_in is -- is refused by Safari's tracking
# prevention and partitioned by Firefox's, filed under the application's own
# top-level site where no other application in the realm can see it. Issuing the
# cookie at sign-in therefore appears to work in whichever browser it is first
# tried in and silently fails to do the one thing it is for.
#
# A top-level navigation to this server makes it the top-level site, so the
# cookie is first-party and shared across the realm. This token is what makes
# such a navigation safe to act on: without it, anyone could navigate a browser
# to /sso/bootstrap and be handed a session.
class SsoBootstrap < ApplicationRecord
  # A minute, which is a ceiling rather than a budget: the application navigates
  # as soon as it has the sign-in response, so this is normally spent in
  # milliseconds. The ceiling allows for a slow network and a skewed clock, and
  # no more -- it travels in a URL, so it is exposed like an authorization code.
  BOOTSTRAP_TTL = 1.minute

  belongs_to :identity
  belongs_to :client, foreign_key: :issuing_client_id, inverse_of: false

  # The sign-in this token was issued alongside. Carried so the navigation can
  # link that session to the realm session it establishes -- the realm session
  # does not exist yet at sign-in, so the link cannot be made there.
  #
  # Optional: a token issued before this existed has none, and signing out then
  # simply revokes nothing rather than everything.
  belongs_to :session, optional: true

  validates :token_digest, presence: true, uniqueness: true
  validates :expires_at, presence: true

  scope :live, -> { where(consumed_at: nil).where(expires_at: Time.current..) }

  class << self
    def issue!(identity:, client:, session: nil)
      raw = SecureRandom.urlsafe_base64(32)

      bootstrap = create!(
        identity: identity,
        client: client,
        session: session,
        token_digest: digest(raw),
        expires_at: BOOTSTRAP_TTL.from_now
      )

      [ bootstrap, raw ]
    end

    # Claimed with a single conditional UPDATE, for the same reason
    # AuthorizationCode is: reading the row, checking it, then writing leaves a
    # window in which two navigations both believe they hold the token, and this
    # token establishes a realm-wide session.
    def consume!(raw_token)
      return nil if raw_token.blank?

      bootstrap = live.find_by(token_digest: digest(raw_token))
      return nil if bootstrap.nil?

      claimed = live.where(id: bootstrap.id).update_all(consumed_at: Time.current)
      claimed == 1 ? bootstrap.reload : nil
    end

    def digest(raw)
      Digest::SHA256.hexdigest(raw)
    end
  end

  def consumed?
    consumed_at.present?
  end
end
