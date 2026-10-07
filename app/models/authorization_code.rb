# frozen_string_literal: true

# The code /authorize hands back through a redirect, exchanged once for tokens.
#
# This is the most exposed credential this server issues. It travels in a URL,
# so it passes through the address bar, the browser's history, server logs at
# the far end and any Referer the application leaks. The design assumes it WILL
# be seen by something it was not meant for, and makes seeing it insufficient:
#
#   * it lives for one minute
#   * it is consumed on first use, atomically
#   * it is bound to the client, the exact redirect_uri and a PKCE challenge,
#     all of which the exchange must reproduce
#   * it dies with the browser session it came from
#
# Only a digest is stored, as with refresh tokens and the SSO cookie.
class AuthorizationCode < ApplicationRecord
  # Long enough for a redirect and an immediate exchange, and no longer. OAuth
  # 2.1 permits up to ten minutes and advises far less; a code is redeemed by
  # the page it lands on, within a second or two, so a minute is already
  # generous and every extra second is a window for a leaked URL.
  CODE_TTL = 1.minute

  # S256 only. `plain` puts the verifier in the request that carries the code,
  # so anything that can see one can see both -- which is the exact situation
  # PKCE exists to survive.
  CHALLENGE_METHOD = "S256"

  belongs_to :identity
  belongs_to :sso_session
  belongs_to :client, foreign_key: :authorized_client_id, inverse_of: false

  validates :code_digest, presence: true, uniqueness: true
  validates :redirect_uri, presence: true
  validates :code_challenge, presence: true
  validates :code_challenge_method, inclusion: { in: [ CHALLENGE_METHOD ] }
  validates :expires_at, presence: true

  scope :live, -> { where(consumed_at: nil).where(expires_at: Time.current..) }

  class << self
    # Mints a code and returns it with the RAW value, which exists only in the
    # redirect URL built from it.
    def issue!(identity:, client:, sso_session:, redirect_uri:, code_challenge:,
               nonce: nil, scope: nil)
      raw = SecureRandom.urlsafe_base64(32)

      code = create!(
        identity: identity,
        client: client,
        sso_session: sso_session,
        code_digest: digest(raw),
        redirect_uri: redirect_uri,
        code_challenge: code_challenge,
        code_challenge_method: CHALLENGE_METHOD,
        nonce: nonce.presence,
        scope: scope.presence,
        expires_at: CODE_TTL.from_now
      )

      [ code, raw ]
    end

    # Consumes a code, returning it only if everything it was bound to still
    # holds. Unused in this slice -- the exchange is the next one -- but it
    # lives here so the consuming rules sit beside the issuing ones rather than
    # being reinvented in a controller.
    #
    # The UPDATE is the lock. Marking it consumed in a single conditional
    # statement and checking how many rows changed means two simultaneous
    # redemptions cannot both succeed: the second updates nothing. Reading the
    # row, checking `consumed_at`, then writing it would leave exactly that
    # race, and a replayed code is the thing this is here to stop.
    def consume!(raw_token, client:, redirect_uri:)
      return nil if raw_token.blank?

      scope = live.where(code_digest: digest(raw_token), client: client, redirect_uri: redirect_uri)

      # Bound to a session that is still good. A code outlives its browser
      # session otherwise, and signing out would not reach one already in
      # flight.
      scope = scope.where(sso_session: SsoSession.active)

      code = scope.first
      return nil if code.nil?

      claimed = live.where(id: code.id).update_all(consumed_at: Time.current)
      claimed == 1 ? code.reload : nil
    end

    def digest(raw)
      Digest::SHA256.hexdigest(raw)
    end
  end

  def consumed?
    consumed_at.present?
  end

  def live?
    consumed_at.nil? && expires_at.future?
  end

  # Verifies a presented PKCE verifier against the stored challenge.
  #
  # Compared with a fixed-time comparison, like any secret. The challenge is
  # already public-ish -- it was in the authorize URL -- but the verifier is
  # not, and a length-or-prefix timing difference is free to exploit when the
  # attacker controls the guess.
  def verifies?(code_verifier)
    return false if code_verifier.blank?

    expected = Base64.urlsafe_encode64(
      OpenSSL::Digest::SHA256.digest(code_verifier), padding: false
    )

    ActiveSupport::SecurityUtils.secure_compare(expected, code_challenge)
  end
end
