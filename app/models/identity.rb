# frozen_string_literal: true

# A person, within one realm.
#
# The uuid primary key is the OIDC `sub` and the only cross-app key for a
# person. Email is a mutable attribute and is never used as a key.
#
# Devise is included for its MODEL modules only. There is no devise_for, no
# Devise controller and no view: the credential endpoints are this app's own
# API, because consuming apps build their own forms and post to it.
class Identity < ApplicationRecord
  devise :database_authenticatable, :recoverable, :confirmable, :lockable

  belongs_to :realm
  has_many :sessions, dependent: :destroy
  belongs_to :signup_client, class_name: "Client", optional: true

  validates :email, presence: true,
                    uniqueness: { scope: :realm_id, case_sensitive: false },
                    format: { with: URI::MailTo::EMAIL_REGEXP }

  # Password rules, deliberately explicit rather than via Devise's :validatable,
  # which would also add a second email-format validation alongside the one
  # above.
  #
  # MINIMUM 12. Longer than the NIST 800-63B floor of 8, because this server
  # guards whole realms rather than one application, and because length is the
  # only password rule that reliably helps -- no composition rules, per the same
  # guidance. Migrated identities keep their existing hashes and are never
  # revalidated, so this applies to new and reset passwords only.
  #
  # MAXIMUM 72 BYTES, and this one is not arbitrary: bcrypt silently truncates
  # at 72 bytes. Without this, a 100-character passphrase would have its last 28
  # bytes ignored with nothing to say so, and two different long passphrases
  # sharing a prefix would both unlock the account.
  PASSWORD_RANGE = 12..72

  validates :password,
            length: { minimum: PASSWORD_RANGE.min },
            if: :password_required?

  # Checked in BYTES, not characters, which Rails' length validator cannot do.
  # bcrypt truncates at 72 BYTES, so a 25-character passphrase of multi-byte
  # characters is already over the limit while looking comfortably short -- and
  # a character-based maximum would pass it straight through to be silently cut.
  validate :password_within_bcrypt_limit, if: :password_required?

  validates :password, confirmation: true, if: :password_required?

  before_validation :normalize_email

  # Devise looks an identity up by its authentication_keys GLOBALLY. That is
  # wrong here: email is unique per realm, so a global lookup would find an
  # identity from another realm and authenticate against the wrong suite.
  #
  # The realm is always known before a credential is checked -- it is resolved
  # from the request's client_id -- so scope the lookup to it.
  def self.find_for_authentication_in_realm(realm, email)
    return nil if realm.nil? || email.blank?

    realm.identities.find_by("lower(email) = ?", email.to_s.downcase.strip)
  end

  # Devise's own extension point, consulted in BOTH places that matter: whether
  # to send the confirmation email, and whether to let an unconfirmed identity
  # sign in. One override covers both.
  #
  # Overriding active_for_authentication? instead is the common mistake -- it
  # blocks the sign-in but still mails every new identity a link it does not
  # need.
  def confirmation_required?
    realm.require_email_confirmation? && super
  end

  # Re-confirmation on email change follows the same realm setting.
  def reconfirmable?
    realm.require_email_confirmation?
  end

  # Accepting an invitation proves inbox access -- the token was delivered to
  # that address and only someone who can read it could present it -- so
  # confirmation is earned by that flow rather than asked for separately.
  def confirm_by_invitation!
    return true if confirmed?

    update_columns(confirmed_at: Time.current, confirmation_token: nil) # rubocop:disable Rails/SkipsModelValidations
  end

  # Every notification goes through this app's own mailer, never Devise's.
  #
  # Devise's mailer cannot work here -- its views build URLs from devise_for
  # routes, and this app has none -- and it should not: its links would point at
  # this server, which has no forms. Each link has to land the person back in
  # the app they started from, which only IdentityMailer knows how to build.
  def send_devise_notification(notification, *args)
    IdentityMailer.public_send(notification, self, *args).deliver_later
  end

  # --- MFA (TOTP) -------------------------------------------------------------

  # Verified with a drift window, because phone clocks are not accurate and a
  # code rejected for being a few seconds old is indistinguishable, to the
  # person typing it, from a broken feature.
  TOTP_DRIFT = 30

  def verify_totp(code)
    return false if mfa_secret.blank? || code.blank?

    ROTP::TOTP.new(mfa_secret, issuer: "identitybyscott")
              .verify(code.to_s.gsub(/\s/, ""), drift_behind: TOTP_DRIFT, drift_ahead: TOTP_DRIFT)
              .present?
  end

  # Backup codes are stored as digests, never in the clear. A stolen database
  # dump must not yield usable second factors.
  def backup_code_digests
    JSON.parse(backup_codes.presence || "[]")
  rescue JSON::ParserError
    []
  end

  # Consumed on use. A reusable backup code is a permanent second factor that
  # cannot be revoked without regenerating the whole set.
  def consume_backup_code!(code)
    normalized = code.to_s.strip.downcase
    return false if normalized.blank?

    digest = Digest::SHA256.hexdigest(normalized)
    remaining = backup_code_digests
    return false unless remaining.delete(digest)

    update_columns(backup_codes: remaining.to_json) # rubocop:disable Rails/SkipsModelValidations
    true
  end

  def full_name
    [ first_name, last_name ].compact_blank.join(" ").presence
  end

  private

  # Required on create, and on any change. Not on an unrelated update, which
  # would make every profile edit demand a password.
  def password_required?
    return true if new_record?

    password.present? || password_confirmation.present?
  end

  def password_within_bcrypt_limit
    return if password.blank?
    return if password.bytesize <= PASSWORD_RANGE.max

    errors.add(:password,
               "is too long (maximum #{PASSWORD_RANGE.max} bytes; " \
               "#{password.bytesize} given). bcrypt ignores anything beyond that.")
  end

  def normalize_email
    self.email = email.to_s.downcase.strip if email.present?
  end
end
