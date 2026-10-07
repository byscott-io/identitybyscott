# frozen_string_literal: true

# The one place that decides whether a password gets someone in.
#
# Extracted because there are now TWO things that ask -- the credential API,
# where an application posts a form it rendered, and the hosted login page, where
# this server renders the form itself. Two copies of this sequence would be a
# security problem rather than a tidiness one: the checks are ORDERED, and the
# order is load-bearing, so a copy that drifted would not look broken. It would
# just quietly stop asking something.
#
# The order, and why each step is where it is:
#
#   1. unknown address and wrong password are INDISTINGUISHABLE. Saying "no such
#      account" would turn this into a way to ask which realm an address exists
#      in, which is the cross-realm fact realms isolate.
#   2. a lock is reported only AFTER the password verifies. Reporting it to
#      somebody who does not know the password tells them the address exists.
#   3. confirmation likewise.
#   4. the grant is checked BEFORE any second factor, so nobody completes MFA
#      only to be refused.
#   5. MFA last, because it is the one step that continues rather than concludes.
#
# Returns an outcome rather than rendering, so the API answers in JSON and the
# page answers in HTML from identical decisions.
class CredentialCheck
  OUTCOMES = %i[invalid locked unconfirmed not_granted mfa_required ok].freeze

  Result = Struct.new(:outcome, :identity, keyword_init: true) do
    def ok? = outcome == :ok
    def mfa_required? = outcome == :mfa_required
  end

  def self.call(realm:, client:, email:, password:)
    new(realm: realm, client: client, email: email, password: password).call
  end

  def initialize(realm:, client:, email:, password:)
    @realm = realm
    @client = client
    @email = email
    @password = password
  end

  def call
    identity = Identity.find_for_authentication_in_realm(@realm, @email)
    return failure(:invalid) if identity.nil?

    unless identity.valid_password?(@password)
      # Lockable counts this. Devise increments failed_attempts and locks at the
      # configured maximum.
      register_failure(identity)
      return failure(:invalid)
    end

    return failure(:locked, identity) if identity.access_locked?
    return failure(:unconfirmed, identity) unless identity.active_for_authentication?

    identity.reset_failed_attempts! if identity.failed_attempts.positive?

    return failure(:not_granted, identity) unless Grant.permits?(identity: identity, client: @client)

    return Result.new(outcome: :mfa_required, identity: identity) if identity.mfa_enabled?

    Result.new(outcome: :ok, identity: identity)
  end

  # Counting a failure and locking at the maximum, in one place so neither
  # caller has to remember both halves.
  def self.register_failure(identity)
    identity.increment_failed_attempts

    return if identity.failed_attempts < Devise.maximum_attempts
    return if identity.access_locked?

    identity.lock_access!
  end

  private

  def register_failure(identity)
    self.class.register_failure(identity)
  end

  def failure(outcome, identity = nil)
    Result.new(outcome: outcome, identity: identity)
  end
end
