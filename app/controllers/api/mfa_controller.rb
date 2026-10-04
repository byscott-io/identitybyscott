# frozen_string_literal: true

module Api
  # The second step of sign in. The application renders its own prompt and posts
  # the code here with the challenge it was given.
  class MfaController < BaseController
    include IssuesSessions
    # Tighter than sign-in: a TOTP code is six digits, so an unthrottled
    # endpoint is a feasible brute force rather than a theoretical one. Keyed on
    # the challenge, so one person's attempts cannot exhaust another's budget.
    rate_limit to: 5, within: 1.minute, by: -> { params[:mfa_token].to_s[0, 64] }, only: :verify

    def verify
      identity = MfaChallenge.identity_for(params[:mfa_token], client: Current.client, realm: realm)

      unless accept_code?(identity, params[:code])
        identity.increment_failed_attempts
        identity.lock_access! if identity.failed_attempts >= Devise.maximum_attempts && !identity.access_locked?
        return render json: { error: "Invalid code" }, status: :unauthorized
      end

      identity.reset_failed_attempts! if identity.failed_attempts.positive?

      render json: session_response(identity)
    rescue MfaChallenge::InvalidChallenge
      # Covers an expired challenge, one for another client, and an access token
      # presented in its place. All the same answer: start again.
      render json: { error: "Invalid or expired challenge" }, status: :unauthorized
    end

    private

    # A TOTP code, or one of the backup codes. A backup code is consumed on use
    # -- otherwise it is a permanent second factor that cannot be revoked
    # without regenerating the whole set.
    def accept_code?(identity, code)
      return false if code.blank?
      return true if identity.verify_totp(code)

      identity.consume_backup_code!(code)
    end
  end
end
