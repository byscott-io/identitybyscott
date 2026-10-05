# frozen_string_literal: true

module Api
  # Sign in. The credentials arrive from a form the APPLICATION renders, posted
  # here over HTTPS -- this server has no forms of its own.
  class SessionsController < BaseController
    include IssuesSessions
    # Keyed on BOTH the address and the IP, because either alone is trivially
    # sidestepped: rotate addresses to beat an email limit, rotate IPs to beat
    # an address limit. This is the single door into a whole realm, so it
    # matters more here than on one application's own endpoint.
    rate_limit to: 10, within: 1.minute, by: -> { "#{request.remote_ip}" }, only: :create
    rate_limit to: 5, within: 1.minute, by: -> { params[:email].to_s.downcase.strip }, only: :create

    def create
      identity = Identity.find_for_authentication_in_realm(realm, params[:email])

      # Deliberately indistinguishable from a wrong password. Saying "no such
      # account" would turn this into a way to ask which realm an address
      # exists in -- which is exactly the cross-realm fact realms isolate.
      return render_invalid_credentials if identity.nil?

      unless identity.valid_password?(params[:password])
        # Lockable counts this. Devise increments failed_attempts and locks at
        # the configured maximum.
        identity.increment_failed_attempts
        identity.lock_access! if identity.failed_attempts >= Devise.maximum_attempts && !identity.access_locked?
        return render_invalid_credentials
      end

      # Checked AFTER the password, on purpose. Reporting a lock to someone who
      # does not know the password tells them the address exists.
      return render_locked if identity.access_locked?
      return render_unconfirmed unless identity.active_for_authentication?

      identity.reset_failed_attempts! if identity.failed_attempts.positive?

      # Before MFA, not after: making someone complete a second factor and
      # then refusing them wastes their time and teaches nothing.
      return render_not_granted unless grant_permits_client?(identity)

      return render_mfa_required(identity) if identity.mfa_enabled?

      render_signed_in(identity)
    end

    private

    def render_signed_in(identity)
      render json: session_response(identity)
    end

    # The same body and status for an unknown address and a wrong password.
    def render_invalid_credentials
      render json: { error: "Invalid email or password" }, status: :unauthorized
    end

    def render_locked
      render json: { error: "Account locked", detail: "Check your email for unlock instructions." },
             status: :locked
    end

    def render_unconfirmed
      render json: { error: "Email not confirmed" }, status: :forbidden
    end

    # MFA is a second step rather than a second field, so the application can
    # render its own prompt. The interim token proves the password was correct
    # and nothing more; it cannot be used as an access token.
    def render_mfa_required(identity)
      render json: {
        mfa_required: true,
        mfa_token: MfaChallenge.issue(identity: identity, client: Current.client)
      }
    end
  end
end
