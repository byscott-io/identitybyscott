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
    rate_limit to: 10, within: 1.minute, by: -> { "#{request.remote_ip}" }, only: :create,
               with: -> { rate_limited!(retry_after: 1.minute) }
    rate_limit to: 5, within: 1.minute, by: -> { params[:email].to_s.downcase.strip }, only: :create,
               with: -> { rate_limited!(retry_after: 1.minute) }

    # The sequence, its ordering and the reasons for it live in CredentialCheck,
    # because the hosted login page asks exactly the same question and two
    # copies of an ORDERED security check drift without looking broken -- a copy
    # that quietly stopped asking something would still read fine.
    def create
      result = CredentialCheck.call(
        realm: realm, client: Current.client,
        email: params[:email], password: params[:password]
      )

      case result.outcome
      when :invalid then render_invalid_credentials
      when :locked then render_locked
      when :unconfirmed then render_unconfirmed
      when :not_granted then render_not_granted
      when :mfa_required then render_mfa_required(result.identity)
      when :ok then render_signed_in(result.identity)
      end
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
