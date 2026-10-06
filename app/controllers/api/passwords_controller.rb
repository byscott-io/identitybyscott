# frozen_string_literal: true

module Api
  # Password recovery. Both actions are deliberately uninformative about whether
  # an address exists.
  class PasswordsController < BaseController
    rate_limit to: 5, within: 1.minute, by: -> { request.remote_ip }, only: :create,
               with: -> { rate_limited!(retry_after: 1.minute) }
    rate_limit to: 3, within: 1.hour, by: -> { params[:email].to_s.downcase.strip }, only: :create,
               with: -> { rate_limited!(retry_after: 1.hour) }

    # Always 202, whether or not the address exists in this realm.
    #
    # Anything else turns this into a way to ask which realm an address belongs
    # to, which is the cross-realm fact realms exist to isolate -- and it would
    # be a far easier question to ask here than at sign-in, since no password is
    # needed.
    def create
      identity = Identity.find_for_authentication_in_realm(realm, params[:email])
      identity&.send_reset_password_instructions

      render json: { status: "accepted" }, status: :accepted
    end

    # The token is the capability, so it is the only thing that matters here.
    # Devise stores a digest of it rather than the token itself, so a database
    # read yields nothing usable.
    def update
      # The confirmation is honoured WHEN SENT, and falls back to the password
      # when it is not.
      #
      # Applications own the reset form and normally confirm there, so most
      # callers send only `password` -- for them nothing changes. But passing
      # `params[:password]` as its own confirmation unconditionally meant
      # `validates :password, confirmation: true` could never fire on this path:
      # a client that did send a mismatched confirmation had it silently
      # discarded and the password set anyway. Accepting one and ignoring it is
      # worse than not accepting it at all.
      identity = Identity.reset_password_by_token(
        reset_password_token: params[:token],
        password: params[:password],
        password_confirmation: params[:password_confirmation] || params[:password]
      )

      if identity.errors.empty?
        # A successful reset clears a lock. Someone who can read the inbox has
        # proved more than a password would, and leaving them locked out after
        # a successful reset is a support call with no security benefit.
        identity.unlock_access! if identity.access_locked?

        render json: { status: "reset" }
      else
        render json: { error: "Invalid or expired token" }, status: :unprocessable_content
      end
    end
  end
end
