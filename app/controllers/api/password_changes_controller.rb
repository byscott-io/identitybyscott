# frozen_string_literal: true

module Api
  # Changing a password while signed in, which is distinct from resetting a
  # forgotten one: this proves the CURRENT password rather than access to an
  # inbox, so it needs no emailed token and must not be reachable without one.
  class PasswordChangesController < AuthenticatedController
    # The current password is a credential, and guessing it here is as valuable
    # as guessing it at sign-in -- more so, since a correct guess also lets the
    # attacker lock the owner out by replacing it. Keyed on the identity rather
    # than the email, because this endpoint already knows who is asking.
    rate_limit to: 5, within: 1.minute, by: -> { request.headers["Authorization"].to_s[0, 64] }

    def update
      unless current_identity.valid_password?(params[:current_password])
        return render json: { error: "Current password is incorrect" }, status: :unprocessable_content
      end

      # password_confirmation falls back to password: the application renders the
      # form and confirms there, and core's own endpoint behaves the same way, so
      # a client that sends only `password` is not rejected.
      if current_identity.update(
        password: params[:password],
        password_confirmation: params[:password_confirmation] || params[:password]
      )
        # A successful change clears a lock, for the same reason a successful
        # reset does: someone who knows the current password has proved more
        # than the lock was protecting against.
        current_identity.unlock_access! if current_identity.access_locked?

        render json: { message: "Password changed successfully." }
      else
        render json: { error: current_identity.errors.full_messages.join(", ") },
               status: :unprocessable_content
      end
    end
  end
end
