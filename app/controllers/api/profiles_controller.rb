# frozen_string_literal: true

module Api
  # The fields this server owns: name, nickname, time zone, phone and the email
  # address itself. Everything else about a person -- their role, which
  # organization they are acting in, their notification preferences -- belongs to
  # the application and is not reachable here.
  class ProfilesController < AuthenticatedController
    # Deliberately NOT permitted: realm_id, encrypted_password, confirmed_at,
    # mfa_*, failed_attempts, locked_at, signup_client_id. Several of those would
    # be privilege escalation if a client could set them -- confirming your own
    # address, clearing your own lock, or moving yourself into another realm.
    PERMITTED = %i[first_name last_name nickname time_zone phone email].freeze

    def update
      attributes = profile_params

      # An email change normally waits for the new address to be confirmed
      # (reconfirmable), which is right when the realm requires confirmation:
      # until then the old address still works and nobody is locked out by a
      # typo. A realm that does not require confirmation should not be given a
      # pending state it never asked for, so there the change applies at once.
      if attributes.key?(:email) && !current_identity.realm.require_email_confirmation?
        current_identity.skip_reconfirmation!
      end

      if current_identity.update(attributes)
        render json: {
          user: identity_json(current_identity),
          # Say so rather than leaving the client to discover that the address it
          # just sent is not the one in effect yet.
          pending_email: current_identity.unconfirmed_email,
          message: "Profile updated successfully."
        }
      else
        render json: { error: current_identity.errors.full_messages.join(", ") },
               status: :unprocessable_content
      end
    end

    private

    # Accepts core's shape -- { user: { ... } } -- so repointing an application at
    # this server stays a base-URL change rather than a rewrite. A bare top-level
    # body is accepted too, for a client that is not corebyscott.
    def profile_params
      source = params[:user].presence || params
      source.permit(*PERMITTED).to_h.symbolize_keys
    end

    def identity_json(identity)
      {
        id: identity.id,
        email: identity.email,
        first_name: identity.first_name,
        last_name: identity.last_name,
        nickname: identity.nickname,
        time_zone: identity.time_zone,
        phone: identity.phone
      }
    end
  end
end
