# frozen_string_literal: true

module Api
  # Enrolling and removing a second factor. The application renders the screens;
  # this server owns the secret and the codes.
  class MfaEnrollmentController < AuthenticatedController
    BACKUP_CODE_COUNT = 10

    def show
      render json: {
        enabled: current_identity.mfa_enabled,
        backup_codes_remaining: current_identity.backup_code_digests.length
      }
    end

    # DELIBERATELY NOT the codes themselves.
    #
    # corebyscott's equivalent returns the raw codes, because an application on
    # local Devise stores them in plaintext and can read them back. This server
    # stores DIGESTS -- see Identity#backup_code_digests -- so the raw codes
    # exist only in the response that generated them, at `enable` and
    # `regenerate_backup_codes`. There is nothing to return, and that is correct
    # rather than a gap: a store that can show you your codes can also show them
    # to whoever reads the database.
    #
    # So this contract differs from core's on purpose. A client expecting an
    # array gets a count, and should send the person to regenerate if they have
    # lost them.
    def backup_codes
      unless current_identity.mfa_enabled?
        return render json: { error: "MFA is not enabled" }, status: :unprocessable_content
      end

      render json: {
        backup_codes_remaining: current_identity.backup_code_digests.length,
        backup_codes_generated_at: current_identity.backup_codes_generated_at,
        # Stated in the payload so an integrator reading a response, rather than
        # this comment, understands why there is no array here.
        detail: "Backup codes are stored hashed and cannot be retrieved. " \
                "Regenerate to obtain a new set."
      }
    end

    # Generates a secret and hands back the provisioning URI for a QR code. The
    # secret is NOT enabled yet: enrolment is only complete once a code proves
    # the authenticator actually has it, otherwise a mistyped scan locks the
    # person out of their own account.
    def setup
      secret = ROTP::Base32.random
      current_identity.update!(mfa_secret: secret, mfa_enabled: false)

      render json: {
        secret: secret,
        provisioning_uri: ROTP::TOTP.new(secret, issuer: issuer_label)
                                    .provisioning_uri(current_identity.email)
      }
    end

    def enable
      return render_invalid_code unless current_identity.verify_totp(params[:code])

      codes = generate_backup_codes
      current_identity.update!(
        mfa_enabled: true,
        backup_codes: codes.map { |code| Digest::SHA256.hexdigest(code) }.to_json,
        backup_codes_generated_at: Time.current
      )

      # The only time these are ever readable. Stored as digests, so they cannot
      # be shown again -- which is the point.
      render json: { enabled: true, backup_codes: codes }
    end

    # Requires a current code, not just a valid session. A stolen access token
    # must not be enough to remove the second factor it was supposed to be
    # protected by.
    def disable
      return render_invalid_code unless accept_second_factor?(params[:code])

      current_identity.update!(
        mfa_enabled: false, mfa_secret: nil,
        backup_codes: nil, backup_codes_generated_at: nil
      )

      render json: { enabled: false }
    end

    def regenerate_backup_codes
      return render_invalid_code unless accept_second_factor?(params[:code])

      codes = generate_backup_codes
      current_identity.update!(
        backup_codes: codes.map { |code| Digest::SHA256.hexdigest(code) }.to_json,
        backup_codes_generated_at: Time.current
      )

      render json: { backup_codes: codes }
    end

    private

    def accept_second_factor?(code)
      return false if code.blank?

      current_identity.verify_totp(code) || current_identity.consume_backup_code!(code)
    end

    def generate_backup_codes
      Array.new(BACKUP_CODE_COUNT) do
        # Grouped for legibility, lowercase so a person typing it back cannot
        # get the case wrong.
        "#{SecureRandom.alphanumeric(4)}-#{SecureRandom.alphanumeric(4)}".downcase
      end
    end

    def issuer_label
      Current.client.realm.name
    end

    def render_invalid_code
      render json: { error: "Invalid code" }, status: :unauthorized
    end
  end
end
