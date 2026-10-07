# frozen_string_literal: true

# The validated authorize request, carried across the login form.
#
# /authorize validates everything -- the client, the exact redirect_uri, the
# response type, state, PKCE -- and then has to render a form. Whatever carries
# those parameters to the POST must not be re-editable in between, or every one
# of those checks would have to be redone against fresh user input, and the
# redirect_uri check in particular is the one that must never be skipped.
#
# So they travel as a SIGNED, EXPIRING message rather than as hidden fields.
# Hidden fields would be user input again by the time they came back; this is
# this server's own statement that it already validated them.
#
# It is not a credential. Holding one lets somebody start a login they could
# have started anyway by visiting /authorize -- it carries no identity and
# proves nothing. The CSRF cookie is what binds the submission to a browser.
class PendingAuthorization
  # Long enough to read a form and type a password, short enough that a
  # half-finished login does not stay resumable all day.
  EXPIRY = 15.minutes

  KEYS = %i[client_id redirect_uri state code_challenge nonce scope].freeze

  class Invalid < StandardError; end

  def self.encode(**attributes)
    unknown = attributes.keys - KEYS
    raise ArgumentError, "unknown keys: #{unknown.join(', ')}" if unknown.any?

    verifier.generate(attributes.slice(*KEYS).compact, expires_in: EXPIRY)
  end

  # Raises on a tampered, expired or absent message. Never returns a partially
  # trusted hash -- the point is that everything in it was validated before it
  # was signed.
  def self.decode(message)
    raise Invalid, "missing" if message.blank?

    payload = verifier.verified(message)
    raise Invalid, "tampered or expired" if payload.nil?

    payload.symbolize_keys
  end

  def self.verifier
    Rails.application.message_verifier(:sso_pending_authorization)
  end
  private_class_method :verifier
end
