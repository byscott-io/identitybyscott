# frozen_string_literal: true

# The short-lived token handed out between a correct password and a correct TOTP
# code.
#
# Signed with the same key as an access token but carrying a purpose claim, and
# verification refuses it for anything else. Without that, an interim token
# would BE an access token and MFA would be decorative.
class MfaChallenge
  class InvalidChallenge < StandardError; end

  PURPOSE = "mfa_challenge"
  TTL = 5.minutes

  class << self
    def issue(identity:, client:)
      JWT.encode(
        {
          sub: identity.id,
          aud: client.client_id,
          purpose: PURPOSE,
          exp: TTL.from_now.to_i,
          jti: SecureRandom.uuid
        },
        SigningKeys.private_key,
        SigningKeys::ALGORITHM,
        { kid: SigningKeys.key_id }
      )
    end

    # Returns the identity, or raises. The purpose claim is checked explicitly:
    # an access token presented here must NOT be accepted as a completed first
    # factor, and vice versa.
    def identity_for(token, client:, realm:)
      payload, = JWT.decode(
        token, SigningKeys.private_key.public_key, true,
        algorithm: SigningKeys::ALGORITHM, aud: client.client_id, verify_aud: true
      )

      raise InvalidChallenge, "Not an MFA challenge" unless payload["purpose"] == PURPOSE

      realm.identities.find_by(id: payload["sub"]) ||
        raise(InvalidChallenge, "Unknown identity for this realm")
    rescue JWT::DecodeError => e
      raise InvalidChallenge, e.message
    end
  end
end
