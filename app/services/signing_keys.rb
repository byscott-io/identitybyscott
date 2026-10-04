# frozen_string_literal: true

# The server's RS256 key material, and the JWK Set published from it.
#
# RS256 and not HS256: a symmetric secret able to VERIFY this server's tokens
# could also FORGE them, so under HS256 every application that checked a token
# could mint one for every other application. Here this server holds the private
# key and applications hold only the public half.
class SigningKeys
  class ConfigurationError < StandardError; end

  ALGORITHM = "RS256"

  class << self
    # Signs. Must never leave this process.
    def private_key
      @private_key ||= begin
        pem = ENV["IDENTITY_SIGNING_KEY"].presence ||
              Rails.application.credentials.identity_signing_key.presence
        raise ConfigurationError, "No signing key configured (IDENTITY_SIGNING_KEY)" if pem.nil?

        key = OpenSSL::PKey::RSA.new(decode_pem(pem))
        raise ConfigurationError, "The configured signing key has no private component" unless key.private?

        key
      end
    end

    def key_id
      @key_id ||= ENV["IDENTITY_SIGNING_KEY_ID"].presence || derive_key_id(private_key)
    end

    # Keys that are published and accepted but no longer sign: the previous key,
    # for as long as tokens it signed are still valid.
    #
    # Rotation is two-phase, and the order matters. Publish the new PUBLIC key
    # first and wait for verifiers' caches to refresh; only then start signing
    # with it. A key put straight into service is unverifiable to any verifier
    # that fetched recently and is throttled from re-fetching.
    def retired_public_keys
      ENV.fetch("IDENTITY_RETIRED_PUBLIC_KEYS", "")
         .split("|")
         .map(&:strip)
         .compact_blank
         .map { |pem| OpenSSL::PKey::RSA.new(decode_pem(pem)) }
    end

    # PUBLIC material only. An RSA private key also holds d, p, q, dp, dq and
    # qi; none of those may ever appear here, because this document is served
    # unauthenticated.
    def jwk_set
      keys = [ jwk(private_key.public_key, key_id) ]
      keys += retired_public_keys.map { |key| jwk(key, derive_key_id(key)) }

      { keys: keys.uniq { |entry| entry[:kid] } }
    end

    def reset!
      @private_key = nil
      @key_id = nil
    end

    private

    def jwk(public_key, kid)
      {
        kty: "RSA",
        use: "sig",
        alg: ALGORITHM,
        kid: kid,
        n: base64url(public_key.n.to_s(2)),
        e: base64url(public_key.e.to_s(2))
      }
    end

    # Accepts a PEM, or base64 of one.
    #
    # A PEM is multi-line and .kamal/secrets is a KEY=VALUE file, so a PEM
    # written there straight arrives as its first line only. Not hypothetical:
    # this server booted in production with a 31-byte signing key that was the
    # PEM's opening banner line and nothing else, and every request to the JWKS
    # endpoint answered 500.
    #
    # So the configured value may be single-line base64. Store it base64-encoded
    # rather than encoding it inside the deploy workflow: GitHub masks the
    # literal secret string in run logs, this repository is public so those logs
    # are world-readable, and a value transformed in the workflow is a string
    # GitHub does not know to mask.
    def decode_pem(value)
      value = value.strip

      if value.include?("-----BEGIN")
        unless value.include?("-----END")
          raise ConfigurationError,
                "IDENTITY_SIGNING_KEY begins a PEM but does not end one (#{value.bytesize} bytes). " \
                "A multi-line PEM does not survive a KEY=VALUE file; store it base64-encoded."
        end

        return value
      end

      decoded = begin
        Base64.strict_decode64(value)
      rescue ArgumentError
        raise ConfigurationError,
              "IDENTITY_SIGNING_KEY is neither a PEM nor base64-encoded PEM (#{value.bytesize} bytes)"
      end

      unless decoded.include?("-----BEGIN") && decoded.include?("-----END")
        raise ConfigurationError, "IDENTITY_SIGNING_KEY decoded from base64 but is not a PEM"
      end

      decoded
    end

    # A digest of the public DER, not an RFC 7638 thumbprint. kid is an opaque
    # string by specification, so the only requirements are that it is stable
    # per key and differs between keys, and both hold. Set
    # IDENTITY_SIGNING_KEY_ID to name keys yourself, which is easier to reason
    # about during a rotation.
    def derive_key_id(key)
      OpenSSL::Digest::SHA256.hexdigest(key.public_key.to_der)[0, 32]
    end

    def base64url(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end
  end
end
