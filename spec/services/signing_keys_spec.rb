# frozen_string_literal: true

require "rails_helper"

# These exist because of a real production failure, not a hypothetical one.
#
# .kamal/secrets is a KEY=VALUE file. A PEM is multi-line. The deploy workflow
# wrote the PEM into it directly, so the container booted with a 31-byte signing
# key -- the PEM's opening banner line and nothing else -- and every request
# to /.well-known/jwks.json answered 500, because OpenSSL raises
# RSAError and the endpoint only rescues ConfigurationError.
RSpec.describe SigningKeys do
  let(:key) { OpenSSL::PKey::RSA.generate(2048) }

  around do |example|
    SigningKeys.reset!
    example.run
  ensure
    ENV.delete("IDENTITY_SIGNING_KEY")
    ENV.delete("IDENTITY_RETIRED_PUBLIC_KEYS")
    SigningKeys.reset!
  end

  describe "the configured signing key" do
    it "accepts a PEM" do
      ENV["IDENTITY_SIGNING_KEY"] = key.to_pem

      expect(described_class.private_key.to_pem).to eq(key.to_pem)
    end

    it "accepts single-line base64 of a PEM, which is what survives a KEY=VALUE file" do
      encoded = Base64.strict_encode64(key.to_pem)

      expect(encoded).not_to include("\n")
      ENV["IDENTITY_SIGNING_KEY"] = encoded

      expect(described_class.private_key.to_pem).to eq(key.to_pem)
    end

    it "treats a PEM truncated to its first line as a configuration error, not an OpenSSL error" do
      truncated = key.to_pem.lines.first.strip
      ENV["IDENTITY_SIGNING_KEY"] = truncated

      # The distinction is the whole point: the JWKS endpoint rescues
      # ConfigurationError and answers 503. An OpenSSL::PKey::RSAError escapes
      # it and renders a public 500.
      expect { described_class.private_key }
        .to raise_error(SigningKeys::ConfigurationError, /does not end one/)
    end

    it "reports the byte length in that error, which is what identified the fault" do
      # Derived, not written out: the literal banner is what
      # bin/check-public-safe scans for, and this repository is public.
      truncated = key.to_pem.lines.first.strip
      ENV["IDENTITY_SIGNING_KEY"] = truncated

      expect { described_class.private_key }
        .to raise_error(SigningKeys::ConfigurationError, /#{truncated.bytesize} bytes/)
    end

    it "rejects a value that is neither a PEM nor base64" do
      ENV["IDENTITY_SIGNING_KEY"] = "not a key at all!"

      expect { described_class.private_key }
        .to raise_error(SigningKeys::ConfigurationError, /neither a PEM nor base64/)
    end

    it "rejects base64 that decodes to something other than a PEM" do
      ENV["IDENTITY_SIGNING_KEY"] = Base64.strict_encode64("just some bytes")

      expect { described_class.private_key }
        .to raise_error(SigningKeys::ConfigurationError, /not a PEM/)
    end

    it "still refuses public-only material" do
      ENV["IDENTITY_SIGNING_KEY"] = key.public_key.to_pem

      expect { described_class.private_key }
        .to raise_error(SigningKeys::ConfigurationError, /no private component/)
    end

    it "still reports an absent key" do
      expect { described_class.private_key }
        .to raise_error(SigningKeys::ConfigurationError, /No signing key configured/)
    end
  end

  describe "retired public keys" do
    it "accepts base64 as well, so a rotation is not a second encoding puzzle" do
      retired = OpenSSL::PKey::RSA.generate(2048)
      ENV["IDENTITY_SIGNING_KEY"] = Base64.strict_encode64(key.to_pem)
      ENV["IDENTITY_RETIRED_PUBLIC_KEYS"] = Base64.strict_encode64(retired.public_key.to_pem)

      expect(described_class.retired_public_keys.map(&:to_pem))
        .to eq([ retired.public_key.to_pem ])
    end
  end
end
