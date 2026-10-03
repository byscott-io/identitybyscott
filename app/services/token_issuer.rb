# frozen_string_literal: true

# Mints an access token for one identity, for one application.
#
# Audience-scoped on purpose: a token minted for one application must not
# authenticate at another, even inside the same realm. Without that, one
# authentication really would grant access to everything.
class TokenIssuer
  # Short, because verification is offline: an application checks a signature
  # rather than asking this server, so revocation only takes effect when the
  # token expires. Fifteen minutes bounds that window.
  ACCESS_TOKEN_TTL = 15.minutes

  # Claim names are the integration contract with the client library, which
  # caches them on its own user row. They are the OIDC standard names, and must
  # not be renamed casually: corebyscott's resolver maps exactly these.
  PROFILE_CLAIMS = {
    email: :email,
    given_name: :first_name,
    family_name: :last_name,
    nickname: :nickname,
    zoneinfo: :time_zone
  }.freeze

  def initialize(identity:, client:, issuer: nil)
    @identity = identity
    @client = client
    @issuer = issuer || ENV.fetch("IDENTITY_ISSUER")
  end

  def access_token
    JWT.encode(payload, SigningKeys.private_key, SigningKeys::ALGORITHM, { kid: SigningKeys.key_id })
  end

  def payload
    now = Time.current

    claims = {
      iss: @issuer,
      sub: @identity.id,
      aud: @client.client_id,
      iat: now.to_i,
      exp: (now + ACCESS_TOKEN_TTL).to_i,
      jti: SecureRandom.uuid,

      # The realm this identity belongs to, stated by THIS server.
      #
      # Informational and defensive, never an authorization input. An
      # application already knows its own realm from its registration, so this
      # exists so it can CHECK rather than assume -- storing realm on its own
      # user row and refusing a token whose realm claim disagrees.
      #
      # The failure that catches is real and otherwise silent: a client
      # registered in the wrong realm would have identities from that realm
      # provision into the application, cross-tenant, with nothing to show it.
      #
      # Note this is not the application telling us a realm -- that direction is
      # forbidden, because an application that could name a realm could claim
      # any realm. It is the reverse: we tell the application, and it may verify.
      realm: @client.realm.key
    }

    PROFILE_CLAIMS.each do |claim, attribute|
      value = @identity.public_send(attribute)
      claims[claim] = value if value.present?
    end

    claims
  end

  # Deliberately absent: any claim about containers, memberships or roles.
  #
  # This server has no memberships table and cannot know which organization a
  # person is acting in. A guessed container claim is a cross-tenant data leak
  # rather than an error, so the application resolves that itself after mapping
  # the identity.
end
