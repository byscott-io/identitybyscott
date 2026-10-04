# frozen_string_literal: true

# Builds the body returned whenever credentials are accepted -- sign-in,
# sign-up, and MFA verification -- so the three cannot drift apart.
#
# Before this, each of them minted a bare access token and recorded nothing, so
# there was no sessions list, no revocation, and no way to tell one device from
# another. Every accepted credential now leaves a row.
module IssuesSessions
  private

  def session_response(identity)
    session, refresh_token = Session.issue!(
      identity: identity,
      client: Current.client,
      request: request,
      device_name: params[:device_name]
    )

    issuer = TokenIssuer.new(identity: identity, client: Current.client, session: session)

    {
      access_token: issuer.access_token,
      token_type: "Bearer",
      expires_in: TokenIssuer::ACCESS_TOKEN_TTL.to_i,

      # Returned ONCE. Only a digest is stored, so this value cannot be
      # recovered afterwards by anyone, including whoever reads the database.
      refresh_token: refresh_token,
      refresh_token_expires_in: Session::REFRESH_TOKEN_TTL.to_i
    }
  end
end
