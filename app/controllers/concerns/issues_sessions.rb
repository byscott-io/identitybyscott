# frozen_string_literal: true

# Builds the body returned whenever credentials are accepted -- sign-in,
# sign-up, and MFA verification -- so the three cannot drift apart.
#
# Before this, each of them minted a bare access token and recorded nothing, so
# there was no sessions list, no revocation, and no way to tell one device from
# another. Every accepted credential now leaves a row.
module IssuesSessions
  extend ActiveSupport::Concern

  include SsoCookie

  private

  # Whether this identity may use the calling application.
  #
  # Checked at the moment a session would be issued rather than beside the
  # password, because a grant is not a credential: failing it is an
  # authorisation answer ("not for you here"), not an authentication one, and
  # conflating them would tell someone holding a correct password that it was
  # wrong.
  #
  # Deliberately distinguishable from bad credentials. The usual argument for a
  # single indistinguishable failure is that a specific one reveals whether an
  # address exists -- but this response is only ever reached by someone who has
  # ALREADY proven the password, so it reveals nothing they did not just
  # demonstrate they knew.
  def grant_permits_client?(identity)
    Grant.permits?(identity: identity, client: Current.client)
  end

  def render_not_granted
    render json: {
      error: "Not granted",
      detail: "This account exists but has not been enabled for this application."
    }, status: :forbidden
  end

  # sso_cookie: false is for the code exchange, which is completing a login that
  # already established a realm session rather than starting one. Re-issuing
  # there would turn SsoSession's absolute twelve-hour lifetime into a sliding
  # one, which is the opposite of why that number was chosen.
  def session_response(identity, sso_cookie: true)
    session, refresh_token = Session.issue!(
      identity: identity,
      client: Current.client,
      request: request,
      device_name: params[:device_name]
    )

    # The realm-wide browser session, where the realm has asked for one.
    #
    # Here rather than in SessionsController because this method is reached by
    # sign-in, sign-up AND mfa verification -- every path that accepts a
    # credential and no other. In particular an MFA challenge does NOT come
    # through here, so the cookie is never issued to someone who has given a
    # password but not yet a second factor.
    issue_sso_cookie!(identity) if sso_cookie

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
