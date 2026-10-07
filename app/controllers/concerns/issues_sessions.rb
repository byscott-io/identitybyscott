# frozen_string_literal: true

# Builds the body returned whenever credentials are accepted -- sign-in,
# sign-up, and MFA verification -- so the three cannot drift apart.
#
# Before this, each of them minted a bare access token and recorded nothing, so
# there was no sessions list, no revocation, and no way to tell one device from
# another. Every accepted credential now leaves a row.
module IssuesSessions
  extend ActiveSupport::Concern

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

  # sso_bootstrap: false is for the code exchange, which is completing a login
  # that already established a realm session rather than starting one. The
  # browser redeeming a code demonstrably HAS the cookie -- that is how it got
  # the code -- so handing it a way to establish another is pointless, and
  # re-establishing one would turn SsoSession's absolute twelve-hour lifetime
  # into a sliding one, which is the opposite of why that number was chosen.
  def session_response(identity, sso_bootstrap: true, sso_session: nil)
    session, refresh_token = Session.issue!(
      identity: identity,
      client: Current.client,
      request: request,
      device_name: params[:device_name],

      # Set by the code exchange, which knows the realm session the code was
      # minted from. A password sign-in has none yet -- the realm session is
      # created by the bootstrap navigation that follows -- so the bootstrap
      # carries this session forward and makes the link there instead.
      sso_session: sso_session
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
    }.merge(sso_bootstrap ? sso_bootstrap_fields(identity, session) : {})
  end

  # The realm-wide browser session is NOT established here, and cannot be.
  #
  # This response goes back to a cross-site XHR, and this server is on a
  # different registrable domain from every application it serves. A cookie set
  # from here is refused by Safari's tracking prevention and partitioned by
  # Firefox's -- filed under the application's own top-level site, invisible to
  # every other application in the realm, which is the only thing single sign-on
  # is for. It would appear to work in whichever browser it was first tried in.
  #
  # So what goes back is a one-use token for the application to navigate with.
  # The cookie is set at /sso/bootstrap, during a top-level navigation, where
  # this server is first-party. See SsoBootstrap.
  #
  # Reached by sign-in, sign-up AND mfa verification -- every path that accepts a
  # credential and no other. An MFA challenge does not come through here, so this
  # is never handed to someone who has given a password but not a second factor.
  def sso_bootstrap_fields(identity, session)
    return {} unless Current.client.realm.sso?

    _bootstrap, raw = SsoBootstrap.issue!(
      identity: identity, client: Current.client, session: session
    )

    {
      sso_bootstrap_token: raw,
      sso_bootstrap_expires_in: SsoBootstrap::BOOTSTRAP_TTL.to_i
    }
  end
end
