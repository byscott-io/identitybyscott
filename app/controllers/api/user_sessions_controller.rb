# frozen_string_literal: true

module Api
  # Listing and revoking an identity's own sessions, and signing out.
  #
  # The point of holding these centrally: before this, each application kept its
  # own jwt_tokens table, so "list my sessions" meant "list my sessions in the
  # app I am looking at" and signing out of one said nothing about the others.
  # Here every session for the identity is one list, and one call ends them all.
  class UserSessionsController < AuthenticatedController
    include SsoCookie

    def index
      sessions = current_identity.sessions.active.order(created_at: :desc)

      render json: { sessions: sessions.map { |s| session_json(s) } }
    end

    def destroy
      # Scoped to the signed-in identity, so an id belonging to someone else is
      # a 404 rather than a revocation.
      session = current_identity.sessions.find_by(id: params[:id])
      return render json: { error: "Not found" }, status: :not_found if session.nil?

      session.revoke!

      render json: { revoked: 1 }
    end

    # Log out everywhere. Revokes every live session for this identity, across
    # every application and device in the realm -- which is the capability no
    # app could offer on its own, because none of them could see the others.
    def destroy_all
      revoked = current_identity.sessions.active.to_a
      revoked.each(&:revoke!)

      # Including the realm-wide browser session. Leaving it would make this
      # endpoint a lie: every application token would be dead, and the next
      # /authorize would silently mint new ones.
      revoke_sso_sessions!(current_identity)

      render json: { revoked: revoked.length }
    end

    # Previously `head :no_content` on an UNauthenticated controller, so it
    # answered 204 for a valid token, no token and a garbage token alike, and
    # the token kept working afterwards. It now revokes the session the
    # presented token was minted from.
    #
    # Still 204 when there is no session to revoke -- a token minted before
    # sessions existed, or one without a sid. Logging out is idempotent, and the
    # client drops its copy either way.
    def sign_out
      # EVERY session for this identity, not only the one that asked.
      #
      # An earlier version revoked the calling application's session and the
      # realm session, and said the other applications kept their own refresh
      # tokens but had lost "the ability to reach a new one without a password".
      # That was wrong, and the comment is the reason to spell it out: refreshing
      # checks the session row and the grant and never looks at the realm
      # session, so another application went on minting access tokens from its
      # own refresh token for up to its 30 days. Signing out of one application
      # left the others signed in, not for fifteen minutes, but for a month.
      #
      # It was also incoherent. The realm session is revoked for the whole
      # identity, on every device, while each application's own session survived
      # -- global in one direction and local in the other, which is not a
      # position anybody chose.
      #
      # So sign-out means signed out. The cost is that it is coarse: signing out
      # on one device signs out on all of them. That is the same coarseness
      # revoke_sso_sessions! already had, now applied consistently.
      #
      # Residual: an access token already issued stays valid until it expires, up
      # to ACCESS_TOKEN_TTL. Closing that needs the application to be told
      # rather than to notice -- back-channel logout -- which is its own piece of
      # work.
      revoked = current_identity.sessions.active.to_a
      revoked.each(&:revoke!)

      # The realm session too. If it survived, the application would bounce
      # through /authorize and sign the person straight back in, and signing out
      # would mean nothing.
      revoke_sso_sessions!(current_identity)

      render json: {
        post_logout_redirect_uri: post_logout_redirect,
        sessions_revoked: revoked.length
      }
    end

    private

    # Where the application should send somebody now.
    #
    # Answered here rather than left to the app so the destination is registered
    # on the client record, which is what makes an override safe to accept at
    # all: a requested URI is honoured only if registered, and an unregistered
    # one falls back to the default. See Client#post_logout_redirect_for.
    #
    # The refusal is logged rather than returned. The session is already revoked
    # by this point, so failing the response would leave somebody signed out
    # looking at an error -- but a misconfigured application should not be
    # silently humoured either.
    def post_logout_redirect
      requested = params[:post_logout_redirect_uri].presence

      if Current.client.post_logout_redirect_refused?(requested)
        Rails.logger.info(
          "post_logout_redirect_uri not registered for #{Current.client.client_id}, using the default"
        )
      end

      Current.client.post_logout_redirect_for(requested)
    end

    # Field for field what corebyscott's SessionsList already renders, so the
    # component works against this server unchanged.
    def session_json(session)
      parsed = UserAgentParser.parse(session.user_agent)

      {
        id: session.id,
        device_name: session.device_name,
        browser: parsed[:browser],
        browser_version: parsed[:browser_version],
        os: parsed[:os],
        device_type: parsed[:device_type],
        is_mobile: parsed[:is_mobile],
        ip_address: UserAgentParser.mask_ip(session.ip_address),
        created_at: session.created_at,
        last_used_at: session.last_used_at,
        expires_at: session.expires_at,

        # Which row is "this device", so the UI can label it and avoid offering
        # to revoke the session being used to read the list.
        current: current_session.present? && session.id == current_session.id,

        # Which application this session belongs to. Core's list has no such
        # column because an app could only ever show its own; here the list spans
        # apps, so without this the rows are indistinguishable.
        client_id: session.client.client_id
      }
    end
  end
end
