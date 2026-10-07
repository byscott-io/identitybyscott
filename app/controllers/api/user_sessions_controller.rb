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

      # Every realm session, on every browser -- which is what "everywhere"
      # means and the one case where the wide version is correct. Leaving them
      # would make this endpoint a lie: every application token would be dead
      # and the next /authorize would silently mint new ones.
      revoke_all_sso_sessions!(current_identity)

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
      current_session&.revoke!

      # THIS browser's realm session goes too. If it survived, the application
      # would bounce through /authorize and sign the person straight back in,
      # and signing out would mean nothing.
      #
      # Identified through the session being revoked rather than by the cookie,
      # which never reaches /api. Other browsers are untouched, and the other
      # applications on this one keep their refresh tokens -- what is gone is
      # reaching a NEW application without a password.
      revoke_sso_session!(current_session)

      head :no_content
    end

    private

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
