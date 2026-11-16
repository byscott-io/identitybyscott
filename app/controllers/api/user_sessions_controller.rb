# frozen_string_literal: true

module Api
  # Listing and revoking an identity's own sessions, and signing out.
  #
  # The point of holding these centrally: before this, each application kept its
  # own jwt_tokens table, so "list my sessions" meant "list my sessions in the
  # app I am looking at" and signing out of one said nothing about the others.
  # Here every session for the identity is one list. Signing out ends this
  # device; ending another device, or every device, is a separate choice.
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

    # Revokes one DEVICE: every application session minted in that browser,
    # plus the browser session itself.
    #
    # This fills the gap between the two endpoints either side of it. destroy
    # ends one application on one device, leaving the others on that same
    # device signed in -- not what anyone means by "sign this laptop out".
    # destroy_all ends everything everywhere, which is more than they meant.
    # Neither could express "this device".
    #
    # Takes a device id as the list reports it: a browser session id, or an
    # ungrouped session own id. Both are accepted so a client can pass back
    # whatever it was given without knowing which kind it holds.
    def destroy_device
      requested = params[:id].to_s

      # Scoped to this identity rows, so another identity id is a 404 rather than
      # a revocation -- the same rule as destroy.
      scope = current_identity.sessions.active
      grouped_ids = scope.where(sso_session_id: requested).or(scope.where(id: requested)).pluck(:id)
      sso_session = current_identity.sso_sessions.active.find_by(id: requested)

      if grouped_ids.empty? && sso_session.nil?
        return render json: { error: "Not found" }, status: :not_found
      end

      revoke_device!(grouped_ids, sso_session)

      render json: { revoked: grouped_ids.size }
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
      # THIS DEVICE ONLY: the browser session the presented token was minted
      # under, and every application session it authorised -- so every
      # application on this device is signed out, and nothing else is.
      #
      # Another device keeps its own sessions. Ending those is the person's
      # choice, made in an application's sessions list (destroy_device, or
      # destroy_all for every device), never a side effect of signing out here.
      #
      # This replaces a sign-out that revoked EVERY session for the identity,
      # on every device. That was done because signing out of one application
      # used to leave the others, on the same device, signed in for up to 30
      # days: refreshing checks the session row and the grant and never the
      # realm session. Revoking the device's application sessions explicitly,
      # as below, closes that without reaching other devices.
      #
      # The device is found from the token, not the cookie: sign-out arrives as
      # an XHR to /api, which the realm cookie's path keeps it away from. A
      # session minted without a browser session (single sign-on off, or a
      # client that holds no cookie) is a device of one, and only it is revoked.
      #
      # Residual: an access token already issued stays valid until it expires,
      # up to ACCESS_TOKEN_TTL. Closing that needs back-channel logout.
      revoked = sign_out_this_device!

      render json: {
        post_logout_redirect_uri: post_logout_redirect,
        sessions_revoked: revoked
      }
    end

    private

    # The device the presented token belongs to, revoked; returns how many
    # application sessions that ended. A token with no sid names no session,
    # so nothing is revoked -- the client drops its copy either way.
    def sign_out_this_device!
      session = current_session
      # This browser's cookie goes either way: it IS this device, and leaving
      # it would let /authorize sign the person straight back in.
      clear_sso_cookie!(current_identity.realm)
      return 0 if session.nil? || session.revoked?

      group = session.device_group_id
      scope = current_identity.sessions.active
      ids = scope.where(sso_session_id: group).or(scope.where(id: group)).pluck(:id)
      revoke_device!(ids, current_identity.sso_sessions.active.find_by(id: session.sso_session_id))
      ids.size
    end

    # Ids are captured by the caller BEFORE anything is revoked, because the
    # scope is `active` and would return fewer rows once the cascade below has
    # run -- which would make the reported count depend on the order of these
    # two statements.
    #
    # The browser session first: its revoke! cascades to the application
    # sessions it authorised. The sweep that follows is re-read from the
    # database rather than from objects loaded earlier, so a row the cascade
    # already revoked is simply no longer `active` and is not written twice.
    # Writing it twice would overwrite the timestamp the cascade recorded.
    def revoke_device!(session_ids, sso_session)
      sso_session&.revoke!
      current_identity.sessions.active.where(id: session_ids).find_each(&:revoke!)
    end

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
        client_id: session.client.client_id,

        # Which DEVICE this session belongs to, so a client can group the rows it
        # is given. Without it, someone using three applications in one browser
        # sees three entries and nothing saying they are one device.
        #
        # Additive: the list stays a flat array, so a client that ignores this
        # behaves exactly as before. Grouping is a presentation choice, and the
        # revoke-a-device endpoint does not depend on the client making it.
        #
        # Falls back to the session own id where there is no browser session, so
        # an ungrouped row is a device of one rather than sharing a null group
        # with every other ungrouped row.
        device_id: session.device_group_id
      }
    end
  end
end
