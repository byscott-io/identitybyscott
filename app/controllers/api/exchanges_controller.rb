# frozen_string_literal: true

module Api
  # Exchanges an application's own access token for one usable at another
  # application in the same realm, on behalf of the same identity.
  #
  # Why this exists at all
  # ---------------------
  # Access tokens are audience-scoped, deliberately: a token minted for one
  # application must not authenticate at another, so one leaked token is not a
  # key to the whole realm. That containment is worth keeping, but it also means
  # an application's backend cannot call another's API for the person using it.
  #
  # This endpoint keeps the containment and adds the capability: each token
  # still names exactly ONE audience, and getting a second one requires asking
  # here, where the identity's grant for the target is checked. The alternative
  # -- listing every granted application in one token's `aud` -- would be
  # simpler and would make a single leaked token work everywhere that person is
  # granted, which is the property this design exists to avoid.
  #
  # Shaped after RFC 8693 rather than wire-compatible with it
  # ---------------------------------------------------------
  # The subject token arrives in the Authorization header, as it does on every
  # other authenticated endpoint here, instead of RFC 8693's `subject_token`
  # parameter. Consistency with the rest of this API is worth more than
  # interoperability with a generic client: the only callers are applications
  # that already hold a token and already send it this way. The `act` claim and
  # the model are the RFC's; the transport is this server's.
  class ExchangesController < AuthenticatedController
    rate_limit to: 60, within: 1.minute, by: -> { token_rate_limit_key },
               with: -> { rate_limited!(retry_after: 1.minute) }

    def create
      # to_s, as every other finder here does. A nested parameter
      # (audience[x]=y) would otherwise hand find_by an
      # ActionController::Parameters rather than a string, turning a malformed
      # request into a 500 instead of the uniform refusal below -- and a
      # different response shape is itself a signal.
      target = Client.active.find_by(client_id: params[:audience].to_s)

      # One answer for unknown, inactive, another realm's, and not granted.
      #
      # Telling them apart would let any application with a token enumerate
      # which applications exist, which realm they are in, and which of them a
      # person has access to -- a map of someone's reach across the whole suite,
      # readable by any one application they use.
      return render_refused unless exchangeable?(target)

      issuer = TokenIssuer.new(
        identity: current_identity,
        client: target,
        actor: Current.client
      )

      render json: {
        access_token: issuer.access_token,
        token_type: "Bearer",
        expires_in: TokenIssuer::ACCESS_TOKEN_TTL.to_i,
        audience: target.client_id
      }
    end

    private

    def exchangeable?(target)
      return false if target.nil?

      # Never across realms, for the same reason a grant cannot cross one: an
      # application belongs to exactly one realm, and an identity to exactly
      # one, so a token crossing that line would defeat the isolation every
      # other check preserves. Grant already enforces this, but a grant could
      # in principle predate a client being moved, so it is checked here too.
      return false unless target.realm_id == current_identity.realm_id

      # Exchanging for yourself is not a refusal, it is a mistake -- but
      # answering normally would hand back a token with an `act` claim naming
      # the caller as acting for itself, which is meaningless and would read
      # oddly in an audit. Refuse plainly.
      return false if target.id == Current.client.id

      return false unless Grant.permits?(identity: current_identity, client: target)

      # An already-exchanged token may not be exchanged again.
      #
      # Not an authorization concern -- every hop is gated by a grant, so
      # chaining could never exceed what the identity may reach. It is a
      # REVOCATION concern. An exchanged token is minted without a session and
      # so carries no sid, and the live-session check below treats a missing sid
      # as "nothing to check". So a second hop would skip it silently and
      # reopen exactly the offline-verification window this endpoint exists to
      # close -- while the README promises revocation is caught immediately
      # here, unlike everywhere else.
      #
      # Chaining also loses the original actor: act would name the middle
      # application and the first one would vanish from the record.
      #
      # Refused rather than threaded through, because nothing asks for it yet.
      # Supporting it later means carrying the originating session into the
      # exchanged token, deliberately, not relying on this gap.
      return false if @payload&.dig("act").present?

      session_still_live?
    end

    # Revocation is normally eventual -- applications verify offline, so a
    # revoked session's token keeps working until it expires. This path is
    # different: it is an online call to this server, so the session CAN be
    # checked, and refusing here means revoking a session stops it being
    # amplified into tokens for other applications. A revoked session's
    # remaining minutes should not buy a wider reach than it already had.
    #
    # A token with no sid is not refused: one minted outside a session carries
    # none, and nothing in this codebase may assume one is present.
    def session_still_live?
      return true if @payload&.dig("sid").blank?

      # Reuses the inherited lookup rather than running a parallel query, so a
      # sid naming someone else's session resolves to nothing here too.
      current_session&.active? || false
    end

    # 403 rather than 404: the caller is authenticated and the request is
    # well-formed, so this is an authorization answer. Deliberately uniform --
    # see the comment at the call site for why the reasons are not separated.
    def render_refused
      render json: {
        error: "Exchange refused",
        detail: "This identity cannot be exchanged into that application."
      }, status: :forbidden
    end
  end
end
