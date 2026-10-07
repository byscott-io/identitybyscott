# frozen_string_literal: true

module Api
  # Resolves the calling application, and with it the realm, before anything
  # else happens.
  #
  # The client_id is a PATH segment, not a body parameter or a custom header,
  # and that is forced by CORS rather than chosen for looks. A preflight request
  # carries only the Origin, the method and the NAMES of requested headers --
  # never a body, never a header value. So the only part of a credential request
  # a preflight can see is its URL, and per-client origin checking would be
  # impossible otherwise.
  class BaseController < ApplicationController
    before_action :resolve_client!

    # BEFORE the origin check and before any rate limiter, not after the
    # action.
    #
    # These were an after_action, and Rails does not run after_action
    # callbacks when a before_action HALTS the chain -- which is exactly what
    # `rate_limit` does when it renders 429. So every rate-limited response
    # went out with no Access-Control-Allow-Origin, and a browser reported it
    # as a CORS failure rather than as the rate limit it was. The JSON body
    # added for precisely that complaint was never readable by the caller it
    # was added for.
    #
    # Here it covers every halt after the client is known: the rate limiters,
    # and anything added later that renders from a filter. An origin that is
    # NOT allowed still gets nothing, because this only ever echoes one
    # already on that client's allowlist.
    before_action :apply_cors_headers
    before_action :enforce_origin!

    private

    # The realm is never read from a parameter. If an application could send
    # realm=church, any application could claim any realm and the isolation the
    # whole design rests on would be decorative.
    def resolve_client!
      Current.client = Client.active.find_by(client_id: path_client_id)

      return if Current.client

      # 404 rather than 401: an unknown client_id is not a failed
      # authentication, and this response must not become a way to enumerate
      # which client ids exist.
      render json: { error: "Not found" }, status: :not_found
    end

    def realm
      Current.client.realm
    end

    # Every rate limiter answers with this rather than Rails' default, which
    # is a bare `head :too_many_requests` -- no body at all.
    #
    # An empty 429 is worse than an unhelpful one. Every other failure here
    # returns JSON, so a client parses the body unconditionally, gets a parse
    # error instead of a rate-limit error, and then reports something
    # misleading or crashes. That is how this was found.
    #
    # Retry-After is the WINDOW, not the time remaining. Rails' limiter does
    # not expose when the current window opened, so a precise value is not
    # available -- the window is the honest upper bound, and a client that
    # waits it out is always safe. Deliberately not guessed more finely: too
    # short a value sends a caller straight back into the limit.
    def rate_limited!(retry_after:)
      response.set_header("Retry-After", retry_after.to_i.to_s)

      render json: {
        error: "Too many requests",
        detail: "Try again in #{ActiveSupport::Duration.build(retry_after.to_i).inspect}."
      }, status: :too_many_requests
    end

    # From the PATH explicitly, not from params.
    #
    # params merges path, query string and body. Rails does give path segments
    # precedence, so params[:client_id] happens to be correct today -- verified
    # -- but resting a security property on an implicit merge order is fragile.
    # Reading the path directly means a body or query parameter can never name
    # a different client than the one whose Origin the preflight approved.
    def path_client_id
      request.path_parameters[:client_id]
    end

    # The browser-facing security boundary. A browser holds no secret, so a
    # browser-posted credential presents only the public client_id; what
    # constrains who may send one is this origin allowlist.
    #
    # It does NOT stop a server-side caller, and it does not stop a convincing
    # fake form on someone else's site -- the password reached them before this
    # server was involved. That exposure is inherent to applications owning
    # their own forms.
    def enforce_origin!
      origin = request.headers["Origin"]

      # No Origin at all means a non-browser caller (curl, a server). CORS has
      # nothing to say about those; they are constrained by credentials.
      return if origin.blank?
      return if Current.client.origin_allowed?(origin)

      render json: { error: "Origin not allowed" }, status: :forbidden
    end

    def apply_cors_headers
      origin = request.headers["Origin"]
      return if origin.blank? || Current.client.nil?
      return unless Current.client.origin_allowed?(origin)

      # Echo the specific origin rather than "*". A wildcard cannot carry
      # credentials and would also let any site read these responses.
      response.set_header("Access-Control-Allow-Origin", origin)
      response.set_header("Vary", [ response.get_header("Vary"), "Origin" ].compact_blank.join(", "))
    end
  end
end
