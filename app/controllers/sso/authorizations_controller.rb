# frozen_string_literal: true

module Sso
  # GET /sso/authorize -- the one endpoint that reads the single sign-on cookie.
  #
  # It answers one question: does this browser already hold a realm session that
  # entitles it to a code for this application? If yes it redirects back with an
  # authorization code; if no it redirects back with `login_required` and the
  # application shows its own sign-in form.
  #
  # IT NEVER PROMPTS, because there is nothing here to prompt with. This server
  # has no hosted login page and no HTML -- applications render every form -- so
  # "silent or not at all" is not a simplification of OIDC, it is the only
  # behaviour this design can honestly offer. `prompt_values_supported` says so.
  #
  # This is also the FIRST endpoint here reached with an ambient credential: the
  # cookie rides a top-level navigation, so a cross-site link can cause this
  # action to run. Its protection is the shape of the flow rather than a CSRF
  # token:
  #
  #   * the only state it changes is minting a code
  #   * that code can only be delivered to a redirect_uri the client registered
  #   * the application checks the `state` it sent on the way back
  #
  # So the worst a hostile link achieves is sending someone to an application
  # they are already entitled to use, signed in. That is an annoyance, not a
  # disclosure, and it is inherent to redirect-based single sign-on. Anything
  # beyond minting a code must NOT be added behind this cookie.
  class AuthorizationsController < ApplicationController
    include SsoCookie

    # The cookie is a bearer credential and this endpoint is a GET, so it is
    # cheap to hammer. Keyed on the address rather than the cookie: an attacker
    # probing has no cookie to key on.
    rate_limit to: 60, within: 1.minute, by: -> { request.remote_ip },
               with: -> { render json: { error: "Too many requests" }, status: :too_many_requests }

    RECOGNISED_PROMPTS = [ nil, "", "none", "login" ].freeze

    # The ordering below is the security property, not a style choice.
    #
    # Everything before `redirect_uri` is validated answers LOCALLY, with a
    # plain 400, because until the URI is known to be registered there is
    # nowhere safe to send anything. Redirecting an error to an unverified
    # redirect_uri is an open redirect, and an open redirect on an endpoint that
    # mints credentials is how codes end up at an attacker's server.
    #
    # Only after the client is resolved AND the URI matches that client's
    # registered list does this start answering by redirect.
    def show
      client = Client.active.find_by(client_id: requested["client_id"])
      return render_local_error("unknown client") if client.nil?

      @redirect_uri = requested["redirect_uri"].to_s
      unless client.redirect_uri_allowed?(@redirect_uri)
        # Not redirected, for the reason above, and answered IDENTICALLY to an
        # unknown client.
        #
        # The credential endpoints already refuse to let an unknown client_id be
        # distinguished, so that this server cannot be used to enumerate which
        # applications exist. The same answer for both keeps that true here: a
        # real client with a wrong URI and an invented client are the same
        # response, so neither question can be asked.
        return render_local_error("unregistered redirect_uri")
      end

      # From here, every answer goes back to a URI this client registered.
      @state = requested["state"].to_s

      return redirect_error("unsupported_response_type") unless requested["response_type"] == "code"

      # state and PKCE are REQUIRED here, though OIDC calls both optional.
      #
      # This server has exactly one client library and controls both ends, so
      # the interoperability those options exist for costs nothing to give up,
      # and each closes a real hole: without `state` the application cannot tell
      # its own callback from a forged one, and without PKCE a stolen code is
      # redeemable by whoever stole it.
      return redirect_error("invalid_request") if @state.blank?
      return redirect_error("invalid_request") if requested["code_challenge"].blank?

      unless requested["code_challenge_method"] == AuthorizationCode::CHALLENGE_METHOD
        # Includes the case of no method at all. OAuth defaults an absent method
        # to `plain`, which sends the verifier in the clear; defaulting to the
        # secure value instead would silently accept a client that believes it
        # is doing something weaker than it is.
        return redirect_error("invalid_request")
      end

      return redirect_error("invalid_request") unless RECOGNISED_PROMPTS.include?(requested["prompt"])

      # A realm that has not asked for single sign-on has no silent path, and
      # says so the same way an unauthenticated browser does. The application
      # falls back to its own form either way, so there is nothing to gain from
      # a distinct answer and a realm's configuration is not the caller's
      # business.
      return redirect_error("login_required") unless client.realm.sso?

      # prompt=login means "do not reuse the session", so the cookie is not even
      # looked at and this goes straight to the form.
      return offer_login(client) if requested["prompt"] == "login"

      session = sso_session_from_cookie
      return offer_login(client) if session.nil?

      # The cross-realm check, and the reason SsoSession.authenticate takes no
      # client: the cookie proves a browser is someone in SOME realm and says
      # nothing about whether that realm is this client's.
      #
      # Being precise about what this does and does not carry. It is NOT the
      # only thing stopping a code being issued across realms -- the grant check
      # below would also refuse, because Grant validates that a client is in the
      # identity's own realm, so a cross-realm grant cannot exist to be found.
      #
      # What this adds is the ANSWER. Without it the refusal would be
      # access_denied, which tells the application that this browser holds a
      # live session for an identity it cannot see, in a realm it cannot see --
      # exactly the cross-realm fact realms exist to keep separate. With it the
      # answer is identical to not being signed in at all.
      #
      # It is also the check that would still hold if grants were ever relaxed,
      # which is worth keeping for a property this load-bearing.
      return offer_login(client) unless session.identity.realm_id == client.realm_id

      # Authentication is not authorisation. Being someone in the realm does not
      # entitle a browser to a code for every application in it.
      #
      # `access_denied` rather than `login_required`, because this is the one
      # failure a sign-in form cannot fix: signing in again grants nothing, and
      # answering login_required would send the application round a loop.
      unless Grant.permits?(identity: session.identity, client: client)
        return redirect_error("access_denied")
      end

      issue_code(client, session)
    end

    private

    # request.query_parameters, never `params`.
    #
    # The credential endpoints take client_id from request.path_parameters for a
    # CORS reason that does not apply here -- there is no preflight on a
    # top-level navigation, and discovery has to publish ONE
    # authorization_endpoint, which a per-client path could not be. So this
    # surface takes it from the query string.
    #
    # What does carry across is the principle behind that rule: a security
    # property must not rest on `params`' implicit merge of path, query and
    # body. Naming the source explicitly means this keeps reading the query
    # string even if a route or a verb changes underneath it.
    def requested
      @requested ||= request.query_parameters
    end

    # Sends the browser to the hosted login page, carrying what this request
    # already validated as a signed statement rather than as parameters to be
    # validated again.
    #
    # prompt=none is the exception and gets login_required instead: that mode
    # exists precisely so an application can ask "is there a session?" without
    # a form appearing, and answering it with one would make silent
    # authentication impossible to attempt safely.
    #
    # A realm MISMATCH comes here too, and is indistinguishable from having no
    # session at all. A distinct answer would tell the application this browser
    # is signed in to a realm it cannot see.
    def offer_login(client)
      return redirect_error("login_required") if requested["prompt"] == "none"

      redirect_to sso_login_form_path(authorization: PendingAuthorization.encode(
        client_id: client.client_id,
        redirect_uri: @redirect_uri,
        state: @state,
        code_challenge: requested["code_challenge"],
        nonce: requested["nonce"],
        scope: requested["scope"]
      )), status: :see_other
    end

    def issue_code(client, session)
      _code, raw = AuthorizationCode.issue!(
        identity: session.identity,
        client: client,
        sso_session: session,
        redirect_uri: @redirect_uri,
        code_challenge: requested["code_challenge"].to_s,
        nonce: requested["nonce"],
        scope: requested["scope"]
      )

      session.touch_used!

      redirect_to_app(code: raw, state: @state)
    end

    # 400 with a body, not a redirect. Reached only before a redirect_uri is
    # trusted, so there is nowhere safe to redirect TO.
    #
    # The RESPONSE is uniform; the reason is logged. A developer wiring an
    # application up does need to know which of the two it was, but putting that
    # in the response is also what would let someone enumerate client ids, so it
    # goes to the log where an operator can read it and a caller cannot. Same
    # pattern as the JWKS endpoint, which logs a configuration error rather than
    # rendering it.
    def render_local_error(reason)
      Rails.logger.info(
        "[identity] /sso/authorize refused: #{reason} " \
        "(client_id=#{requested["client_id"].to_s.truncate(64)})"
      )

      render json: { error: "invalid_request" }, status: :bad_request
    end

    def redirect_error(code)
      # state is echoed when there is one. When state itself was the thing
      # missing there is nothing to echo, which is why it is not required here.
      redirect_to_app(error: code, state: @state.presence)
    end

    def redirect_to_app(**query)
      redirect_to AuthorizeRedirect.build(@redirect_uri, **query),
                  allow_other_host: true, status: :found
    end
  end
end
