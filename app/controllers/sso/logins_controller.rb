# frozen_string_literal: true

module Sso
  # The hosted login page: the only HTML this server renders outside mailers.
  #
  # == Why it exists at all
  #
  # Because every alternative leaves the password in an application's own origin,
  # and that is worse than it sounds. An XSS in any application would then steal
  # the CREDENTIAL, not a session -- and no amount of token binding helps, since
  # script on a registered origin can always do whatever the real page can.
  # An embedded form cannot fix it either: an iframe stops script READING the
  # field but not drawing a convincing fake over it.
  #
  # A top-level page on this server's own origin is the only shape that fixes
  # both, because it is the only one that gives somebody an address bar to check
  # who is asking.
  #
  # == And why it is safe to add HTML here
  #
  # The page carries NO JavaScript, so it ships `script-src 'none'`. That is what
  # makes this acceptable in the process holding the signing key and every
  # password hash: adding views would otherwise create an XSS surface where there
  # was none. Nothing here renders user-controlled markup, there is no script to
  # hijack, and the appearance tokens are rendered as CSS custom properties by
  # ThemeCss, which re-validates every one.
  #
  # == Flow
  #
  #   GET  /sso/authorize  -> no session, so AuthorizationsController renders
  #                           :new here with a signed PendingAuthorization
  #   POST /sso/login      -> credentials; on success the cookie is set and the
  #                           browser is redirected back with a code
  #   POST /sso/login/mfa  -> the second factor, carrying the same pending
  #                           authorization forward
  class LoginsController < ActionController::Base
    include DoubleSubmitCsrf
    include SsoCookie

    layout "sso"

    # Rails' own CSRF is deliberately not used: it keys the token to a session,
    # and a session store would put an ambient credential on every path in this
    # server. DoubleSubmitCsrf does the job with one cookie. See that concern.
    skip_forgery_protection

    before_action :apply_security_headers

    # The single door into a whole realm, so keyed on both the address and the
    # IP -- either alone is trivially sidestepped by rotating the other. Matches
    # the credential API's limits, since this is the same door.
    rate_limit to: 10, within: 1.minute, by: -> { request.remote_ip }, only: :create,
               with: -> { too_many_requests }
    rate_limit to: 5, within: 1.minute,
               by: -> { params[:email].to_s.downcase.strip }, only: :create,
               with: -> { too_many_requests }
    # Tighter for the second factor: six digits is a feasible brute force
    # unthrottled. Keyed on the challenge so one person cannot exhaust another's
    # budget.
    rate_limit to: 5, within: 1.minute, by: -> { params[:mfa_token].to_s[0, 64] }, only: :mfa,
               with: -> { too_many_requests }

    # Reached by a redirect from /sso/authorize, which has already validated the
    # whole request and signed it. A real URL rather than a render inside
    # /authorize, so the person can see and refresh the page they are typing a
    # password into.
    def new
      pending = PendingAuthorization.decode(params[:authorization])
      client = resolve_client!(pending)
      return if performed?

      render_login(pending: pending, client: client, status: :ok)
    rescue PendingAuthorization::Invalid
      render_expired
    end

    def create
      return render_login(error: :generic) unless verify_csrf!

      pending = PendingAuthorization.decode(params[:authorization])
      client = resolve_client!(pending)
      return if performed?

      result = CredentialCheck.call(
        realm: client.realm, client: client,
        email: params[:email], password: params[:password]
      )

      case result.outcome
      when :invalid then render_login(pending: pending, client: client, error: :invalid)
      when :locked then render_login(pending: pending, client: client, error: :locked)
      when :unconfirmed then render_login(pending: pending, client: client, error: :unconfirmed)
      when :not_granted then render_login(pending: pending, client: client, error: :not_granted)
      when :mfa_required
        render_mfa(pending: pending, client: client,
                   mfa_token: MfaChallenge.issue(identity: result.identity, client: client))
      when :ok then complete(result.identity, client, pending)
      end
    rescue PendingAuthorization::Invalid
      render_expired
    end

    def mfa
      return render_login(error: :generic) unless verify_csrf!

      pending = PendingAuthorization.decode(params[:authorization])
      client = resolve_client!(pending)
      return if performed?

      identity = MfaChallenge.identity_for(params[:mfa_token], client: client, realm: client.realm)

      unless accept_code?(identity, params[:code])
        CredentialCheck.register_failure(identity)
        return render_mfa(pending: pending, client: client,
                          mfa_token: params[:mfa_token], error: :invalid_code)
      end

      identity.reset_failed_attempts! if identity.failed_attempts.positive?

      # Re-checked here as well as before the challenge: reaching this point
      # ungranted means the grant was revoked mid-flow. Rare, and the
      # alternative is a session issued by a path that never checked.
      unless Grant.permits?(identity: identity, client: client)
        return render_login(pending: pending, client: client, error: :not_granted)
      end

      complete(identity, client, pending)
    rescue PendingAuthorization::Invalid, MfaChallenge::InvalidChallenge
      render_expired
    end

    private

    # Everything the authorize request already validated, used as given. It was
    # signed by this server precisely so it does not have to be re-derived from
    # user input here -- above all the redirect_uri.
    def complete(identity, client, pending)
      # THE point of the hosted page. The cookie is set in reply to a credential
      # submission from THIS browser, so it is first-party by construction and
      # bound to the browser that proved the password -- there is no token to
      # transplant into somebody else's, which is what made every other shape of
      # this vulnerable to session fixation.
      #
      # Through SsoCookie rather than written here, so the cookie's attributes
      # are stated once. An architecture spec enforces that, and caught this
      # when it was written inline.
      sso_session = issue_sso_cookie!(identity)

      _code, raw = AuthorizationCode.issue!(
        identity: identity,
        client: client,
        sso_session: sso_session,
        redirect_uri: pending[:redirect_uri],
        code_challenge: pending[:code_challenge],
        nonce: pending[:nonce],
        scope: pending[:scope]
      )

      redirect_to(
        AuthorizeRedirect.build(pending[:redirect_uri], code: raw, state: pending[:state]),
        allow_other_host: true, status: :see_other
      )
    end

    def resolve_client!(pending)
      client = Client.active.find_by(client_id: pending[:client_id])
      render_expired if client.nil?

      client
    end

    def render_login(pending: nil, client: nil, error: nil, status: :unprocessable_content)
      @pending = pending
      # Re-signed rather than echoed back from the request, so what the form
      # carries forward is always this server's own statement.
      @pending_token = pending && PendingAuthorization.encode(**pending)
      @client = client
      @error = error
      @theme = client ? Theme.resolve(client) : Theme::DEFAULTS
      @logo_owner = client && Theme.resolve_logo(client)

      render :new, status: status
    end

    def render_mfa(pending:, client:, mfa_token:, error: nil)
      @pending = pending
      @pending_token = PendingAuthorization.encode(**pending)
      @client = client
      @mfa_token = mfa_token
      @error = error
      @theme = Theme.resolve(client)
      @logo_owner = Theme.resolve_logo(client)

      render :mfa, status: error ? :unprocessable_content : :ok
    end

    # No client, so no branding and nowhere to send anybody. A dead end on
    # purpose: the application starts the flow again, and this page must not
    # offer a link somewhere, since the only URL it could offer would come from
    # the thing that just failed to verify.
    def render_expired
      @theme = Theme::DEFAULTS
      render :expired, status: :unprocessable_content
    end

    def too_many_requests
      @theme = Theme::DEFAULTS
      render :throttled, status: :too_many_requests
    end

    def accept_code?(identity, code)
      return false if code.blank?
      return true if identity.verify_totp(code)

      identity.consume_backup_code!(code)
    end

    # Every one of these matters on a page that takes a password.
    def apply_security_headers
      response.set_header("Content-Security-Policy", content_security_policy)
      response.set_header("X-Content-Type-Options", "nosniff")
      # So the URL -- which carries state and the PKCE challenge -- is not
      # handed to the application in a Referer.
      response.set_header("Referrer-Policy", "no-referrer")
      response.set_header("Cache-Control", "no-store")
    end

    def content_security_policy
      [
        # Nothing loads by default, and script loads at all.
        "default-src 'none'",
        "script-src 'none'",
        # The one inline <style> block, by nonce rather than 'unsafe-inline', so
        # a hypothetical injection could not add a second one.
        "style-src 'nonce-#{style_nonce}'",
        # data: for an inline logo; 'self' for one served from here.
        "img-src 'self' data:",
        # The form may post to this server and nowhere else.
        "form-action 'self'",
        # Never embedded -- an embedded login page cannot show whose it is.
        "frame-ancestors 'none'",
        "base-uri 'none'"
      ].join("; ")
    end

    def style_nonce
      @style_nonce ||= SecureRandom.base64(16)
    end
    helper_method :style_nonce
  end
end
