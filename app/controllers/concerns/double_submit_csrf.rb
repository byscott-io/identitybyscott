# frozen_string_literal: true

# CSRF for the hosted login page, WITHOUT a Rails session.
#
# == Why not Rails' own
#
# `protect_from_forgery` keys the token to the session, so using it would mean
# adding a session store -- an ambient credential on every path here, which is
# exactly what the architecture spec bans and what the API-only rule warns
# about. The login page needs one cookie for one purpose, not a session.
#
# == Why a bare signed token is not enough
#
# The obvious shortcut is a signed, timestamped token in the form and no cookie.
# It does not work: an attacker can fetch the login page themselves, get a
# perfectly valid token, and put it in their own auto-submitting form. The token
# has to be bound to the BROWSER, which means something only that browser has.
#
# == What this does
#
# Double submit. A random value goes into an HttpOnly cookie and into a hidden
# field; the POST is refused unless they match. An attacker can neither read nor
# set our cookie in the victim's browser, so their form carries their value and
# the victim's cookie -- a mismatch.
#
# This is what stops LOGIN CSRF: without it, an attacker's page could submit
# their own credentials through the victim's browser, and the victim would be
# signed in as the attacker with everything they typed afterwards going to the
# attacker's account.
#
# SameSite=Strict, because the form POST is same-origin to this server. The
# cross-site navigation that brings somebody to the login page only needs the
# cookie to be STORED, which SameSite does not govern.
module DoubleSubmitCsrf
  extend ActiveSupport::Concern

  included do
    include ActionController::Cookies

    # The form needs it, and it is named distinctly rather than `csrf_token` so
    # it cannot be confused with Rails' own helper -- which is tied to a session
    # this server deliberately does not have.
    helper_method :login_csrf_token
  end

  COOKIE_NAME = "identity_csrf"
  FIELD_NAME = "authenticity_token"
  TOKEN_BYTES = 32

  private

  # Issued on the GET that renders a form, and reused when one is already set so
  # two tabs on the login page do not invalidate each other.
  def login_csrf_token
    @csrf_token ||= begin
      existing = cookies[COOKIE_NAME]
      token = existing.presence || SecureRandom.urlsafe_base64(TOKEN_BYTES)

      cookies[COOKIE_NAME] = {
        value: token,
        httponly: true,
        secure: !Rails.env.local?,
        same_site: :strict,
        path: "/sso"
      }

      token
    end
  end

  # Compared in fixed time, like any secret. The value is not guessable, but a
  # length-or-prefix difference is free to exploit when the attacker controls
  # the guess.
  def verify_csrf!
    submitted = params[FIELD_NAME].to_s
    expected = cookies[COOKIE_NAME].to_s

    return true if expected.present? && submitted.present? &&
                   ActiveSupport::SecurityUtils.secure_compare(submitted, expected)

    # Deliberately not a helpful error. A missing cookie and a wrong token are
    # the same answer, and the honest cause -- somebody submitted a form this
    # browser was not given -- is not something to explain to whoever did it.
    Rails.logger.info("[identity] login POST refused: csrf")
    false
  end
end
