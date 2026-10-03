# frozen_string_literal: true

# This server's own mail, replacing Devise's.
#
# Devise's mailer cannot be used here at all: its views build URLs from
# devise_for routes, and this app deliberately has none. More importantly its
# links would point HERE, which is a dead end -- identity has no forms, so every
# link has to land the person back in the app they started from.
class IdentityMailer < ApplicationMailer
  def confirmation_instructions(identity, token, _opts = {})
    @identity = identity
    @url = app_url_for(identity, :confirmation, token)

    mail to: identity.email, subject: "Confirm your email address"
  end

  def reset_password_instructions(identity, token, _opts = {})
    @identity = identity
    @url = app_url_for(identity, :password_reset, token)

    mail to: identity.email, subject: "Reset your password"
  end

  def unlock_instructions(identity, token, _opts = {})
    @identity = identity
    @url = app_url_for(identity, :unlock, token)

    mail to: identity.email, subject: "Unlock your account"
  end

  private

  CONVENTIONAL_PATHS = {
    confirmation: "/confirm-email?token={token}",
    password_reset: "/reset-password?token={token}",
    unlock: "/unlock?token={token}"
  }.freeze

  # The current request's client, falling back to the one this identity signed
  # up through -- so a reset raised from a console or a job still produces a
  # usable link.
  def app_url_for(identity, purpose, token)
    client = Current.client || identity.signup_client
    raise ArgumentError, "No client to build a #{purpose} URL from" if client.nil?

    base = client.app_base_url.to_s.chomp("/")
    raise ArgumentError, "Client #{client.client_id} has no app_base_url" if base.empty?

    template = client.url_templates[purpose.to_s].presence || CONVENTIONAL_PATHS.fetch(purpose)
    "#{base}#{template.sub('{token}', token.to_s)}"
  end
end
