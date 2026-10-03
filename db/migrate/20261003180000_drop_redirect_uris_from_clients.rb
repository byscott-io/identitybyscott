# frozen_string_literal: true

class DropRedirectUrisFromClients < ActiveRecord::Migration[8.1]
  def change
    # Left over from a hosted redirect login flow that is out of scope: this
    # server is API-only and each application renders its own forms, so nothing
    # ever read this column.
    #
    # Removed rather than kept "just in case". Dead security-shaped code in a
    # public authentication server is worse than absent code -- a future reader
    # has to work out whether redirect validation is active, and an unused
    # allowlist invites being wired up carelessly. Social login genuinely needs
    # a redirect, and reintroducing this is one migration when that arrives.
    remove_column :clients, :redirect_uris, :text, default: "", null: false
  end
end
