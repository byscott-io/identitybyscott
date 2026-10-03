# frozen_string_literal: true

class AddAppUrlsToClients < ActiveRecord::Migration[8.1]
  def change
    # Where this app lives. Required, because every email this server sends has
    # to land the person back in the app they started from -- identity has no
    # forms of its own, so a link pointing here would be a dead end.
    add_column :clients, :app_base_url, :string

    # Per-app overrides for the paths those links use, when an app does not use
    # the conventional ones. {token} is substituted.
    add_column :clients, :url_templates, :jsonb, null: false, default: {}
  end
end
