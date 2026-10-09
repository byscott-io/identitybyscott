# frozen_string_literal: true

# Where an application wants somebody sent after signing out.
#
# A list rather than a single value, and validated the same way redirect_uris
# is, because the sign-out call may name one: an unvalidated redirect on a
# sign-out endpoint is an open redirect, and a sign-out link is exactly the kind
# of thing that gets mailed around.
#
# The first entry is the default when the caller names nothing.
class AddPostLogoutRedirectUrisToClients < ActiveRecord::Migration[8.0]
  def change
    add_column :clients, :post_logout_redirect_uris, :text
  end
end
