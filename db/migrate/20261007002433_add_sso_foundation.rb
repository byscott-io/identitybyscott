# frozen_string_literal: true

# The two columns single sign-on needs before any of it is built.
#
# Nothing reads them yet. They land first, default-off and empty, so the
# endpoint that will enforce them is a separate, smaller change -- and so a
# realm can be prepared without anything changing for it.
class AddSsoFoundation < ActiveRecord::Migration[8.1]
  def change
    # Per-realm rollout control. Default FALSE everywhere, including realms that
    # already exist: single sign-on is opt-in per suite, not a fleet-wide switch
    # thrown once. A realm with one application gains nothing from it, and the
    # cost -- a browser session at the identity server -- is only worth paying
    # where people actually move between applications.
    add_column :realms, :sso_enabled, :boolean, null: false, default: false

    # Where an authorization code may be sent back to, matched EXACTLY.
    #
    # The single most important field in the whole design: a code is a
    # credential, and a redirect_uri that is merely "close enough" is how codes
    # get delivered to someone else. No wildcards, no prefix matching, no
    # scheme-relative forms -- exact string equality against this list.
    #
    # Empty by default, which means an application cannot complete a redirect
    # flow until someone registers one deliberately.
    add_column :clients, :redirect_uris, :text, null: false, default: ""
  end
end
