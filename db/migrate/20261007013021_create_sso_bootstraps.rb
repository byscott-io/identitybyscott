# frozen_string_literal: true

# The one-use token that lets a top-level navigation establish the SSO cookie.
#
# This exists because of where this server sits relative to the applications it
# serves. They are on their own registrable domains, so this server is a THIRD
# PARTY to every one of them, and a cookie set in a response to a cross-site
# request from an application is either refused outright (Safari's tracking
# prevention) or filed under that application's own top-level site (Firefox's
# partitioning) -- where it is invisible to every other application in the
# realm, which is the only thing single sign-on is for.
#
# A top-level navigation to this server does not have that problem: this server
# is then the top-level site, the cookie is first-party, and every application
# in the realm sees it on a later navigation. So the cookie has to be set during
# a navigation, and this token is what makes that navigation safe to act on.
#
# Shaped like an authorization code, for the same reason: it travels in a URL.
class CreateSsoBootstraps < ActiveRecord::Migration[8.1]
  def change
    create_table :sso_bootstraps, id: :uuid do |t|
      t.references :identity, type: :uuid, null: false, foreign_key: true

      # issuing_client_id, not client_id, following Grant and AuthorizationCode:
      # a uuid column called client_id beside Client's public string client_id is
      # the confusion those classes already warn about.
      #
      # Kept so return_to can be checked against the registered URIs of the
      # application that actually signed this person in, rather than any
      # application that happens to hold the token.
      t.uuid :issuing_client_id, null: false

      t.string :token_digest, null: false
      t.datetime :expires_at, null: false
      t.datetime :consumed_at

      t.timestamps
    end

    add_index :sso_bootstraps, :token_digest, unique: true
    add_index :sso_bootstraps, :issuing_client_id
    add_foreign_key :sso_bootstraps, :clients, column: :issuing_client_id
  end
end
