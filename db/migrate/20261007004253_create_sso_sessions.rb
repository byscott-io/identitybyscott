# frozen_string_literal: true

# The realm-wide browser session single sign-on needs.
#
# Separate from `sessions` rather than a flag on it, because the two answer
# different questions and have different blast radii. A `sessions` row is one
# application's refresh token: scoped to a client, redeemable only there. This
# row is a browser's claim to be an identity across the WHOLE realm, so it is
# the credential with the widest reach this server issues -- and that is exactly
# why it gets its own table, its own shorter lifetime, and its own revocation.
#
# Only a digest of the cookie value is stored, like refresh tokens: a database
# dump must not yield usable credentials.
class CreateSsoSessions < ActiveRecord::Migration[8.1]
  def change
    create_table :sso_sessions, id: :uuid do |t|
      t.references :identity, type: :uuid, null: false, foreign_key: true

      # No realm column on purpose. The realm is derived from the identity, so
      # there is no second copy to drift out of step with it -- and the realm is
      # the boundary /authorize will check, which must not be able to disagree
      # with the identity it belongs to.

      t.string :token_digest, null: false
      t.string :user_agent
      t.string :ip_address
      t.datetime :last_used_at
      t.datetime :expires_at, null: false
      t.datetime :revoked_at

      t.timestamps
    end

    add_index :sso_sessions, :token_digest, unique: true
    add_index :sso_sessions, [ :identity_id, :revoked_at ]
  end
end
