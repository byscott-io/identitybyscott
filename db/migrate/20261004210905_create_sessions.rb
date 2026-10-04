# A session is one row per (identity, application, device), created when
# credentials are accepted and holding the refresh token that mints access
# tokens afterwards.
#
# Why this lives here rather than in each application: today every app carries
# its own jwt_tokens table, so "list my sessions" means "list my sessions in the
# app I happen to be looking at", and signing out of one says nothing about the
# others. One row per session at this server makes the list genuinely complete
# and makes "log out everywhere" a single call.
#
# NOT one session per device per realm. That was this milestone's original claim
# and it is not achievable: with applications rendering their own forms there is
# no top-level navigation here, so no browser cookie is ever set at this server,
# and every app sits on its own apex domain where a third-party cookie is
# blocked. So it is one session per app per device -- which is what the apps
# already do, and still delivers the central list and the central revocation.
class CreateSessions < ActiveRecord::Migration[8.1]
  def change
    create_table :sessions, id: :uuid do |t|
      t.references :identity, type: :uuid, null: false, foreign_key: true
      # Which application this session belongs to. An access token is audience
      # scoped, so a session has to be too: a session for one app must not mint
      # a token for another.
      t.references :client, type: :uuid, null: false, foreign_key: true

      # The DIGEST, never the token. A refresh token is a bearer credential with
      # a long life, so a readable copy in the database would be worth more to an
      # attacker than a password hash -- it needs no cracking.
      t.string :refresh_token_digest, null: false

      t.string :device_name
      t.string :user_agent
      t.string :ip_address

      t.datetime :last_used_at
      t.datetime :expires_at, null: false
      t.datetime :revoked_at

      t.timestamps
    end

    add_index :sessions, :refresh_token_digest, unique: true

    # The sessions list, and every revocation sweep, reads by identity and skips
    # the revoked rows.
    add_index :sessions, [ :identity_id, :revoked_at ]

    # No realm_id column. The original ticket asked for one, null: false, to stop
    # a session in one realm satisfying an /authorize request in another. There
    # is no /authorize and no browser session, so that failure mode does not
    # exist -- and an identity belongs to exactly one realm, so realm is already
    # reachable without a denormalised column that could drift out of agreement
    # with it.
  end
end
