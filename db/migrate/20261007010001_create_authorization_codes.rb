# frozen_string_literal: true

# The short-lived, single-use code /authorize hands back through a redirect.
#
# A code travels in a URL -- through the address bar, the browser's history and
# any Referer the application leaks -- so it is the credential with the most
# exposure of anything here. Everything about this table follows from that:
# only a digest is stored, it lives for a minute, it is consumed on first use,
# and it is bound to the client, the redirect_uri and the PKCE challenge it was
# requested with, so possession of the code alone is not enough to redeem it.
class CreateAuthorizationCodes < ActiveRecord::Migration[8.1]
  def change
    create_table :authorization_codes, id: :uuid do |t|
      t.references :identity, type: :uuid, null: false, foreign_key: true

      # Bound to the browser session it was minted from, so signing out
      # invalidates codes already in flight rather than leaving a redeemable
      # one behind.
      t.references :sso_session, type: :uuid, null: false, foreign_key: true

      # authorized_client_id, not client_id, following Grant: a uuid column
      # called client_id sitting beside Client's public string client_id is the
      # confusion that class already warns about.
      t.uuid :authorized_client_id, null: false

      t.string :code_digest, null: false

      # The code is bound to the exact URI it was issued for. The exchange has
      # to present the same one, so a code intercepted at one registered
      # callback cannot be redeemed as though it arrived at another.
      t.string :redirect_uri, null: false

      # PKCE, required rather than optional -- see AuthorizationCode. S256 only;
      # `plain` sends the verifier in the clear and defeats the point.
      t.string :code_challenge, null: false
      t.string :code_challenge_method, null: false, default: "S256"

      t.string :nonce
      t.string :scope

      t.datetime :expires_at, null: false
      t.datetime :consumed_at

      t.timestamps
    end

    add_index :authorization_codes, :code_digest, unique: true
    add_index :authorization_codes, :authorized_client_id
    add_foreign_key :authorization_codes, :clients, column: :authorized_client_id
  end
end
