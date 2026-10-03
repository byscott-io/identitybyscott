# frozen_string_literal: true

class CreateClients < ActiveRecord::Migration[8.1]
  def change
    # A registered application. This record is what makes realm isolation real:
    # the realm is resolved from the client_id a request presents, and is NEVER
    # accepted as a request parameter. If an app could send realm=church, any
    # app could claim any realm.
    create_table :clients, id: :uuid do |t|
      t.references :realm, null: false, foreign_key: true, type: :uuid

      t.string :name, null: false
      t.string :client_id, null: false

      # Confidential clients only. A browser cannot hold a secret, so a
      # browser-posted credential presents client_id alone -- public and
      # therefore spoofable -- and is constrained by the Origin allowlist below
      # instead. The secret is for server-to-server calls (token refresh,
      # introspection) and must never reach a JS bundle.
      t.string :client_secret_digest

      # The browser-facing security boundary. Adding an origin admits a new site
      # to this realm's credential endpoints, so this is a security control
      # rather than configuration trivia.
      t.text :allowed_origins, null: false, default: ""

      # For the optional hosted redirect flow. Exact matches only.
      t.text :redirect_uris, null: false, default: ""

      t.boolean :active, null: false, default: true

      t.timestamps
    end

    add_index :clients, :client_id, unique: true
    add_index :clients, %i[realm_id name], unique: true
  end
end
