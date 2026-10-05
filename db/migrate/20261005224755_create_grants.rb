# frozen_string_literal: true

class CreateGrants < ActiveRecord::Migration[8.1]
  def change
    create_table :grants, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.references :identity, null: false, foreign_key: true, type: :uuid

      # Named for its role rather than :client_id on purpose. Client has BOTH an
      # internal uuid `id` and a public string `client_id` ("churchcare"), and
      # that class documents the confusion between them as a known hazard. A
      # column called client_id holding a uuid, beside a client_id holding a
      # name, is exactly that hazard -- `grant.client_id` would return something
      # quite different from `grant.client.client_id`. Follows the shape already
      # set by identities.signup_client_id.
      t.uuid :granted_client_id, null: false

      t.timestamps
    end

    add_foreign_key :grants, :clients, column: :granted_client_id

    # One grant per identity per application. Enforced in the database, not only
    # in the model, because a double-submit races the uniqueness validation.
    add_index :grants, %i[identity_id granted_client_id], unique: true,
              name: "index_grants_on_identity_and_client"
    add_index :grants, :granted_client_id
  end
end
