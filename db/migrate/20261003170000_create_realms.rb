# frozen_string_literal: true

class CreateRealms < ActiveRecord::Migration[8.1]
  def change
    enable_extension "pgcrypto" unless extension_enabled?("pgcrypto")

    # A realm is a suite: a set of apps that share identities. Realms are fully
    # isolated -- an identity in one has no knowledge of the other. See #670.
    create_table :realms, id: :uuid do |t|
      t.string :key, null: false
      t.string :name, null: false

      # Whether self-signup in this realm must confirm its email address.
      # Default TRUE so opting out is always a deliberate act on a specific
      # realm rather than something a new realm inherits by accident.
      #
      # Skipping it is defensible when identities arrive only by invitation --
      # the invitation token is itself proof of inbox access. It is not
      # defensible alongside open registration.
      t.boolean :require_email_confirmation, null: false, default: true

      t.timestamps
    end

    add_index :realms, :key, unique: true
  end
end
