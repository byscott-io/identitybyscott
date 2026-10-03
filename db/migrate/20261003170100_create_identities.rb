# frozen_string_literal: true

class CreateIdentities < ActiveRecord::Migration[8.1]
  def change
    # The uuid primary key IS the OIDC sub, and the fleet's only cross-app key
    # for a person. Never the email: email is a mutable attribute, and keying on
    # it would cascade a rename across every app and corrupt historical metrics,
    # whose S3 archive is append-and-overwrite-only with no rewrite available.
    create_table :identities, id: :uuid do |t|
      t.references :realm, null: false, foreign_key: true, type: :uuid

      t.string :email, null: false
      t.string :encrypted_password, null: false, default: ""

      # Profile, owned here. Apps keep a denormalised cache refreshed from token
      # claims, so they can render a name without calling out.
      t.string :first_name
      t.string :last_name
      t.string :nickname
      t.string :time_zone
      t.string :phone

      # recoverable
      t.string :reset_password_token
      t.datetime :reset_password_sent_at

      # confirmable
      t.string :confirmation_token
      t.datetime :confirmed_at
      t.datetime :confirmation_sent_at
      t.string :unconfirmed_email

      # lockable -- always on, unlike confirmation. No realm benefits from
      # unlimited password guessing.
      t.integer :failed_attempts, null: false, default: 0
      t.string :unlock_token
      t.datetime :locked_at

      # MFA (TOTP)
      t.boolean :mfa_enabled, null: false, default: false
      t.string :mfa_secret
      t.text :backup_codes
      t.datetime :backup_codes_generated_at

      t.timestamps
    end

    # Email is unique PER REALM, not globally. The same address is one identity
    # in the SDK suite and a DIFFERENT identity -- different password, different
    # MFA, different sub -- in the church suite.
    #
    # A global unique index on email, which is what Devise generates and what
    # every app in this fleet carries, would make that impossible: the second
    # realm's signup fails on a uniqueness error.
    #
    # lower(email) so case cannot be used to register a near-duplicate.
    add_index :identities, "realm_id, lower(email)",
              unique: true, name: "index_identities_on_realm_and_lower_email"

    # Tokens are looked up without a realm (they arrive from an emailed link and
    # are unguessable), so these stay globally unique.
    add_index :identities, :reset_password_token, unique: true
    add_index :identities, :confirmation_token, unique: true
    add_index :identities, :unlock_token, unique: true
  end
end
