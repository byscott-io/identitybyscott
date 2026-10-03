# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_10_03_170400) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"
  enable_extension "pgcrypto"

  create_table "clients", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.uuid "realm_id", null: false
    t.string "name", null: false
    t.string "client_id", null: false
    t.string "client_secret_digest"
    t.text "allowed_origins", default: "", null: false
    t.text "redirect_uris", default: "", null: false
    t.boolean "active", default: true, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "app_base_url"
    t.jsonb "url_templates", default: {}, null: false
    t.index ["client_id"], name: "index_clients_on_client_id", unique: true
    t.index ["realm_id", "name"], name: "index_clients_on_realm_id_and_name", unique: true
    t.index ["realm_id"], name: "index_clients_on_realm_id"
  end

  create_table "identities", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.uuid "realm_id", null: false
    t.string "email", null: false
    t.string "encrypted_password", default: "", null: false
    t.string "first_name"
    t.string "last_name"
    t.string "nickname"
    t.string "time_zone"
    t.string "phone"
    t.string "reset_password_token"
    t.datetime "reset_password_sent_at"
    t.string "confirmation_token"
    t.datetime "confirmed_at"
    t.datetime "confirmation_sent_at"
    t.string "unconfirmed_email"
    t.integer "failed_attempts", default: 0, null: false
    t.string "unlock_token"
    t.datetime "locked_at"
    t.boolean "mfa_enabled", default: false, null: false
    t.string "mfa_secret"
    t.text "backup_codes"
    t.datetime "backup_codes_generated_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.uuid "signup_client_id"
    t.index "realm_id, lower((email)::text)", name: "index_identities_on_realm_and_lower_email", unique: true
    t.index ["confirmation_token"], name: "index_identities_on_confirmation_token", unique: true
    t.index ["realm_id"], name: "index_identities_on_realm_id"
    t.index ["reset_password_token"], name: "index_identities_on_reset_password_token", unique: true
    t.index ["signup_client_id"], name: "index_identities_on_signup_client_id"
    t.index ["unlock_token"], name: "index_identities_on_unlock_token", unique: true
  end

  create_table "realms", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "key", null: false
    t.string "name", null: false
    t.boolean "require_email_confirmation", default: true, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["key"], name: "index_realms_on_key", unique: true
  end

  add_foreign_key "clients", "realms"
  add_foreign_key "identities", "clients", column: "signup_client_id"
  add_foreign_key "identities", "realms"
end
