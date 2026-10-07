# frozen_string_literal: true

require "rails_helper"

# db/schema.rb must be exactly what the committed migrations produce.
#
# == Why this exists
#
# A review caught schema.rb carrying a table and a column that NO migration in
# the repository creates. They came from a sibling branch whose migrations had
# been applied to the development database; the schema dump captured the
# database rather than the result of the branch's own migrations.
#
# The consequence is not cosmetic. A database set up from that schema holds
# objects with no row in schema_migrations saying where they came from, so the
# migration that genuinely creates them later fails on a duplicate -- on
# whatever machine or environment runs it next.
#
# == Why the obvious check does not catch it
#
# Recreating the database and running `db:migrate` reproduces the corruption
# rather than exposing it. Against an EMPTY database that task does not run
# migrations at all: it loads schema.rb and marks every version as applied. So
# the polluted file validates itself, and rubocop, the whole suite and
# check-public-safe all passed on it.
#
# What actually exercises the migrations is running them from nothing. This does
# that inside a savepoint and rolls it back, so it needs no second database:
# every migration here is DDL-transactional, which Postgres can undo. Add a
# migration that is not -- disable_ddl_transaction!, or an index built
# CONCURRENTLY -- and this spec has to change with it.
#
# == Only one direction, because the other is already covered
#
# The opposite drift -- a migration committed without regenerating schema.rb --
# is caught before this file even loads: `maintain_test_schema!` in rails_helper
# aborts the whole suite on a pending migration. Verified rather than assumed.
#
# What nothing covered, and what this is for, is schema.rb containing objects
# that no migration creates.
RSpec.describe "db/schema.rb" do
  it "is exactly what the committed migrations produce" do
    committed = Rails.root.join("db/schema.rb").read
    reproduced = nil

    rebuild_from_migrations { reproduced = dump_schema }

    # A diff rather than a bare "not equal", because the useful information is
    # WHICH objects are unaccounted for.
    expect(reproduced).to eq(committed), -> { schema_difference(committed, reproduced) }
  end

  # Runs every migration against an empty database inside a savepoint, yields,
  # then rolls back so the test database is left exactly as it was.
  def rebuild_from_migrations
    connection = ActiveRecord::Base.lease_connection

    connection.transaction(requires_new: true) do
      connection.tables.each { |table| connection.drop_table(table, force: :cascade) }

      # Quiet, or one spec prints every migration in the repository.
      was_verbose = ActiveRecord::Migration.verbose
      ActiveRecord::Migration.verbose = false
      begin
        ActiveRecord::MigrationContext.new(migration_paths).migrate
      ensure
        ActiveRecord::Migration.verbose = was_verbose
      end

      yield

      # Undoes the drops and the migrations together. The suite's own
      # transactional fixtures sit outside this one.
      raise ActiveRecord::Rollback
    end
  end

  def migration_paths
    Rails.application.paths["db/migrate"].to_a
  end

  def dump_schema
    StringIO.new.tap do |stream|
      ActiveRecord::SchemaDumper.dump(ActiveRecord::Base.connection_pool, stream)
    end.string
  end

  # The objects each side has that the other does not, which is the only part
  # anybody reading a failure needs.
  def schema_difference(committed, reproduced)
    only_committed = objects_in(committed) - objects_in(reproduced)
    only_reproduced = objects_in(reproduced) - objects_in(committed)

    [
      "db/schema.rb does not match what the migrations produce.",
      ("  in schema.rb but created by NO migration: #{only_committed.join(', ')}" if only_committed.any?),
      ("  created by a migration but missing from schema.rb: #{only_reproduced.join(', ')}" if only_reproduced.any?),
      "",
      "Regenerate it by loading a known-good schema and migrating FORWARD.",
      "Running db:migrate against an empty database only re-loads schema.rb."
    ].compact.join("\n")
  end

  def objects_in(schema)
    tables = schema.scan(/create_table "([^"]+)"/).flatten
    columns = schema.scan(/create_table "([^"]+)".*?\n(.*?)\n  end/m).flat_map do |table, body|
      body.scan(/t\.\w+ "([^"]+)"/).flatten.map { |column| "#{table}.#{column}" }
    end

    (tables + columns).sort
  end
end
