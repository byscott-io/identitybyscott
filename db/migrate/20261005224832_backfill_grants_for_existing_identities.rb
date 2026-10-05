# frozen_string_literal: true

# Grants did not exist before this, so every identity could sign in to every
# application in its realm. Enforcing grants without this migration would lock
# all of them out at once -- the check would be correct and the outcome an
# outage.
#
# Granting each identity every application in its own realm reproduces exactly
# the access they had a moment earlier. It is deliberately permissive: this is a
# migration, not a policy decision, and tightening it is a later, deliberate act
# of revoking grants rather than a side effect of adding the table.
#
# Inactive applications are included. `active` is a switch an operator flips to
# take an application offline; it does not express who was allowed to use it,
# and omitting them would quietly revoke access the moment one came back.
class BackfillGrantsForExistingIdentities < ActiveRecord::Migration[8.1]
  def up
    say_with_time "granting existing identities their realm's applications" do
      granted = execute(<<~SQL).cmd_tuples
        INSERT INTO grants (id, identity_id, granted_client_id, created_at, updated_at)
        SELECT gen_random_uuid(), i.id, c.id, NOW(), NOW()
        FROM identities i
        JOIN clients c ON c.realm_id = i.realm_id
        ON CONFLICT (identity_id, granted_client_id) DO NOTHING
      SQL

      granted
    end
  end

  # Irreversible on purpose. Rolling back cannot tell a backfilled grant from
  # one an operator added afterwards, so deleting them all would revoke real
  # decisions. Dropping the table (the previous migration's down) is the honest
  # way back.
  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
