# frozen_string_literal: true

# Links an application session to the browser session that authorised it, so
# "my devices" can be a list of devices rather than a list of
# application-and-device pairs.
#
# Nullable on purpose, and permanently so. A session is not always born of a
# browser session: a realm with single sign-on disabled never mints one, a
# mobile client has no cookie, and rows created before this migration have no
# browser session to point at. Those are ungrouped, which is the honest answer
# rather than a fabricated grouping.
class AddSsoSessionToSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :sessions, :sso_session_id, :uuid, null: true

    # Every query against this filters to one identity's rows first, so the
    # index exists for the revoke-this-device path, which looks rows up by
    # browser session alone.
    add_index :sessions, :sso_session_id

    # No foreign key, deliberately. SsoSession rows are revoked rather than
    # deleted, but authorization_codes cascades on destroy, and a cascade
    # reaching sessions would silently delete the refresh-token rows that a
    # sessions list and an audit trail both depend on. The association is
    # declared optional in the model for the same reason.
  end
end
