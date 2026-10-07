# frozen_string_literal: true

# Which realm session each application session came from.
#
# Without this, signing out of one application cannot tell WHICH browser is
# asking. A sign-out arrives at /api, and the SSO cookie is path-scoped to /sso
# precisely so it never goes there -- so the only way to revoke the right realm
# session was to revoke all of them, which signed the person out on their other
# devices too.
#
# The link is recorded at the two moments a session is created from a realm
# session: the bootstrap navigation, which knows the sign-in session it was
# issued for, and the code exchange, which knows the realm session the code was
# minted from.
#
# Nullable, because plenty of sessions legitimately have no realm session: a
# realm without single sign-on, and every session that predates this.
class LinkSessionsToSsoSessions < ActiveRecord::Migration[8.1]
  def change
    add_reference :sessions, :sso_session, type: :uuid, null: true, foreign_key: true

    # The sign-in that will be linked once its bootstrap token is spent. The
    # realm session does not exist yet at sign-in -- it is created by the
    # navigation -- so the bootstrap carries the Session forward to it.
    add_reference :sso_bootstraps, :session, type: :uuid, null: true, foreign_key: true
  end
end
