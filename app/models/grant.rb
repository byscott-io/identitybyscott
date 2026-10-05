# frozen_string_literal: true

# Permission for one identity to use one registered application.
#
# An identity existing in a realm is NOT permission to use the applications in
# it. Authentication says who someone is; a grant says where they may take that.
# Without this distinction every identity in a realm could sign in to every
# application in it, which makes a realm a single blast radius rather than a
# shared set of credentials.
#
# Granting is the deliberate step: "enable this person for issues and metrics".
# Later adding email is another grant, not another sign-up and not a re-login --
# the person keeps one identity, one password and one `sub`.
#
# An application belongs to exactly one realm, so a grant can only ever name an
# application inside the identity's own realm. That is enforced here rather than
# assumed: a grant crossing realms would silently defeat the isolation the whole
# design rests on, and nothing else would notice.
#
# Revoking is deleting the row. There is no revoked_at: a grant is a statement
# about the present, and a soft-deleted one invites code that forgets to filter.
class Grant < ApplicationRecord
  belongs_to :identity
  belongs_to :client, foreign_key: :granted_client_id, inverse_of: :grants

  validates :granted_client_id, uniqueness: { scope: :identity_id }
  validate :client_must_be_in_the_identitys_realm

  # Whether this identity may use this application.
  #
  # Takes records rather than ids so a caller cannot accidentally pass a public
  # client_id string where a uuid is expected -- the two are easy to confuse,
  # and a lookup that silently matches nothing would read as "not granted" and
  # lock someone out for a reason no log would explain.
  def self.permits?(identity:, client:)
    return false if identity.nil? || client.nil?

    exists?(identity_id: identity.id, granted_client_id: client.id)
  end

  private

  def client_must_be_in_the_identitys_realm
    return if identity.nil? || client.nil?
    return if identity.realm_id == client.realm_id

    errors.add(:client, "belongs to a different realm than the identity")
  end
end
