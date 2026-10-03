# frozen_string_literal: true

# A suite: a set of applications that share identities.
#
# Realms are fully isolated. An identity in one has no knowledge of the other,
# and the same email address is a DIFFERENT identity in each -- different
# password, different MFA, different sub.
class Realm < ApplicationRecord
  has_many :identities, dependent: :restrict_with_error
  has_many :clients, dependent: :restrict_with_error

  validates :key, presence: true, uniqueness: true,
                  format: { with: /\A[a-z0-9][a-z0-9_-]*\z/,
                            message: "must be lowercase letters, digits, hyphen or underscore" }
  validates :name, presence: true

  # Resolve a realm from the client_id a request presents. The ONLY way a realm
  # is ever determined: it is never read from a parameter, because an app that
  # could send realm=church could claim any realm and the isolation would be
  # decorative.
  def self.for_client_id(client_id)
    Client.active.find_by(client_id: client_id)&.realm
  end
end
