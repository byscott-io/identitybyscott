# frozen_string_literal: true

# A registered application, and the record that makes realm isolation real:
# every request's realm is resolved from its client_id.
class Client < ApplicationRecord
  belongs_to :realm

  has_secure_password :client_secret, validations: false

  validates :name, presence: true, uniqueness: { scope: :realm_id }
  validates :client_id, presence: true, uniqueness: true

  scope :active, -> { where(active: true) }

  before_validation :generate_client_id, on: :create

  # Origins permitted to post credentials from a browser. This is the
  # browser-facing security boundary: a browser presents only the public
  # client_id, so the Origin header checked against this list is what constrains
  # who may call the credential endpoints.
  #
  # It does NOT stop a server-side caller, and it does not stop a convincing
  # fake form on someone else's site -- the password reached them before this
  # server was involved. That exposure is inherent to app-owned forms.
  def allowed_origins_list
    split_list(allowed_origins)
  end

  def redirect_uris_list
    split_list(redirect_uris)
  end

  def origin_allowed?(origin)
    return false if origin.blank?

    allowed_origins_list.include?(origin)
  end

  # Exact match only. No wildcards and no prefix matching: a prefix match on a
  # redirect_uri is the classic way authorization codes get handed to an
  # attacker.
  def redirect_uri_allowed?(uri)
    return false if uri.blank?

    redirect_uris_list.include?(uri)
  end

  private

  def split_list(value)
    value.to_s.split(/[\s,]+/).compact_blank
  end

  def generate_client_id
    self.client_id ||= "cid_#{SecureRandom.urlsafe_base64(24)}"
  end
end
