# frozen_string_literal: true

# A registered application, and the record that makes realm isolation real:
# every request's realm is resolved from its client_id.
class Client < ApplicationRecord
  belongs_to :realm

  has_secure_password :client_secret, validations: false

  # A readable public identifier rather than a random string.
  #
  # client_id is public by design -- it ships in every application's JS bundle
  # and appears as the aud claim in every token -- so randomising it hides
  # nothing. A readable one makes URLs and tokens legible:
  #
  #   POST /api/apps/churchcare/auth/sign_in       aud: "churchcare"
  #   POST /api/apps/cid_x7KqL9.../auth/sign_in    aud: "cid_x7KqL9..."
  #
  # One identifier, not two. A separate "slug for URLs, client_id for tokens"
  # would be two names for the same thing and an invitation to confuse them.
  RESERVED_CLIENT_IDS = %w[
    api apps clients admin auth health up new edit index .well-known
  ].freeze

  validates :name, presence: true, uniqueness: { scope: :realm_id }
  validates :client_id,
            presence: true,
            uniqueness: true,
            format: {
              with: /\A[a-z0-9][a-z0-9-]{1,62}[a-z0-9]\z/,
              message: "must be 3-64 lowercase letters, digits or hyphens"
            },
            exclusion: {
              in: RESERVED_CLIENT_IDS,
              message: "is reserved"
            }

  scope :active, -> { where(active: true) }

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
end
