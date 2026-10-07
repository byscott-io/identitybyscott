# frozen_string_literal: true

# A registered application, and the record that makes realm isolation real:
# every request's realm is resolved from its client_id.
#
# Two identifiers, and they must not be confused:
#
#   id         a uuid primary key. INTERNAL. Only ever a foreign key target
#              (identities.signup_client_id). Never published, never in a URL,
#              never in a token.
#   client_id  the public KEY -- a stable readable name like "churchcare".
#              Appears in URLs, in the aud claim of every token, and in each
#              application's own configuration.
#
# client_id is a poor name for what it is: semantically it is a key, not an id,
# and this class having a real `id` beside it makes that worse. The name stays
# because it is not ours to choose -- RFC 6749 section 2.2 defines it, every
# OIDC library expects it, the discovery document publishes it, and aud is
# matched against it. Being tidier here would mean being non-standard at the one
# boundary where standards earn their keep.
class Client < ApplicationRecord
  belongs_to :realm
  has_many :sessions, dependent: :destroy
  has_many :grants, foreign_key: :granted_client_id, dependent: :destroy, inverse_of: :client
  has_many :granted_identities, through: :grants, source: :identity

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

  def origin_allowed?(origin)
    return false if origin.blank?

    allowed_origins_list.include?(origin)
  end

    # Where an authorization code may be sent back to.
    #
    # Nothing reads this yet -- /authorize does not exist. It lands now so a
    # client can be registered ahead of the endpoint that will enforce it.
    def redirect_uris_list
      split_list(redirect_uris)
    end

    # EXACT string equality, and nothing cleverer.
    #
    # A code is a credential, so where it may be delivered is the single most
    # important thing this record states. Every relaxation is a known way
    # codes reach the wrong party: a prefix match lets
    # https://app.example.com.attacker.test through, a host-only match
    # ignores the path, and a wildcard in the path lets an open redirect on
    # the application carry the code onward.
    #
    # If a legitimate callback needs to vary, register each form.
    def redirect_uri_allowed?(uri)
      return false if uri.blank?

      redirect_uris_list.include?(uri)
    end

  private

  def split_list(value)
    value.to_s.split(/[\s,]+/).compact_blank
  end
end
