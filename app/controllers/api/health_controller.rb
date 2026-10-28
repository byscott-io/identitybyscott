# frozen_string_literal: true

module Api
  # Liveness, plus the deployed commit to whoever can prove they may ask.
  #
  # Separate from `/up` (Rails' stock health route, which Kamal's own
  # healthcheck still uses) because that one answers HTML, and a deploy-sync
  # monitor needs JSON carrying a commit. Without this, this server could run
  # arbitrarily stale code while its monitor stayed green — which is a poor
  # property for the process that issues the tokens every other application
  # verifies, and was exactly the state found on 2026-10-26.
  #
  # Does NOT inherit Api::BaseController. That one resolves a Client from a
  # `client_id` path segment and enforces a per-client origin allowlist, neither
  # of which a monitor has or should need. It is a sibling of WellKnownController
  # in that respect: unauthenticated, client-less, and not a credential endpoint.
  #
  # Deliberately reports no backing-service state — no database, no queue, no
  # migration status. This is a public endpoint on a public server, the sort of
  # detail core gates behind a secret for private apps, and `/up` never offered
  # it either. Liveness and a commit are what the monitor consumes.
  class HealthController < ApplicationController
    # GET /api/health
    def show
      payload = { status: "ok", timestamp: Time.current.utc.iso8601 }

      # Only to an authorized caller. The repository is public, so the commit
      # itself is not a secret — but which commit is LIVE tells an unauthorized
      # reader whether a published fix has actually shipped, which is a
      # reconnaissance answer worth withholding.
      payload[:commit_sha] = commit_sha if authorized_for_details?

      render json: payload
    end

    private

    # Set by Kamal in every deployed container, so nothing has to be passed at
    # build time. Short form, matching what the fleet's monitors compare against.
    def commit_sha
      sha = ENV.fetch("KAMAL_VERSION", nil)
      sha.presence && sha[0, 8]
    end

    # The monitor presents the secret as a bearer token; a query parameter is
    # accepted too, because that is the other shape the fleet's checkers use.
    #
    # An unauthorized caller gets the same 200 and the same two fields as one
    # that presented nothing, so this never becomes a way to test a guessed
    # secret — the uniform-failure rule the credential endpoints follow.
    def authorized_for_details?
      secret = ENV.fetch("HEALTH_CHECK_SECRET", nil)
      return false if secret.blank?

      provided = presented_token
      return false if provided.blank?

      ActiveSupport::SecurityUtils.secure_compare(secret, provided)
    end

    def presented_token
      header = request.headers["Authorization"]
      return header.split(" ", 2).last if header&.start_with?("Bearer ")

      request.query_parameters[:token]
    end
  end
end
