# frozen_string_literal: true

module Api
  # Answers CORS preflights.
  #
  # Separate from BaseController because a preflight must be answered WITHOUT
  # authenticating anything: the browser sends it before the real request, with
  # no credentials, and refusing it for lack of credentials would block every
  # legitimate call.
  class PreflightController < ApplicationController
    ALLOWED_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    ALLOWED_HEADERS = "Content-Type, Authorization"

    def handle
      client = Client.active.find_by(client_id: request.path_parameters[:client_id])
      origin = request.headers["Origin"]

      # A refused preflight stops the real request being SENT, not merely hides
      # its response -- which is why this is a real control for a JSON POST.
      return head :forbidden unless client && origin.present? && client.origin_allowed?(origin)

      response.set_header("Access-Control-Allow-Origin", origin)
      response.set_header("Access-Control-Allow-Methods", ALLOWED_METHODS)
      response.set_header("Access-Control-Allow-Headers", ALLOWED_HEADERS)
      response.set_header("Access-Control-Max-Age", "600")
      response.set_header("Vary", "Origin")

      head :no_content
    end
  end
end
