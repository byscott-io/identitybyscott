# frozen_string_literal: true

module Sso
  # Serves an application's login page logo from the bytes this server holds.
  #
  # From here rather than from a remote URL, so `img-src 'self'` holds and no
  # host outside this one can change what appears on a page that takes a
  # password.
  #
  # Unauthenticated, like the discovery documents: it is a logo, it is already
  # public wherever the application shows it, and the login page needs it before
  # anybody has signed in.
  class ThemeLogosController < ActionController::Metal
    include ActionController::Head
    include AbstractController::Callbacks
    include ActionController::Rendering

    def show
      client = Client.active.find_by(client_id: request.query_parameters["client_id"])
      owner = client && Theme.resolve_logo(client)

      return head(:not_found) if owner.nil?

      # nosniff AND a locked-down CSP on the asset itself. The content type is
      # validated on the way in, so this is belt and braces -- but an image
      # route that could ever serve something a browser treats as a document is
      # the one place this would matter, and the cost is two headers.
      headers["X-Content-Type-Options"] = "nosniff"
      headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
      headers["Content-Disposition"] = "inline"
      # Public: it is a logo, and the login page should not re-fetch it.
      headers["Cache-Control"] = "public, max-age=3600"

      send_logo(owner)
    end

    private

    def send_logo(owner)
      self.status = 200
      self.content_type = owner.theme_logo_content_type
      self.response_body = owner.theme_logo_data
    end
  end
end
