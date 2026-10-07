# frozen_string_literal: true

# Builds the redirect back to an application, appending rather than replacing.
#
# Extracted from AuthorizationsController because the hosted login page now
# builds the same URL, and a second copy of query-string assembly is a second
# place for a code to end up somewhere unintended.
#
# A registered callback is allowed to carry its own parameters, and clobbering
# them would break it in a way that looks like the application's bug.
class AuthorizeRedirect
  def self.build(redirect_uri, **query)
    uri = URI.parse(redirect_uri)
    existing = URI.decode_www_form(uri.query.to_s)
    uri.query = URI.encode_www_form(existing + query.compact.transform_keys(&:to_s).to_a)
    uri.to_s
  end
end
