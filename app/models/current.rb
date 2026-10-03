# frozen_string_literal: true

# Per-request context.
#
# +client+ is set from the VALIDATED client_id of the incoming request, never
# from an unchecked parameter, and the realm follows from it. That is what makes
# realm isolation real: an app cannot name a realm, only present a client_id
# this server recognises.
class Current < ActiveSupport::CurrentAttributes
  attribute :client

  def realm
    client&.realm
  end
end
