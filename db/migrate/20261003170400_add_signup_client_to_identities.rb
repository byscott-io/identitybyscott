# frozen_string_literal: true

class AddSignupClientToIdentities < ActiveRecord::Migration[8.1]
  def change
    # Which app this identity signed up through. Used as the fallback when a
    # notification is raised outside a request -- a console password reset, a
    # background job -- and there is no current client to take URLs from.
    add_reference :identities, :signup_client, type: :uuid, foreign_key: { to_table: :clients }
  end
end
