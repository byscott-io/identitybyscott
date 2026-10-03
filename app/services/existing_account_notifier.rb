# frozen_string_literal: true

# Tells the OWNER of an address that someone tried to sign up with it, instead of
# telling the caller that it is taken.
#
# This is what lets a confirmation-requiring realm answer signup identically
# whether or not the address exists. The person who can read the inbox learns
# something useful; the person probing learns nothing.
class ExistingAccountNotifier
  def self.call(realm:, email:, client:)
    identity = Identity.find_for_authentication_in_realm(realm, email)
    return if identity.nil?

    Current.client = client
    IdentityMailer.existing_account(identity).deliver_later
  end
end
