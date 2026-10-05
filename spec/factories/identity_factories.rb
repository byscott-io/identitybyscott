# frozen_string_literal: true

FactoryBot.define do
  factory :realm do
    sequence(:key) { |n| "realm-#{n}" }
    sequence(:name) { |n| "Realm #{n}" }
  end

  factory :client do
    realm
    sequence(:name) { |n| "App #{n}" }
    sequence(:client_id) { |n| "test-app-#{n}" }
    allowed_origins { "https://app.example.com" }
    app_base_url { "https://app.example.com" }
  end

  factory :identity do
    realm
    sequence(:email) { |n| "person#{n}@example.com" }
    password { "correct horse battery staple" }

    # Every notification needs a client to build its URL from, because the link
    # must land in the app rather than here.
    signup_client { association :client, realm: realm }

    # Mirrors registration: signing up through an application enables it.
    # Without this the factory builds a state production never produces --
    # an identity granted nothing -- and every sign-in spec would 403 for a
    # reason unrelated to what it was testing.
    #
    # Call `identity.grants.destroy_all` to test the ungranted case.
    after(:create) do |identity|
      identity.grants.create!(client: identity.signup_client) if identity.signup_client
    end
  end

  factory :grant do
    identity
    client { association :client, realm: identity.realm }
  end
end
