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
  end
end
