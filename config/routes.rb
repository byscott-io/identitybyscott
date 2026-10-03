Rails.application.routes.draw do
  # skip: :all -- the MAPPING without any routes.
  #
  # Devise needs a mapping to exist (Devise::Mapping.find_scope! raises without
  # one, including from its mailers), but this app deliberately has no Devise
  # controllers: credential endpoints are its own API, because consuming apps
  # build their own forms and post to them.
  devise_for :identities, skip: :all

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
