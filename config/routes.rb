Rails.application.routes.draw do
  # skip: :all -- the MAPPING without any routes.
  #
  # Devise needs a mapping to exist (Devise::Mapping.find_scope! raises without
  # one, including from its mailers), but this app deliberately has no Devise
  # controllers: credential endpoints are its own API, because consuming apps
  # build their own forms and post to them.
  devise_for :identities, skip: :all

  # Discovery. Unauthenticated by design -- these documents exist so a verifier
  # can find the public keys without credentials.
  get "/.well-known/jwks.json", to: "well_known#jwks", format: false
  get "/.well-known/openid-configuration", to: "well_known#openid_configuration", format: false

  # Credential endpoints, scoped by client_id in the PATH.
  #
  # In the path because a CORS preflight can see nothing else: it carries the
  # Origin, the method and the names of requested headers, but no body and no
  # header values. Per-client origin checking therefore has to read the client
  # from the URL.
  # "apps" rather than "clients", and a readable client_id rather than a random
  # one -- the identifier is public either way, so legibility is free. The
  # segment is kept so a client_id can never collide with a top-level API path.
  scope "api/apps/:client_id", module: :api do
    match "*any", to: "preflight#handle", via: :options

    post "auth/sign_in", to: "sessions#create"
  end

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
