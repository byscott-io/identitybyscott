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

  # Single sign-on. The ONE surface that sees a cookie, which is why it has its
  # own path prefix: the cookie is scoped to /sso, so the browser never attaches
  # it to anything under /api.
  #
  # client_id is a QUERY parameter here, unlike the credential endpoints below.
  # The reason those need it in the path is CORS -- a preflight can see only the
  # URL -- and there is no preflight on a top-level navigation, which is the
  # only way this endpoint is ever reached. The property that matters is
  # untouched: the realm still comes from a Client record looked up by this
  # id, never from a request parameter. Discovery also has to publish ONE
  # authorization_endpoint, which a per-client path could not be.
  scope "sso", module: :sso do
    get "authorize", to: "authorizations#show"

    # Establishes the cookie during a top-level navigation, because this server
    # is a third party to every application it serves and a cookie set in reply
    # to a cross-site request is refused or partitioned. See SsoBootstrap.
    get "bootstrap", to: "bootstraps#show"
  end

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
    post "auth/sign_up", to: "registrations#create"
    post "auth/verify_mfa", to: "mfa#verify"
    post "auth/forgot_password", to: "passwords#create"
    post "auth/reset_password", to: "passwords#update"
    # Session management. sign_out moved off SessionsController (which handles
    # sign-IN and is unauthenticated) onto the authenticated controller, because
    # revoking the right session requires knowing which token asked.
    delete "auth/sign_out", to: "user_sessions#sign_out"
    post "auth/refresh", to: "refreshes#create"

    # Redeems an authorization code from /sso/authorize. In the path-scoped
    # block, not under /sso, because this one IS preflighted -- see
    # Api::TokensController.
    post "auth/token", to: "tokens#create"
    get "auth/sessions", to: "user_sessions#index"
    delete "auth/sessions", to: "user_sessions#destroy_all"
    delete "auth/sessions/:id", to: "user_sessions#destroy"

    get "auth/mfa", to: "mfa_enrollment#show"
    post "auth/mfa/setup", to: "mfa_enrollment#setup"
    post "auth/mfa/enable", to: "mfa_enrollment#enable"
    post "auth/mfa/disable", to: "mfa_enrollment#disable"
    post "auth/mfa/regenerate_backup_codes", to: "mfa_enrollment#regenerate_backup_codes"
    get "auth/mfa/backup_codes", to: "mfa_enrollment#backup_codes"
    put "auth/change_password", to: "password_changes#update"
    put "auth/profile", to: "profiles#update"

    # Exchange this application's token for one usable at another application
    # in the same realm, for the same identity. Gated on that identity holding
    # a grant for the target.
    post "auth/exchange", to: "exchanges#create"
  end

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
