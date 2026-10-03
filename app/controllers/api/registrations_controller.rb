# frozen_string_literal: true

module Api
  # Self-signup. The application renders the form; this server creates the
  # identity in the realm that application belongs to.
  #
  # An admin inviting someone to an existing organisation is a different flow
  # and lives in the application: the invitation token is emailed by the
  # application, proves inbox access on its own, and grants a membership the
  # application owns. This endpoint is only for someone arriving with no
  # account.
  class RegistrationsController < BaseController
    rate_limit to: 5, within: 1.hour, by: -> { request.remote_ip }, only: :create

    def create
      identity = realm.identities.new(
        email: params[:email],
        password: params[:password],
        first_name: params[:first_name],
        last_name: params[:last_name],
        signup_client: Current.client
      )

      return render_errors(identity) unless identity.save

      if identity.confirmation_required?
        # Nothing is returned but an acknowledgement. The person cannot sign in
        # until they confirm, so there is no token to give them.
        render json: { status: "confirmation_sent" }, status: :accepted
      else
        issuer = TokenIssuer.new(identity: identity, client: Current.client)
        render json: {
          access_token: issuer.access_token,
          token_type: "Bearer",
          expires_in: TokenIssuer::ACCESS_TOKEN_TTL.to_i
        }, status: :created
      end
    end

    private

    # An unavoidable disclosure, and worth being explicit about rather than
    # pretending otherwise.
    #
    # Where a realm requires confirmation, a taken address can be hidden: answer
    # 202 either way and let the email say "you already have an account". Where
    # it does not -- which is the fleet's own choice for self-signup, since a new
    # identity only ever reaches the empty organisation it just created -- the
    # caller is owed a token on success, so failure has to be distinguishable.
    # That makes signup a way to ask whether an address exists in this realm.
    #
    # The exposure is bounded: it says nothing about any OTHER realm, and
    # sign-in and forgot-password remain uniform, so this is the only endpoint
    # that answers the question at all.
    def render_errors(identity)
      if identity.errors.of_kind?(:email, :taken) && realm.require_email_confirmation?
        # Confirmation is on, so say nothing: the address owner gets an email
        # rather than the caller getting an answer.
        ExistingAccountNotifier.call(realm: realm, email: params[:email], client: Current.client)
        return render json: { status: "confirmation_sent" }, status: :accepted
      end

      render json: { errors: identity.errors.to_hash(true) }, status: :unprocessable_content
    end
  end
end
