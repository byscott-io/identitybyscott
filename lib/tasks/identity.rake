# frozen_string_literal: true

namespace :identity do
  namespace :realm do
    desc "Create a realm. KEY=sdk NAME='SDK suite' [CONFIRM_EMAIL=true]"
    task create: :environment do
      key = ENV.fetch("KEY")
      realm = Realm.create!(
        key: key,
        name: ENV.fetch("NAME", key.titleize),
        # Default ON, so opting out is always deliberate. Skipping confirmation
        # is defensible where identities arrive only by invitation -- the
        # invitation token is itself proof of inbox access -- and not where
        # anyone can self-signup.
        require_email_confirmation: ENV.fetch("CONFIRM_EMAIL", "true") != "false"
      )

      puts "realm #{realm.key} (#{realm.id})"
      puts "  email confirmation: #{realm.require_email_confirmation ? 'required' : 'not required'}"
    end

    desc "List realms"
    task list: :environment do
      Realm.order(:key).each do |realm|
        puts format("%-20s %-28s identities:%-5d clients:%d",
                    realm.key, realm.name, realm.identities.count, realm.clients.count)
      end
    end
  end

  namespace :client do
    desc <<~DESC
      Register an application. REALM=sdk CLIENT_ID=churchcare NAME='ChurchCare'
        APP_URL=https://churchcare.net ORIGINS='https://churchcare.net https://www.churchcare.net'
        [SECRET=true]
    DESC
    task register: :environment do
      realm = Realm.find_by!(key: ENV.fetch("REALM"))

      client = realm.clients.new(
        client_id: ENV.fetch("CLIENT_ID"),
        name: ENV.fetch("NAME"),
        app_base_url: ENV.fetch("APP_URL"),
        # The browser-facing security boundary. Adding an origin admits a new
        # site to this realm's credential endpoints, so it is a security
        # decision rather than configuration.
        allowed_origins: ENV.fetch("ORIGINS")
      )

      # Only for an application that makes server-to-server calls. A browser
      # cannot hold a secret, so a front end never needs one.
      secret = nil
      if ENV["SECRET"] == "true"
        secret = SecureRandom.urlsafe_base64(48)
        client.client_secret = secret
      end

      client.save!

      puts "client #{client.client_id} in realm #{realm.key}"
      puts "  app:     #{client.app_base_url}"
      puts "  origins: #{client.allowed_origins_list.join(', ')}"
      if secret
        puts
        puts "  secret:  #{secret}"
        puts "  ^ shown once and never recoverable -- only the digest is stored."
        puts "    Server-to-server only. Never put this in a JS bundle."
      end
    end

    desc "List registered applications. [REALM=sdk]"
    task list: :environment do
      scope = ENV["REALM"] ? Realm.find_by!(key: ENV["REALM"]).clients : Client.all

      scope.includes(:realm).order(:client_id).each do |client|
        puts format("%-24s %-12s %-34s %s",
                    client.client_id,
                    client.realm.key,
                    client.app_base_url.to_s,
                    client.active ? "" : "(inactive)")
        puts "    origins: #{client.allowed_origins_list.join(', ')}"
      end
    end

    desc "Add an allowed origin. CLIENT_ID=churchcare ORIGIN=https://new.example.com"
    task add_origin: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      origin = ENV.fetch("ORIGIN")

      if client.origin_allowed?(origin)
        puts "already allowed: #{origin}"
        next
      end

      client.update!(allowed_origins: (client.allowed_origins_list + [ origin ]).join(" "))
      puts "#{client.client_id} now allows: #{client.allowed_origins_list.join(', ')}"
    end

    desc "Deactivate an application, refusing every request it makes. CLIENT_ID=churchcare"
    task deactivate: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      client.update!(active: false)

      # Note what this does NOT do: tokens already issued stay valid until they
      # expire, because applications verify offline. This stops new sign-ins,
      # not current sessions.
      puts "#{client.client_id} deactivated -- no new sign-ins."
      puts "Tokens already issued remain valid for up to #{TokenIssuer::ACCESS_TOKEN_TTL.inspect}."
    end
  end

  namespace :grant do
    desc <<~DESC
      Enable an identity for an application.
      EMAIL=person@example.com REALM=sdk CLIENT_ID=metrics
    DESC
    task create: :environment do
      realm = Realm.find_by!(key: ENV.fetch("REALM"))
      identity = Identity.find_for_authentication_in_realm(realm, ENV.fetch("EMAIL"))
      raise "No identity #{ENV.fetch('EMAIL')} in realm #{realm.key}" if identity.nil?

      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))

      grant = Grant.new(identity: identity, client: client)
      if grant.save
        puts "granted #{identity.email} -> #{client.client_id}"
      elsif grant.errors.of_kind?(:granted_client_id, :taken)
        puts "already granted: #{identity.email} -> #{client.client_id}"
      else
        abort "could not grant: #{grant.errors.full_messages.join(', ')}"
      end
    end

    desc "List grants. [REALM=sdk] [EMAIL=person@example.com] [CLIENT_ID=metrics]"
    task list: :environment do
      scope = Grant.includes(:identity, :client)
      scope = scope.where(identity: Realm.find_by!(key: ENV["REALM"]).identities) if ENV["REALM"]
      scope = scope.where(granted_client_id: Client.find_by!(client_id: ENV["CLIENT_ID"]).id) if ENV["CLIENT_ID"]

      if ENV["EMAIL"]
        scope = scope.where(identity: Identity.where("lower(email) = ?", ENV["EMAIL"].downcase.strip))
      end

      rows = scope.to_a.sort_by { |g| [ g.identity.email, g.client.client_id ] }
      puts "(none)" if rows.empty?
      rows.each { |g| puts format("%-40s %-24s %s", g.identity.email, g.client.client_id, g.identity.realm.key) }
    end

    desc <<~DESC
      Remove an identity's access to an application.
      EMAIL=person@example.com REALM=sdk CLIENT_ID=metrics
    DESC
    task revoke: :environment do
      realm = Realm.find_by!(key: ENV.fetch("REALM"))
      identity = Identity.find_for_authentication_in_realm(realm, ENV.fetch("EMAIL"))
      raise "No identity #{ENV.fetch('EMAIL')} in realm #{realm.key}" if identity.nil?

      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      grant = Grant.find_by(identity_id: identity.id, granted_client_id: client.id)

      if grant.nil?
        puts "not granted anyway: #{identity.email} -> #{client.client_id}"
        next
      end

      grant.destroy!

      # Say plainly what this does and does not reach. Applications verify
      # access tokens offline, so a revoked grant stops the NEXT refresh and
      # every future sign-in -- not the token someone is holding right now.
      puts "revoked #{identity.email} -> #{client.client_id}"
      puts "Their current access token stays valid for up to #{TokenIssuer::ACCESS_TOKEN_TTL.inspect}."
      puts "Revoke their sessions too if that matters."
    end
  end

  desc "Generate a signing key pair. Prints the private PEM for IDENTITY_SIGNING_KEY."
  task :signing_key do
    key = OpenSSL::PKey::RSA.generate(2048)

    puts key.to_pem
    puts "# kid: #{OpenSSL::Digest::SHA256.hexdigest(key.public_key.to_der)[0, 32]}"
    puts "# Store as IDENTITY_SIGNING_KEY. Never commit it -- this repository is public."
  end
end
