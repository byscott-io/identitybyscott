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

    desc <<~DESC
      Turn single sign-on on or off for a realm. KEY=sdk ENABLED=true
      Off everywhere by default; nothing reads it until /authorize exists.
    DESC
    task sso: :environment do
      realm = Realm.find_by!(key: ENV.fetch("KEY"))
      enabled = ActiveModel::Type::Boolean.new.cast(ENV.fetch("ENABLED"))
      realm.update!(sso_enabled: enabled)

      puts "#{realm.key}: sso_enabled=#{realm.sso_enabled}"
      puts "Applications in this realm may share a browser session once /authorize ships." if enabled
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

    desc <<~DESC
      Register where authorization codes may be returned to.
      CLIENT_ID=churchcare URI=https://churchcare.net/auth/callback

      Matched EXACTLY when /authorize ships -- no wildcards and no prefixes, so
      register every form a real callback needs.
    DESC
    task add_redirect_uri: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      uri = ENV.fetch("URI")

      parsed = URI.parse(uri) rescue nil
      abort "not an absolute https URI: #{uri}" unless parsed.is_a?(URI::HTTPS) || parsed&.scheme == "http"

      if client.redirect_uri_allowed?(uri)
        puts "already registered: #{uri}"
        next
      end

      client.update!(redirect_uris: (client.redirect_uris_list + [ uri ]).join(" "))
      puts "#{client.client_id} now returns codes to:"
      client.redirect_uris_list.each { |u| puts "  #{u}" }
    end

    desc "Remove a redirect URI. CLIENT_ID=churchcare URI=https://churchcare.net/auth/callback"
    task remove_redirect_uri: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      uri = ENV.fetch("URI")

      unless client.redirect_uri_allowed?(uri)
        puts "not registered anyway: #{uri}"
        next
      end

      client.update!(redirect_uris: (client.redirect_uris_list - [ uri ]).join(" "))
      puts "#{client.client_id} no longer returns codes to #{uri}"
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

    desc "List grants. [REALM=sdk] [EMAIL=person@example.com, needs REALM] [CLIENT_ID=metrics]"
    task list: :environment do
      scope = Grant.includes(:identity, :client)
      realm = ENV["REALM"] ? Realm.find_by!(key: ENV["REALM"]) : nil
      scope = scope.where(identity: realm.identities) if realm
      scope = scope.where(granted_client_id: Client.find_by!(client_id: ENV["CLIENT_ID"]).id) if ENV["CLIENT_ID"]

      if ENV["EMAIL"]
        # REALM is required alongside EMAIL. An address is only unique
        # WITHIN a realm -- the same one is a different person in each -- so
        # an unscoped email lookup silently mixes them, which is the
        # confusion realms exist to prevent. Scoping it is also the rule
        # this repository states plainly: never look up an identity by
        # email without a realm.
        abort "EMAIL needs REALM too -- an address is only unique within a realm" if realm.nil?

        identity = Identity.find_for_authentication_in_realm(realm, ENV["EMAIL"])
        scope = identity ? scope.where(identity_id: identity.id) : scope.none
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

  namespace :client do
    desc "Set login page appearance tokens for an application"
    task theme: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      apply_theme(client, "client #{client.client_id}")
    end

    desc "Clear an application's appearance tokens, falling back to its realm"
    task clear_theme: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      client.update!(theme: {})
      puts "Cleared theme for client #{client.client_id}; realm defaults now apply."
    end

    desc "Set an application's login page logo from a local image file"
    task logo: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      apply_logo(client, "client #{client.client_id}")
    end

    desc "Remove an application's logo, falling back to its realm"
    task clear_logo: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      client.update!(theme_logo_data: nil, theme_logo_content_type: nil)
      puts "Cleared logo for client #{client.client_id}."
    end

    desc "Show the appearance tokens actually in force for an application"
    task show_theme: :environment do
      client = Client.find_by!(client_id: ENV.fetch("CLIENT_ID"))
      resolved = Theme.resolve(client)
      logo_owner = Theme.resolve_logo(client)

      puts "Resolved theme for #{client.client_id} (client over realm over default):"
      resolved.each { |key, value| puts format("  %-18s %s", key, value.nil? ? "(none)" : value) }
      puts format("  %-18s %s", "logo",
                  logo_owner ? "#{logo_owner.class.name.downcase}'s (#{logo_owner.theme_logo_content_type})" : "(none)")
    end
  end

  namespace :realm do
    desc "Set default login page appearance tokens for a realm"
    task theme: :environment do
      realm = Realm.find_by!(key: ENV.fetch("REALM"))
      apply_theme(realm, "realm #{realm.key}")
    end

    desc "Set a realm's default login page logo from a local image file"
    task logo: :environment do
      realm = Realm.find_by!(key: ENV.fetch("REALM"))
      apply_logo(realm, "realm #{realm.key}")
    end
  end

  # Only the keys Theme knows are read from the environment, so a typo is a
  # refusal rather than a silently ignored setting -- an operator who types
  # PRIMARY_COLOUR should be told, not left wondering why nothing changed.
  def apply_theme(record, label)
    supplied = Theme::KEYS.to_h { |key| [ key, ENV[key.to_s.upcase] ] }.compact_blank

    if supplied.empty?
      abort "Nothing to set. Pass any of: #{Theme::KEYS.map { |k| k.to_s.upcase }.join(' ')}"
    end

    # Merged over what is already there, so setting one colour does not clear
    # the rest.
    record.theme = record.theme_tokens.merge(supplied.transform_keys(&:to_s))

    unless record.save
      abort "Refused: #{record.errors.full_messages.join('; ')}"
    end

    puts "Set #{supplied.keys.join(', ')} on #{label}."
  end

  def apply_logo(record, label)
    path = ENV.fetch("LOGO")
    abort "No such file: #{path}" unless File.file?(path)

    data = File.binread(path)
    content_type = ENV["CONTENT_TYPE"] || content_type_for(path)

    record.theme_logo_data = data
    record.theme_logo_content_type = content_type

    unless record.save
      abort "Refused: #{record.errors.full_messages.join('; ')}"
    end

    puts "Set logo on #{label} (#{content_type}, #{data.bytesize} bytes)."
  end

  # Derived from the extension, and deliberately NOT sniffed from the bytes.
  # Only the types Theme accepts are mapped, so an svg or a pdf named .png is
  # refused by the model rather than guessed at here.
  def content_type_for(path)
    case File.extname(path).downcase
    when ".png" then "image/png"
    when ".jpg", ".jpeg" then "image/jpeg"
    when ".webp" then "image/webp"
    else
      abort "Cannot tell the type of #{path}. Pass CONTENT_TYPE=, one of " \
            "#{Theme::LOGO_CONTENT_TYPES.join(', ')}."
    end
  end
end
