# frozen_string_literal: true

require "rails_helper"

# The rules in .claude/rules/identitybyscott.md that can be MECHANICALLY
# checked, checked.
#
# A rule in a document is an instruction: it depends on whoever is editing
# having read it and remembered it. A rule here is a failing build. Anything in
# that file which can become a spec should, leaving the document to carry only
# the reasoning and the judgement calls.
RSpec.describe "architectural rules" do
  describe "email is unique PER REALM, never globally" do
    let(:indexes) { ActiveRecord::Base.connection.indexes(:identities) }

    it "has a unique index scoped to the realm" do
      scoped = indexes.find { |index| index.name == "index_identities_on_realm_and_lower_email" }

      expect(scoped).to be_present
      expect(scoped.unique).to be(true)
      expect(scoped.columns).to include("realm_id")
    end

    # The obvious wrong move, because it is what Devise generates and what every
    # consuming application carries. It would make the second realm's signup
    # fail on a uniqueness error.
    it "has NO unique index on email alone" do
      global = indexes.select do |index|
        index.unique && Array(index.columns) == [ "email" ]
      end

      expect(global).to be_empty,
                        "a global unique index on email breaks realm isolation: #{global.map(&:name)}"
    end

    it "scopes the model validation to the realm too" do
      validator = Identity.validators_on(:email)
                          .find { |v| v.is_a?(ActiveRecord::Validations::UniquenessValidator) }

      expect(validator.options[:scope]).to eq(:realm_id)
    end
  end

  # Comments are stripped before matching. Both of these rules are DISCUSSED in
  # comments explaining why the forbidden form is forbidden -- an earlier version
  # of these specs matched its own documentation and failed.
  def self.code_without_comments(path)
    File.read(path).lines.reject { |line| line.strip.start_with?("#") }.join
  end

  describe "no email lookup without a realm" do
    # Devise's own find_for_authentication queries globally and would
    # authenticate against the wrong suite, so the scoped finder has to be the
    # only route in.
    it "routes every lookup through the realm-scoped finder" do
      offenders = Dir["app/**/*.rb"].select do |path|
        self.class.code_without_comments(path)
            .match?(/Identity\.(find_by|where|find_for_authentication)\b.*email/)
      end

      expect(offenders).to be_empty,
                           "use Identity.find_for_authentication_in_realm instead: #{offenders}"
    end
  end

  describe "client_id is read from the PATH" do
    # params merges path, query and body. The CORS preflight approved an Origin
    # for the client in the PATH, so a body parameter must never be able to name
    # a different one.
    it "never reads client_id from params" do
      offenders = Dir["app/controllers/**/*.rb"].select do |path|
        self.class.code_without_comments(path).match?(/params\[:client_id\]/)
      end

      expect(offenders).to be_empty,
                           "read request.path_parameters[:client_id] instead: #{offenders}"
    end
  end

  describe "API only" do
    it "is configured api_only" do
      expect(Rails.application.config.api_only).to be(true)
    end

    it "descends from ActionController::API" do
      expect(ApplicationController.superclass).to eq(ActionController::API)
    end

    # No ambient credential means CSRF has nothing to forge. Adding a session
    # would quietly make CSRF protection necessary.
    it "has no cookie, session or flash middleware" do
      stack = Rails.application.middleware.map { |m| m.klass.to_s }
      ambient = stack.grep(/Cookies|Session|Flash/)

      expect(ambient).to be_empty, "ambient credentials reintroduce CSRF: #{ambient}"
    end

    it "has no view templates outside mailers" do
      views = Dir["app/views/**/*.erb"].reject { |path| path.include?("mailer") }

      expect(views).to be_empty, "this server renders no HTML: #{views}"
    end
  end

  describe "it does not depend on corebyscott" do
    # Not the gem, and not the npm package -- which could not be installed from
    # a public repository anyway, since the registry needs a token.
    it "is absent from the lockfile" do
      expect(File.read("Gemfile.lock")).not_to include("corebyscott")
    end

    it "declares no corebyscott gem" do
      declarations = File.read("Gemfile").lines.grep(/^\s*gem /)

      expect(declarations.grep(/corebyscott/)).to be_empty
    end
  end

  describe "tokens carry no container, membership or role claim" do
    it "issues none of them" do
      realm = create(:realm)
      client = create(:client, realm: realm)
      identity = create(:identity, realm: realm, signup_client: client)

      key = OpenSSL::PKey::RSA.generate(2048)
      ENV["IDENTITY_SIGNING_KEY"] = key.to_pem
      ENV["IDENTITY_ISSUER"] = "https://identity.test"
      SigningKeys.reset!

      claims = TokenIssuer.new(identity: identity, client: client).payload.keys.map(&:to_s)

      expect(claims).not_to include("cid", "container_id", "role", "roles", "membership_id")
    ensure
      ENV.delete("IDENTITY_SIGNING_KEY")
      ENV.delete("IDENTITY_ISSUER")
      SigningKeys.reset!
    end

    # The integration contract with the client library, which caches exactly
    # these. Renaming one silently stops a consuming application seeing a name.
    it "uses the OIDC standard profile claim names" do
      expect(TokenIssuer::PROFILE_CLAIMS.keys)
        .to eq(%i[email given_name family_name nickname zoneinfo])
    end
  end

  describe "the public-safety gate is wired" do
    it "runs on pre-commit, on the commit message, and on pre-push" do
      lefthook = File.read("lefthook.yml")

      expect(lefthook).to include("check-public-safe --staged")
      expect(lefthook).to include("check-public-safe --message")
      expect(lefthook).to include("check-public-safe --all")
    end

    # A hook is advice: git commit --no-verify skips it. For a public repository
    # the real gate has to be in CI.
    it "also runs in CI, where --no-verify cannot reach" do
      ci = File.read(".github/workflows/ci.yml")

      expect(ci).to include("check-public-safe --all")
      expect(ci).to include("check-public-safe --history")
    end
  end
end
