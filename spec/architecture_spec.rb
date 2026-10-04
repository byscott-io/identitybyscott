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

  describe "the deploy configuration names no infrastructure" do
    # The file most likely to acquire a hostname during a hurried fix, in the
    # one repository where that cannot happen.
    it "reads the host, user, key and registry from the environment" do
      kamal = File.read(".kamal/deploy.yml")

      expect(kamal).to include('ENV["DEPLOY_HOST"]')
      expect(kamal).to include('ENV["DEPLOY_SSH_USER"]')
      expect(kamal).to include('ENV["DEPLOY_SSH_KEY"]')
      expect(kamal).to match(/DEPLOY_REGISTRY_ACCOUNT/)
    end

    it "lists application settings as secret NAMES, not values" do
      kamal = YAML.safe_load(ERB.new(File.read(".kamal/deploy.yml")).result, aliases: true)

      expect(kamal.dig("env", "secret")).to include("IDENTITY_SIGNING_KEY", "DATABASE_URL")
      expect(kamal.dig("env", "clear").keys).not_to include("IDENTITY_SIGNING_KEY")
    end

    # Deploys serialise fleet-wide through this group. An application that
    # deployed outside it would race the host's container store.
    it "joins the shared deploy concurrency group" do
      expect(File.read(".github/workflows/deploy.yml")).to include("group: deploy-byscott-host")
    end

    it "is dispatch-only, so nothing deploys on a push" do
      workflow = YAML.safe_load(File.read(".github/workflows/deploy.yml"))

      expect(workflow[true] || workflow["on"]).to eq("workflow_dispatch" => nil)
    end
  end

  describe "no workflow exposes secrets to untrusted input" do
    # This is what actually protects the secrets in a public repository, and it
    # is the one thing that was being trusted to memory.
    #
    # GitHub never passes secrets to a fork's pull_request run, so the danger is
    # not today's workflows -- it is a future one that reads a secret while
    # triggering on something an outsider controls. pull_request_target and
    # workflow_run run in the BASE repository's context with secrets available;
    # issue_comment fires on anyone's comment.
    UNTRUSTED_TRIGGERS = %w[pull_request_target issue_comment workflow_run issues].freeze

    let(:workflows) { Dir[".github/workflows/*.yml"] }

    it "finds the workflows" do
      expect(workflows).not_to be_empty
    end

    it "uses no untrusted trigger anywhere" do
      offenders = workflows.select do |path|
        triggers = YAML.safe_load(File.read(path)).then { |y| y[true] || y["on"] }
        keys = triggers.is_a?(Hash) ? triggers.keys.map(&:to_s) : Array(triggers).map(&:to_s)
        keys.intersect?(UNTRUSTED_TRIGGERS)
      end

      expect(offenders).to be_empty,
                           "these run on input an outsider controls: #{offenders}"
    end

    it "keeps secrets out of every workflow that an outsider can trigger" do
      offenders = workflows.select do |path|
        content = File.read(path)
        triggers = YAML.safe_load(content).then { |y| y[true] || y["on"] }
        keys = triggers.is_a?(Hash) ? triggers.keys.map(&:to_s) : Array(triggers).map(&:to_s)

        keys.include?("pull_request") && content.match?(/secrets\./)
      end

      expect(offenders).to be_empty,
                           "a pull_request workflow must reference no secrets: #{offenders}"
    end

    it "never interpolates a secret directly into a run block" do
      # Values reach the shell through env:, so only NAMES appear in the
      # world-readable run log. GitHub masks secrets, but only on exact
      # matches, so a transformed value would slip through.
      # Parsed rather than line-matched: an env: mapping carrying a secret is
      # the CORRECT pattern, so a regex over lines flags the fix as the fault.
      offenders = Dir[".github/workflows/*.yml"].select do |path|
        YAML.safe_load(File.read(path), aliases: true)
            .fetch("jobs", {})
            .values
            .flat_map { |job| job["steps"].to_a }
            .any? { |step| step["run"].to_s.match?(/\$\{\{\s*secrets\./) }
      end

      expect(offenders).to be_empty,
                           "pass secrets via env:, not inline in run: #{offenders}"
    end

    it "does not use the org-wide packages token" do
      # GH_TOKEN carries write:packages, which could publish a poisoned package
      # that every application installs. A public repository gets a read-only
      # credential of its own.
      offenders = workflows.select { |path| File.read(path).include?("secrets.GH_TOKEN") }

      expect(offenders).to be_empty,
                           "use a read:packages-only token instead of org GH_TOKEN: #{offenders}"
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
