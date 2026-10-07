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
  # Rails' rate limiter answers a bare `head :too_many_requests` by default --
  # no body at all. Every other failure here returns JSON, so a client parses
  # the body unconditionally and gets a parse error instead of a rate-limit
  # error.
  #
  # Checked here rather than as a request spec because the limiters cannot fire
  # in test: `store:` defaults to `cache_store`, evaluated when the class is
  # defined, and the test environment is :null_store -- `increment` returns nil,
  # so the limit is never reached. A spec that drove a real limiter would
  # therefore pass whether or not the response was fixed. This asserts the
  # declaration instead, which is the part that can regress.
  describe "every rate limiter returns a parseable body" do
    let(:controller_sources) do
      Dir[Rails.root.join("app/controllers/**/*.rb")].to_h { |path| [ path, File.read(path) ] }
    end

    it "declares with: on every rate_limit" do
      missing = controller_sources.flat_map do |path, source|
        # Each declaration spans the rate_limit line and its with: continuation.
        source.scan(/rate_limit to:.*?(?=\n\s*(?:rate_limit|def |#|end\b))/m)
              .reject { |declaration| declaration.include?("with:") }
              .map { |declaration| "#{Pathname.new(path).relative_path_from(Rails.root)}: #{declaration[0, 60]}" }
      end

      expect(missing).to be_empty
    end

    it "renders JSON and a Retry-After header" do
      controller = Api::BaseController.new
      controller.set_request!(ActionDispatch::TestRequest.create)
      controller.set_response!(Api::BaseController.make_response!(controller.request))

      controller.send(:rate_limited!, retry_after: 1.minute)

      expect(controller.response.status).to eq(429)
      expect(controller.response.get_header("Retry-After")).to eq("60")
      expect(JSON.parse(controller.response.body)).to include("error" => "Too many requests")
    end
  end

  # A church hall, an office or a school is one public address, so a per-IP
  # signup limit is a limit on the whole building -- the sixth person in a group
  # signing up together was refused. The pairing is what makes a generous IP
  # figure affordable, so it is the pairing that must not quietly revert.
  describe "signup is not limited by IP alone" do
    let(:source) { File.read(Rails.root.join("app/controllers/api/registrations_controller.rb")) }

    it "limits by address as well as by IP" do
      expect(source).to match(/rate_limit to: \d+, within: [\w.]+, by: -> \{ request\.remote_ip \}/)
      expect(source).to match(/rate_limit to: \d+, within: [\w.]+, by: -> \{ params\[:email\]/)
    end
  end

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

    # The SSO surface is the one exception, and it is explicit rather than
    # incidental.
    #
    # /authorize cannot take client_id from the path: there is no CORS preflight
    # on a top-level navigation, and discovery publishes ONE
    # authorization_endpoint, which a per-client path could not be. So it reads
    # the query string -- but it names that source, rather than relying on
    # `params` to merge path, query and body in the order it happens to.
    it "reads it from the query string explicitly on the SSO surface" do
      source = self.class.code_without_comments("app/controllers/sso/authorizations_controller.rb")

      expect(source).to include("request.query_parameters")
      expect(source).not_to match(/\bparams\[/)
    end
  end

  describe "API only" do
    it "is configured api_only" do
      expect(Rails.application.config.api_only).to be(true)
    end

    it "descends from ActionController::API" do
      expect(ApplicationController.superclass).to eq(ActionController::API)
    end

    # The cookie middleware came back for exactly one cookie -- the single
    # sign-on session -- and brought nothing else with it.
    #
    # A session store or flash would reintroduce an ambient credential for the
    # API, and with it the need for CSRF protection. The SSO cookie does not,
    # because it is path-scoped to /sso: the browser never attaches it to an
    # /api request, so a call there still cannot carry anything the caller did
    # not deliberately attach.
    it "has the cookie middleware but no session store or flash" do
      stack = Rails.application.middleware.map { |m| m.klass.to_s }
      ambient = stack.grep(/Session|Flash/)

      expect(stack.grep(/Cookies/)).not_to be_empty
      expect(ambient).to be_empty, "a session or flash reintroduces CSRF: #{ambient}"
    end

    # One cookie, written in one place. The attributes that make it safe --
    # HttpOnly, SameSite, the path scope, no Domain -- are stated once in
    # SsoCookie, and a second writer elsewhere would be a second, unreviewed
    # set of them.
    it "writes cookies from SsoCookie and nowhere else" do
      writers = Dir["app/**/*.rb"].reject { |path| path.end_with?("concerns/sso_cookie.rb") }
                                  .select do |path|
        File.read(path).match?(/cookies\s*\[[^\]]+\]\s*=|(?:set|delete)_cookie/)
      end

      expect(writers).to be_empty, "the SSO cookie's attributes are stated once: #{writers}"
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
      # The trigger KEYS are the property, not the value shape -- an earlier
      # version asserted workflow_dispatch mapped to nil and broke the moment
      # the required no_cache input was declared.
      workflow = YAML.safe_load(File.read(".github/workflows/deploy.yml"))
      triggers = (workflow[true] || workflow["on"])

      expect(triggers.keys).to eq([ "workflow_dispatch" ])
    end

    # The fleet's DeployService always sends a no_cache input, and a workflow
    # declaring none is rejected with HTTP 422 before it ever starts.
    it "declares the no_cache input the deploy service sends" do
      workflow = YAML.safe_load(File.read(".github/workflows/deploy.yml"))
      inputs = (workflow[true] || workflow["on"]).dig("workflow_dispatch", "inputs")

      expect(inputs.keys).to include("no_cache")
    end

    # GitHub concurrency groups are scoped PER REPOSITORY, so the shared group
    # name does not serialise across repositories. The host-side flock is what
    # actually prevents two deploys racing containerd's content store.
    it "takes the host-side deploy lock" do
      expect(File.read(".github/workflows/deploy.yml")).to include("/var/lock/byscott-deploy")
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

    # NARROWED, deliberately, after it blocked adding the PR review to this
    # repository -- the one holding every password in the fleet, and the only
    # one that had no code review at all.
    #
    # The old rule said a pull_request workflow may reference NO secrets. That
    # is stricter than the threat. GitHub does not pass secrets to a fork's
    # pull_request run, so a secret there is reachable only by someone who
    # already has write access. The ban above -- pull_request_target,
    # issue_comment, workflow_run, issues -- is what actually protects
    # anything, because those run in the BASE repository's context on input an
    # outsider controls.
    #
    # So a secret may reach a pull_request workflow, but ONLY by being handed to
    # a reusable workflow through `secrets:`. A `run:` block is arbitrary code,
    # and a secret reaching one on a pull-request trigger is the shape that
    # leaks: this repository's run logs are world-readable, masking is
    # exact-match only, and a transformed value slips straight through.
    it "allows secrets into a pull_request workflow only via a reusable workflow" do
      offenders = workflows.select do |path|
        parsed = YAML.safe_load(File.read(path), aliases: true)
        triggers = parsed[true] || parsed["on"]
        keys = triggers.is_a?(Hash) ? triggers.keys.map(&:to_s) : Array(triggers).map(&:to_s)
        next false unless keys.include?("pull_request")

        parsed.fetch("jobs", {}).values.any? do |job|
          job["steps"].to_a.any? do |step|
            [ step["run"].to_s, step["env"].to_h.values.join(" ") ].any? { |v| v.include?("secrets.") }
          end
        end
      end

      expect(offenders).to be_empty,
                           "a pull_request workflow may pass secrets to a reusable workflow, but " \
                           "must not put one in a step's run or env: #{offenders}"
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
