source "https://rubygems.org"

# Bundle edge Rails instead: gem "rails", github: "rails/rails", branch: "main"
gem "rails", "~> 8.1.4"
# Use postgresql as the database for Active Record
gem "pg", "~> 1.1"
# Use the Puma web server [https://github.com/puma/puma]
gem "puma", ">= 5.0"

# Use Active Model has_secure_password [https://guides.rubyonrails.org/active_model_basics.html#securepassword]
# gem "bcrypt", "~> 3.1.7"

# Windows does not include zoneinfo files, so bundle the tzinfo-data gem
gem "tzinfo-data", platforms: %i[ windows jruby ]

# Use the database-backed adapters for Rails.cache, Active Job, and Action Cable
gem "solid_cache"
gem "solid_queue"

# Reduces boot times through caching; required in config/boot.rb
gem "bootsnap", require: false

# Add HTTP asset caching/compression and X-Sendfile acceleration to Puma [https://github.com/basecamp/thruster/]
gem "thruster", require: false

# Use Rack CORS for handling Cross-Origin Resource Sharing (CORS), making cross-origin Ajax possible
# gem "rack-cors"

group :development, :test do
  # See https://guides.rubyonrails.org/debugging_rails_applications.html#debugging-with-the-debug-gem
  gem "debug", platforms: %i[ mri windows ], require: "debug/prelude"

  # Audits gems for known security defects (use config/bundler-audit.yml to ignore issues)
  gem "bundler-audit", require: false

  # Static analysis for security vulnerabilities [https://brakemanscanner.org/]
  gem "brakeman", require: false

  # Omakase Ruby styling [https://github.com/rails/rubocop-rails-omakase/]
  gem "rubocop-rails-omakase", require: false
end

# Authentication. Devise is used for its MODEL modules only -- valid_password?,
# recoverable, confirmable, lockable. There is no devise_for, no Devise
# controller and no view: credential endpoints are this app's own API, and the
# forms live in each consuming app (or corebyscott, for the byscott fleet).
gem "devise", ">= 4.9"

# Token signing and verification. RS256 only -- a symmetric secret able to
# verify this server's tokens could also forge them.
gem "jwt", ">= 2.7"

# MFA: TOTP plus the QR code for enrollment.
gem "rotp", ">= 6.0"
gem "rqrcode", ">= 2.0"

# json 3.0 broke ActiveSupport::JSON.decode; pinned fleet-wide until Rails
# ships the fix.
gem "json", "< 3"

group :development, :test do
  gem "rspec-rails", "~> 8.0"
  gem "factory_bot_rails"
end
