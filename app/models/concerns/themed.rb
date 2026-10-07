# frozen_string_literal: true

# Holds the login page's appearance tokens, for a Client or a Realm.
#
# One concern rather than the same validations written twice, because the two
# differ only in which one wins: a client's tokens override its realm's, and
# the realm's override this server's defaults. See Theme.
module Themed
  extend ActiveSupport::Concern

  included do
    # Validated on the way IN, so an invalid token cannot be stored and then
    # discovered at render time. On a login page a render-time failure is a login
    # nobody can complete, which is a worse outcome than a rejected rake task.
    #
    # Theme.validate! raises rather than returning false -- it is reached from a
    # rake task where a precise message is the whole value -- and the exception
    # is translated here so an update! from anywhere else cannot bypass it.
    # Normalised on the way in as well as validated, so what is STORED is the
    # canonical form -- a colour typed as #00AA00 is saved as #00aa00.
    #
    # This was a real bug: Theme.validate! returned a normalised hash and
    # nothing assigned it back, so validation passed on the uppercase value and
    # the uppercase value was what got stored. The specs covered the function
    # rather than the path, and only running the rake task showed it.
    before_validation :normalise_theme_tokens

    validate :theme_tokens_are_valid
    validate :theme_logo_is_valid
  end

  def theme_tokens
    theme || {}
  end

  def theme_logo?
    theme_logo_data.present? && theme_logo_content_type.present?
  end

  private

  # Silent on a bad token: the validation below is what reports it. Raising here
  # would abort the save with an exception instead of a validation error, and the
  # rake tasks report errors.
  def normalise_theme_tokens
    self.theme = Theme.validate!(theme_tokens)
  rescue Theme::InvalidToken
    nil
  end

  def theme_tokens_are_valid
    Theme.validate!(theme_tokens)
  rescue Theme::InvalidToken => e
    errors.add(:theme, e.message)
  end

  def theme_logo_is_valid
    return if theme_logo_data.blank? && theme_logo_content_type.blank?

    Theme.validate_logo!(data: theme_logo_data, content_type: theme_logo_content_type)
  rescue Theme::InvalidToken => e
    errors.add(:theme_logo_data, e.message)
  end
end
