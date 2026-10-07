# frozen_string_literal: true

# Renders an application's appearance tokens into CSS custom properties.
#
# The ONLY place a client-supplied value reaches a stylesheet, and it re-checks
# every one on the way out even though Theme already validated them on the way
# in. That is deliberate belt and braces rather than distrust of Theme: a value
# could reach the column by a route that skips validation -- a migration, a
# console, a future bulk import -- and the consequence of a bad one here is CSS
# injection on the login page. A renderer that refuses what it cannot recognise
# fails to a plain page instead.
class ThemeCss
  # This server's values, not the client's. The client picks a NAME from an
  # enum; the geometry is ours.
  RADII = {
    "none" => "0",
    "small" => "4px",
    "medium" => "8px",
    "large" => "16px"
  }.freeze

  def self.for(client)
    new(Theme.resolve(client)).to_s
  end

  def initialize(tokens)
    @tokens = tokens
  end

  # Only custom properties, so nothing here can introduce a selector, a rule or
  # an at-rule. The stylesheet that USES them is this server's own and fixed.
  def to_s
    <<~CSS.strip
      :root {
        --identity-primary: #{color(:primary_color)};
        --identity-background: #{color(:background_color)};
        --identity-surface: #{color(:surface_color)};
        --identity-text: #{color(:text_color)};
        --identity-radius: #{radius};
      }
    CSS
  end

  private

  def color(key)
    value = @tokens[key].to_s

    return value.downcase if value.match?(Theme::COLOR_PATTERN)

    # Unrecognised: fall back rather than emit it. The default is known-good and
    # a slightly wrong colour is a better outcome than a styled page that is not
    # ours.
    Theme::DEFAULTS.fetch(key)
  end

  def radius
    RADII.fetch(@tokens[:radius].to_s, RADII.fetch("medium"))
  end
end
