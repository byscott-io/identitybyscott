# frozen_string_literal: true

# The appearance an application may give the hosted login page.
#
# == Tokens, never CSS
#
# An application supplies validated VALUES, which this server renders into CSS
# custom properties itself. It never supplies CSS, a stylesheet URL or markup.
# The difference is the whole security of the feature:
#
#   * CSS can hide, move or cover the password field, which is the one thing a
#     login page must not let a third party do
#   * `content:` can add misleading text around the form
#   * attribute and state selectors can leak form state to a remote host
#
# So every value here is PARSED AND RE-EMITTED rather than interpolated. A
# colour that does not satisfy #rrggbb is refused when it is configured, not
# escaped when it is rendered -- there is no way out of
# `--primary: #ff0000;` when the value cannot contain anything else.
#
# == And never from the request
#
# These live on the Client record. They are never read from a query parameter,
# for the same reason the realm never is: anything an application can put in a
# URL, anyone can put in a URL, and a login page restyled by a link is a login
# page that can be made to look like something else.
#
# == What is deliberately not themeable
#
# The form, its fields and labels, the submit button, and the page's structure.
# Applications control the chrome. Nothing here can reposition, conceal or
# overlay the thing the password is typed into.
class Theme
  COLOR_KEYS = %i[primary_color background_color surface_color text_color].freeze

  # An enum rather than a number with a unit, so there is no arithmetic to clamp
  # and no unit string to smuggle anything through. The CSS values these map to
  # are this server's, not the client's.
  RADII = %w[none small medium large].freeze

  # Shown on the login page, so it is capped and escaped at render. The cap is
  # here because a four-thousand-character "name" is a layout attack even when
  # it cannot be a script one.
  MAX_DISPLAY_NAME = 60

  KEYS = ([ :display_name, :radius ] + COLOR_KEYS).freeze

  # Raster only. An SVG is a document, not an image: it can carry script, and
  # while that script does not run through an <img> tag it does run if the file
  # is ever opened directly -- which a logo URL invites. Refusing the type is one
  # rule; relying on every future consumer to use the right tag is not.
  LOGO_CONTENT_TYPES = %w[image/png image/jpeg image/webp].freeze

  # Small enough to sit in a row and be served inline. A logo that needs more
  # than this is not a logo.
  MAX_LOGO_BYTES = 64 * 1024

  COLOR_PATTERN = /\A#[0-9a-f]{6}\z/i

  class InvalidToken < StandardError; end

  # Validates and normalises a token hash, or raises.
  #
  # UNKNOWN KEYS ARE REFUSED, which matters more than it looks. Ignoring them
  # would let an application carry whatever it liked in this column and leave a
  # later renderer free to start honouring it -- the gap between "stored" and
  # "rendered" is exactly where a token set stops being a contract.
  def self.validate!(tokens)
    tokens = (tokens || {}).transform_keys(&:to_sym)

    unknown = tokens.keys - KEYS
    raise InvalidToken, "unknown theme keys: #{unknown.join(', ')}" if unknown.any?

    tokens.to_h do |key, value|
      [ key.to_s, normalise(key, value) ]
    end
  end

  # The tokens in force for a client: its own, over its realm's, over this
  # server's own plain defaults.
  #
  # Merged per KEY rather than wholesale, so a client that sets one colour keeps
  # its realm's other three instead of silently reverting them to the default.
  def self.resolve(client)
    DEFAULTS
      .merge(symbolize(client.realm.theme))
      .merge(symbolize(client.theme))
  end

  # The logo in force, likewise falling back to the realm's. Returns nil when
  # neither has one, and the page shows the display name instead.
  def self.resolve_logo(client)
    [ client, client.realm ].each do |record|
      return record if record.theme_logo_data.present? && record.theme_logo_content_type.present?
    end

    nil
  end

  DEFAULTS = {
    display_name: nil,
    primary_color: "#1f2937",
    background_color: "#f9fafb",
    surface_color: "#ffffff",
    text_color: "#111827",
    radius: "medium"
  }.freeze

  def self.validate_logo!(data:, content_type:)
    unless LOGO_CONTENT_TYPES.include?(content_type)
      raise InvalidToken,
            "logo must be one of #{LOGO_CONTENT_TYPES.join(', ')} " \
            "(SVG is refused: it is a document that can carry script)"
    end

    if data.to_s.bytesize > MAX_LOGO_BYTES
      raise InvalidToken, "logo must be #{MAX_LOGO_BYTES} bytes or fewer"
    end

    raise InvalidToken, "logo is empty" if data.to_s.empty?

    true
  end

  def self.normalise(key, value)
    case key
    when :display_name then normalise_display_name(value)
    when :radius then normalise_radius(value)
    when *COLOR_KEYS then normalise_color(key, value)
    end
  end
  private_class_method :normalise

  # Downcased so two spellings of one colour are one stored value, and because
  # the rendered CSS should not vary with how it was typed.
  def self.normalise_color(key, value)
    unless value.to_s.match?(COLOR_PATTERN)
      raise InvalidToken, "#{key} must be a hex colour like #1f2937, got #{value.inspect}"
    end

    value.to_s.downcase
  end
  private_class_method :normalise_color

  def self.normalise_radius(value)
    unless RADII.include?(value.to_s)
      raise InvalidToken, "radius must be one of #{RADII.join(', ')}, got #{value.inspect}"
    end

    value.to_s
  end
  private_class_method :normalise_radius

  def self.normalise_display_name(value)
    name = value.to_s.strip
    raise InvalidToken, "display_name cannot be blank" if name.empty?

    if name.length > MAX_DISPLAY_NAME
      raise InvalidToken, "display_name must be #{MAX_DISPLAY_NAME} characters or fewer"
    end

    name
  end
  private_class_method :normalise_display_name

  def self.symbolize(tokens)
    (tokens || {}).to_h { |key, value| [ key.to_sym, value ] }.compact
  end
  private_class_method :symbolize
end
