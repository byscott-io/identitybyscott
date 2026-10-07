# frozen_string_literal: true

require "rails_helper"

# The appearance an application may give the hosted login page.
#
# Nothing renders these yet -- the page is the next slice. They are specced now
# because the security of the whole feature is in the VALIDATION, not the
# rendering: an application supplies values, this server renders the CSS, and a
# value that could carry anything else would make the rendering unsafe however
# carefully it was written.
#
# What a hostile token would buy, if any of these got through: hiding, moving or
# covering the password field, adding misleading text around the form, or leaking
# form state to a remote host through a selector.
RSpec.describe Theme do
  let(:realm) { create(:realm) }
  let(:client) { create(:client, realm: realm) }

  describe ".validate!" do
    it "accepts the documented tokens" do
      tokens = {
        display_name: "ChurchCare",
        primary_color: "#1F2937",
        background_color: "#f9fafb",
        surface_color: "#ffffff",
        text_color: "#111827",
        radius: "medium"
      }

      expect(described_class.validate!(tokens)).to include(
        "display_name" => "ChurchCare", "radius" => "medium"
      )
    end

    it "accepts an empty set" do
      expect(described_class.validate!({})).to eq({})
      expect(described_class.validate!(nil)).to eq({})
    end

    # Downcased so one colour has one stored form, and so the rendered CSS does
    # not vary with how somebody typed it.
    it "normalises a colour's case" do
      expect(described_class.validate!(primary_color: "#1F2937"))
        .to eq({ "primary_color" => "#1f2937" })
    end

    # Refusing unknown keys matters more than it looks: ignoring them would let
    # an application store whatever it liked here and leave a later renderer free
    # to start honouring it. The gap between "stored" and "rendered" is where a
    # token set stops being a contract.
    it "refuses an unknown key rather than ignoring it" do
      expect { described_class.validate!(custom_css: "body{}") }
        .to raise_error(described_class::InvalidToken, /unknown theme keys: custom_css/)
    end

    it "names every unknown key" do
      expect { described_class.validate!(a: 1, b: 2) }
        .to raise_error(described_class::InvalidToken, /a, b/)
    end

    # Each of these is a way a colour value could stop being only a colour. They
    # are refused by the PATTERN rather than escaped at render, so there is
    # nothing to get wrong later.
    {
      "a CSS escape out of the declaration" => "#fff; } body { display: none",
      "a url() fetch" => "url(https://attacker.test/x)",
      "a CSS variable reference" => "var(--x)",
      "a named colour" => "red",
      "three-digit shorthand" => "#fff",
      "eight-digit with alpha" => "#ffffffff",
      "rgb() notation" => "rgb(255,255,255)",
      "a missing hash" => "1f2937",
      "trailing content" => "#1f2937 !important",
      "a newline" => "#1f2937\n",
      "an expression" => "expression(alert(1))",
      "empty" => ""
    }.each do |description, value|
      it "refuses #{description} as a colour" do
        expect { described_class.validate!(primary_color: value) }
          .to raise_error(described_class::InvalidToken)
      end
    end

    it "refuses a radius outside the enum" do
      expect { described_class.validate!(radius: "9999px") }
        .to raise_error(described_class::InvalidToken, /must be one of/)
    end

    # An enum rather than a number, so there is no unit to smuggle anything
    # through and no arithmetic to clamp.
    it "refuses a numeric radius, even a sane one" do
      expect { described_class.validate!(radius: "8") }
        .to raise_error(described_class::InvalidToken)
    end

    # It is escaped at render, but a four-thousand-character name is a layout
    # attack even when it cannot be a script one.
    it "caps the display name" do
      expect { described_class.validate!(display_name: "x" * 61) }
        .to raise_error(described_class::InvalidToken, /60 characters/)
    end

    it "refuses a blank display name rather than storing an empty one" do
      expect { described_class.validate!(display_name: "   ") }
        .to raise_error(described_class::InvalidToken, /cannot be blank/)
    end

    it "trims a display name" do
      expect(described_class.validate!(display_name: "  ChurchCare  "))
        .to eq({ "display_name" => "ChurchCare" })
    end
  end

  describe ".resolve" do
    it "falls back to this server's defaults when nothing is set" do
      expect(described_class.resolve(client)).to eq(described_class::DEFAULTS)
    end

    it "prefers the realm's tokens over the defaults" do
      realm.update!(theme: { "primary_color" => "#aa0000" })

      expect(described_class.resolve(client)[:primary_color]).to eq("#aa0000")
    end

    it "prefers the client's tokens over the realm's" do
      realm.update!(theme: { "primary_color" => "#aa0000" })
      client.update!(theme: { "primary_color" => "#00aa00" })

      expect(described_class.resolve(client.reload)[:primary_color]).to eq("#00aa00")
    end

    # Merged per key, not wholesale. A client that sets one colour must keep its
    # realm's other three rather than silently reverting them to the default --
    # which is what a whole-hash override would do.
    it "keeps the realm's other tokens when a client overrides one" do
      realm.update!(theme: { "primary_color" => "#aa0000", "text_color" => "#222222" })
      client.update!(theme: { "primary_color" => "#00aa00" })

      resolved = described_class.resolve(client.reload)

      expect(resolved[:primary_color]).to eq("#00aa00")
      expect(resolved[:text_color]).to eq("#222222")
    end

    it "resolves every key, so the renderer never meets a missing one" do
      expect(described_class.resolve(client).keys).to match_array(described_class::DEFAULTS.keys)
    end
  end

  describe ".resolve_logo" do
    let(:png) { "\x89PNG\r\n\x1a\n#{'x' * 64}".b }

    it "is nil when neither client nor realm has one" do
      expect(described_class.resolve_logo(client)).to be_nil
    end

    it "uses the realm's when the client has none" do
      realm.update!(theme_logo_data: png, theme_logo_content_type: "image/png")

      expect(described_class.resolve_logo(client.reload)).to eq(realm)
    end

    it "prefers the client's own" do
      realm.update!(theme_logo_data: png, theme_logo_content_type: "image/png")
      client.update!(theme_logo_data: png, theme_logo_content_type: "image/webp")

      expect(described_class.resolve_logo(client.reload)).to eq(client)
    end
  end

  describe ".validate_logo!" do
    let(:png) { "\x89PNG\r\n\x1a\n".b }

    it "accepts the raster types" do
      described_class::LOGO_CONTENT_TYPES.each do |type|
        expect(described_class.validate_logo!(data: png, content_type: type)).to be(true)
      end
    end

    # An SVG is a document, not an image: it can carry script, and while that
    # script does not run through an <img> tag it does run if the file is opened
    # directly. Refusing the type is one rule; relying on every future consumer
    # to use the right tag is not.
    it "refuses SVG, and says why" do
      expect { described_class.validate_logo!(data: "<svg/>", content_type: "image/svg+xml") }
        .to raise_error(described_class::InvalidToken, /SVG is refused/)
    end

    it "refuses anything that is not an accepted image type" do
      [ "text/html", "application/pdf", "image/gif", "application/javascript" ].each do |type|
        expect { described_class.validate_logo!(data: png, content_type: type) }
          .to raise_error(described_class::InvalidToken)
      end
    end

    it "refuses an oversized logo" do
      oversized = "x" * (described_class::MAX_LOGO_BYTES + 1)

      expect { described_class.validate_logo!(data: oversized, content_type: "image/png") }
        .to raise_error(described_class::InvalidToken, /bytes or fewer/)
    end

    it "refuses an empty one" do
      expect { described_class.validate_logo!(data: "", content_type: "image/png") }
        .to raise_error(described_class::InvalidToken, /empty/)
    end
  end

  # Validated on the way in, so an invalid token cannot be stored and then
  # discovered at render time. On a login page a render-time failure is a login
  # nobody can complete.
  describe "stored on a record" do
    it "refuses to save an unknown key on a client" do
      client.theme = { "custom_css" => "body{}" }

      expect(client).not_to be_valid
      expect(client.errors[:theme].join).to match(/unknown theme keys/)
    end

    it "refuses to save a bad colour on a realm" do
      realm.theme = { "primary_color" => "red" }

      expect(realm).not_to be_valid
    end

    it "cannot be bypassed with update!" do
      expect { client.update!(theme: { "primary_color" => "#fff; }" }) }
        .to raise_error(ActiveRecord::RecordInvalid)
    end

    it "refuses a logo of the wrong type on save" do
      client.theme_logo_data = "<svg/>"
      client.theme_logo_content_type = "image/svg+xml"

      expect(client).not_to be_valid
    end

    it "allows no logo at all" do
      expect(client).to be_valid
    end

    # The spec I should have written first. validate! returning a normalised
    # hash is worth nothing if nothing assigns it back -- which was the bug, and
    # only running the rake task showed it, because the function's own spec
    # passed throughout.
    it "stores the normalised value, not what was typed" do
      client.update!(theme: { "primary_color" => "#00AA00" })

      expect(client.reload.theme["primary_color"]).to eq("#00aa00")
    end

    it "stores a trimmed display name" do
      client.update!(theme: { "display_name" => "  ChurchCare  " })

      expect(client.reload.theme["display_name"]).to eq("ChurchCare")
    end

    it "normalises on a realm too" do
      realm.update!(theme: { "text_color" => "#ABCDEF" })

      expect(realm.reload.theme["text_color"]).to eq("#abcdef")
    end

    it "defaults to an empty token set rather than null" do
      expect(create(:client).theme).to eq({})
      expect(create(:realm).theme).to eq({})
    end
  end
end
