# frozen_string_literal: true

# Turns a User-Agent into a readable browser / OS / device descriptor for the
# sessions list.
#
# A deliberate copy of corebyscott's equivalent, field for field, so that the
# sessions UI already shipped in core renders a session from this server without
# changes. It is a copy rather than a shared dependency because this server does
# not depend on the corebyscott gem -- a broken core release must not be able to
# take down the identity provider that every application's login runs through.
class UserAgentParser
  DEFAULT = {
    browser: "Unknown", browser_version: nil, os: "Unknown",
    device_type: "Desktop", is_mobile: false
  }.freeze

  class << self
    def parse(user_agent)
      return DEFAULT.dup if user_agent.blank?

      browser = Browser.new(user_agent)

      {
        browser: browser.known? ? browser.name : "Unknown",
        browser_version: (browser.version.to_s.split(".").first.presence if browser.known?),
        os: browser.platform.name.presence || "Unknown",
        device_type: device_type(browser),
        is_mobile: browser.device.mobile?
      }
    end

    # Masks the last octet. The sessions list exists so someone can recognise
    # their own devices, and a /24 is enough for that -- a full address is more
    # than the feature needs and more than is wise to render in a page.
    def mask_ip(ip)
      return nil if ip.blank?

      parts = ip.split(".")
      return ip unless parts.length == 4

      "#{parts[0..2].join('.')}.xxx"
    end

    private

    def device_type(browser)
      return "Bot" if browser.bot?
      return "Tablet" if browser.device.tablet?
      return "Mobile" if browser.device.mobile?

      "Desktop"
    end
  end
end
