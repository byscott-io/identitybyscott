# frozen_string_literal: true

# Per-client appearance for the hosted login page, with realm defaults.
#
# A jsonb column rather than a column per token, because the token set is a
# deliberately small CONTRACT and belongs stated in one place -- Theme -- where
# every value is validated and unknown keys are refused. Spreading it across a
# dozen nullable string columns on two tables would say less about what is valid
# and more about what happens to be storable.
#
# The logo is binary columns rather than jsonb or a URL:
#
#   * not jsonb, because a blob does not belong in a document column
#   * not a URL, because a remote host can swap the image later for something
#     misleading, and it would force a CSP exception for arbitrary image hosts.
#     Holding the bytes keeps img-src 'self'.
#   * not ActiveStorage, which is not loaded here (api_only, and the engine is
#     commented out). One small image is not worth the dependency in the process
#     that holds the signing key.
class AddLoginPageTheming < ActiveRecord::Migration[8.1]
  def change
    [ :clients, :realms ].each do |table|
      add_column table, :theme, :jsonb, null: false, default: {}

      # Served with nosniff and a locked-down CSP, and capped in the model. Only
      # raster types are accepted -- see Theme::LOGO_CONTENT_TYPES for why SVG is
      # refused rather than merely discouraged.
      add_column table, :theme_logo_data, :binary
      add_column table, :theme_logo_content_type, :string
    end
  end
end
