# Example captive portal template
resource "opnsense_captive_portal_templates" "example_captive_portal_template" {
  name          = "example_template"
  template      = "assets/captive-portal-template-default.zip"
  template_hash = filesha512("assets/captive-portal-template-default.zip")
}
