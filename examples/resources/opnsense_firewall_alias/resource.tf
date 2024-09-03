# Example alias referencing the opnsense website
resource "opnsense_firewall_alias" "resource_example" {
  enabled     = true
  name        = "opnsense_website"
  type        = "host"
  counters    = true
  description = "OPNsense main website"
  content = [
    "opnsense.org",
  ]
}
