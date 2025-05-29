# Example one-to-one NAT rule mapping
resource "opnsense_firewall_nat_one_to_one" "resource_example" {
  enabled         = true
  log             = true
  sequence        = 2
  interface       = "opt1"
  type            = "binat"
  source          = "10.2.72.1/32"
  source_not      = false
  destination     = "any"
  destination_not = false
  external        = "10.2.0.1"
  nat_reflection  = "default"
  description     = "Example one-to-one NAT mapping"
}
