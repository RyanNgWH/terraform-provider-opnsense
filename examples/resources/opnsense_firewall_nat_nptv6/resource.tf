# Example NPTv6 NAT rule mapping
resource "opnsense_firewall_nat_nptv6" "resource_example" {
  enabled         = true
  log             = true
  sequence        = 1
  interface       = "lan"
  internal_prefix = "1::"
  external_prefix = "1::"
  categories = [
    "example_category"
  ]
  description = "Example NPTv6 nat rule"
}
