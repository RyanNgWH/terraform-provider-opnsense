# Example firewall automation filter rule
resource "opnsense_firewall_automation_filter" "test_acc_resource_filter" {
  enabled  = true
  sequence = 10
  action   = "pass"
  quick    = true
  interfaces = [
    "lan",
    "wan"
  ]
  direction        = "in"
  ip_version       = "ipv4"
  protocol         = "tcp"
  source           = "any"
  source_not       = false
  source_port      = "ssh"
  destination      = "perm_test_acc_alias"
  destination_not  = false
  destination_port = "ssh"
  gateway          = "WAN_GW"
  log              = true
  categories = [
    "automation"
  ]
  description = "Example firewall automation filter rule"
}
