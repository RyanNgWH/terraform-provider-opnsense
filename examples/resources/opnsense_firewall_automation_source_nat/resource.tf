# Example firewall automation source nat rule
resource "opnsense_firewall_automation_filter" "test_acc_resource_filter" {
  enabled          = true
  no_nat           = false
  sequence         = 2
  interface        = "wan"
  ip_version       = "ipv4"
  protocol         = "tcp"
  source           = "1.1.1.1"
  source_not       = false
  source_port      = "ssh"
  destination      = "2.2.2.2"
  destination_not  = false
  destination_port = "ssh"
  target           = "3.3.3.3"
  target_port      = "ssh"
  log              = false
  categories = [
    "source_nat"
  ]
  description = "Example firewall automation source nat rule"
}
