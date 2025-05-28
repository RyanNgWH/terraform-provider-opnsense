# Example traffic shaper rule
resource "opnsense_firewall_shaper_rules" "example_shaper_rule" {
  enabled           = true
  sequence          = 10
  interface         = "wan"
  interface2        = "lan"
  protocol          = "igmp"
  max_packet_length = 255
  sources = [
    "1.1.1.1",
    "2.2.2.2"
  ]
  source_not  = false
  source_port = "ssh"
  destinations = [
    "any",
  ]
  destination_not  = false
  destination_port = "http"
  dscp = [
    "af11",
    "best effort"
  ]
  direction   = "in"
  target      = "de21d36c-bd97-4477-9c2d-c4a8f23818d0"
  description = "Example traffic shaper rule"
}
