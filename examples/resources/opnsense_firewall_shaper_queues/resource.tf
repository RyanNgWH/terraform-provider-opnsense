# Example traffic shaper queue
resource "opnsense_firewall_shaper_queues" "example_shaper_queue" {
  enabled = true
  pipe    = "de21d36c-bd97-4477-9c2d-c4a8f23818d0"
  weight  = 10
  mask    = "src-ip"
  buckets = 10
  codel = {
    enabled  = true
    target   = 10
    interval = 10
    ecn      = true
  }
  pie         = false
  description = "Example traffic shaper queue"
}