# Example traffic shaper pipe
resource "opnsense_firewall_shaper_pipes" "example_shaper_pipe" {
  enabled = true
  bandwidth = {
    value  = 10
    metric = "Kbit"
  }
  queue     = 10
  mask      = "src-ip"
  buckets   = 10
  scheduler = "deficit round robin"
  codel = {
    enabled  = true
    target   = 10
    interval = 10
    ecn      = true
    quantum  = 10
    limit    = 10
    flows    = 10
  }
  pie         = false
  delay       = 10
  description = "Example traffic shaper pipe"
}