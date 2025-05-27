# Get traffic shaper queue as data source via it's uuid
data "opnsense_firewall_shaper_queues" "data_source_via_id" {
  id = "5b034f00-d4b3-4eba-82d6-d74fce5f149b"
}