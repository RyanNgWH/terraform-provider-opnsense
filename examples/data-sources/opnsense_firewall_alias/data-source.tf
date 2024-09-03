# Get alias as data source via it's uuid
data "opnsense_firewall_alias" "data_source_via_id" {
  id = "409e6cfa-35ef-4f0b-996c-2cf477dc42a0"
}

# Get alias as data source via it's name
data "opnsense_firewall_alias" "data_source_via_name" {
  name = "alias_name"
}
