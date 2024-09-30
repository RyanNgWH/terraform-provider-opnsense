# Get group as data source via it's uuid
data "opnsense_firewall_group" "data_source_via_id" {
  id = "b541fbd8-1020-40cf-9900-c7f955979a69"
}

# Get group as data source via it's name
data "opnsense_firewall_group" "data_source_via_name" {
  name = "group_name"
}
