# Example group containing the lan and opt1 interfaces
resource "opnsense_firewall_group" "resource_example" {
  name = "extended_lan"
  members = [
    "lan",
    "opt1"
  ]

  no_group    = true
  sequence    = 10
  description = "Group multiple lan interfaces"
}
