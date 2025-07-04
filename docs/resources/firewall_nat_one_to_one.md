---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "opnsense_firewall_nat_one_to_one Resource - opnsense"
subcategory: ""
description: |-
  One-to-one NAT will translate two IPs one-to-one, rather than one-to-many as is most common.
---

# opnsense_firewall_nat_one_to_one (Resource)

One-to-one NAT will translate two IPs one-to-one, rather than one-to-many as is most common.

## Example Usage

```terraform
# Example one-to-one NAT rule mapping
resource "opnsense_firewall_nat_one_to_one" "resource_example" {
  enabled         = true
  log             = true
  sequence        = 2
  interface       = "opt1"
  type            = "binat"
  source          = "10.2.72.1/32"
  source_not      = false
  destination     = "any"
  destination_not = false
  external        = "10.2.0.1"
  nat_reflection  = "default"
  description     = "Example one-to-one NAT mapping"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `destination` (String) The 1:1 mapping will only be used for connections to or from the specified destination. Can be a single network/host, alias or predefined network. For interface addresses, add `ip` to the end of the interface name (e.g `opt1ip`).
- `external` (String) The external subnet's starting address for the 1:1 mapping or network. This is the address or network the traffic will translate to/from.
- `interface` (String) The interface this rule applies to.
- `source` (String) The internal subnet for this 1:1 mapping. Can be a single network/host, alias or predefined network. For interface addresses, add `ip` to the end of the interface name (e.g `opt1ip`).
- `type` (String) The type of the nat rule. Must be one of: `nat`, `binat`

### Optional

- `categories` (Set of String) The categories of the rule.
- `description` (String) The description of the rule.
- `destination_not` (Boolean) Whether the destination matching should be inverted. Defaults to `false`.
- `enabled` (Boolean) Whether the one-to-one nat entry is enabled. Defaults to `true`.
- `log` (Boolean) Whether packets that are handled by this rule should be logged. Defaults to `false`.
- `nat_reflection` (String) Whether nat reflection should be enabled. Must be one of: `default`, `enable`, `disable`. Defaults to `default`.
- `sequence` (Number) Order in which multiple matching rules are evaluated and applied. Defaults to `1`.
- `source_not` (Boolean) Whether the source matching should be inverted. Defaults to `false`.

### Read-Only

- `id` (String) Identifier of the one-to-one NAT rule.
- `last_updated` (String) DateTime when the one-to-one NAT rule entry was last updated.

## Import

Import is supported using the following syntax:

```shell
# One-to-one NAT rules can be imported by specifying the rule UUID. This can be found by examining the API calls on the OPNsense web interface
terraform import opnsense_firewall_nat_one_to_one.import_example 7ce41c23-968c-46f2-9b6b-3c9a1519086f
```
