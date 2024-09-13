---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "opnsense_firewall_group Resource - opnsense"
subcategory: ""
description: |-
  To simplify rulesets, you can combine interfaces into Interface Groups and add policies which will be applied to all interfaces in the group.
---

# opnsense_firewall_group (Resource)

To simplify rulesets, you can combine interfaces into Interface Groups and add policies which will be applied to all interfaces in the group.

## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `members` (List of String) Member interfaces of the group. Use the interface identifiers (e.g `lan`, `opt1`) Ensure that the interfaces are in lexicographical order, else the provider will detect a change on every execution.
- `name` (String) The name of the group

### Optional

- `description` (String) The description of the group
- `no_group` (Boolean) If grouping these members in the interfaces menu section should be prevented. Defaults to `false`.
- `sequence` (Number) Priority sequence used in sorting the groups. Defaults to `0`.

### Read-Only

- `id` (String) Identifier of the group
- `last_updated` (String) DateTime when group was last updated

## Import

Import is supported using the following syntax:

```shell
# Groups can be imported by specifying the group name.
terraform import opnsense_firewall_group.import_example extended_lan
```