---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "opnsense_firewall_category Resource - opnsense"
subcategory: ""
description: |-
  To ease maintenance of larger rulesets, OPNsense includes categories for the firewall. Each rule can contain one or more categories, which can be filtered on top of each firewall rule page.
---

# opnsense_firewall_category (Resource)

To ease maintenance of larger rulesets, OPNsense includes categories for the firewall. Each rule can contain one or more categories, which can be filtered on top of each firewall rule page.

## Example Usage

```terraform
resource "opnsense_firewall_category" "resource_example" {
  name  = "lan_interface"
  auto  = true
  color = "000000"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) The name of the category

### Optional

- `auto` (Boolean) Whether the category is automatically added (i.e will be removed when unused)
- `color` (String) The hex color code to be used for the category tag

### Read-Only

- `id` (String) Identifier of the category
- `last_updated` (String) DateTime when alias was last updated

## Import

Import is supported using the following syntax:

```shell
# Categories can be imported by specifying the category name.
terraform import opnsense_firewall_category.import_example your_category
```