---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "opnsense_firewall_automation_source_nat Data Source - opnsense"
subcategory: ""
description: |-
  Retrieves information about a firewall automation source nat rule.
---

# opnsense_firewall_automation_source_nat (Data Source)

Retrieves information about a firewall automation source nat rule.

## Example Usage

```terraform
# Get firewall automation source nat rule as data source via it's uuid
data "opnsense_firewall_automation_source_nat" "data_source_via_id" {
  id = "5b034f00-d4b3-4eba-82d6-d74fce5f149b"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `id` (String) Identifier of the automation source nat rule.

### Read-Only

- `categories` (Set of String) The categories of the rule.
- `description` (String) Description to identify this rule.
- `destination` (String) Destination IP or network.
- `destination_not` (Boolean) Whether the destination matching should be inverted.
- `destination_port` (String) Destination port number or well known name .
- `enabled` (Boolean) Whether the rule is enabled.
- `interface` (String) Interface this rule applies to.
- `ip_version` (String) The applicable ip version this for this rule.
- `log` (Boolean) Whether packets that are handled by this rule should be logged.
- `no_nat` (Boolean) Disable NAT for all traffic matching this rule and stop processing source nat rules.
- `protocol` (String) The applicable protocol for this rule.
- `sequence` (Number) Order in which multiple matching rules are evaluated and applied (lowest first).
- `source` (String) Source IP or network.
- `source_not` (Boolean) Whether the source matching should be inverted.
- `source_port` (String) Source port number or well known name.
- `target` (String) Packets matching this rule will be mapped to this IP address or network.
- `target_port` (String) Target port number or well known name.
