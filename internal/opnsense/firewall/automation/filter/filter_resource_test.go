package filter_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccAutomationFilterResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAutomationFilterResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("sequence"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("action"), knownvalue.StringExact("pass")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("quick"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("lan"),
						knownvalue.StringExact("wan"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("direction"), knownvalue.StringExact("in")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("protocol"), knownvalue.StringExact("tcp")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("gateway"), knownvalue.StringExact("WAN_GW")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("description"), knownvalue.StringExact("automation filter rule for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_automation_filter.test_acc_resource_filter",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccAutomationFilterResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("sequence"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("action"), knownvalue.StringExact("reject")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("quick"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("lan"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("direction"), knownvalue.StringExact("out")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv6")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("protocol"), knownvalue.StringExact("udp")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source"), knownvalue.StringExact("lanip")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination"), knownvalue.StringExact("lanip")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("gateway"), knownvalue.StringExact("WAN_DHCP6")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
						knownvalue.StringExact("perm_test_acc_category2"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("description"), knownvalue.StringExact("[Updated] automation filter rule for terraform resource testing")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_automation_filter.test_acc_resource_filter",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Empty list testing
			{
				Config: testAccAutomationFilterResourceConfig_emptyLists,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("sequence"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("action"), knownvalue.StringExact("reject")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("quick"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("direction"), knownvalue.StringExact("out")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv6")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("protocol"), knownvalue.StringExact("udp")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source"), knownvalue.StringExact("lanip")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination"), knownvalue.StringExact("lanip")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("gateway"), knownvalue.StringExact("WAN_DHCP6")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("description"), knownvalue.StringExact("[Updated] automation filter rule for terraform resource testing")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_automation_filter.test_acc_resource_filter",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccAutomationFilterResource_default(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAutomationFilterResourceConfig_defaults,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("sequence"), knownvalue.Int32Exact(1)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("action"), knownvalue.StringExact("pass")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("quick"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("direction"), knownvalue.StringExact("in")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("protocol"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("source_port"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("destination_port"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("gateway"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_filter.test_acc_resource_filter", tfjsonpath.New("description"), knownvalue.StringExact("")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_automation_filter.test_acc_resource_filter",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

// testAccAutomationFilterResourceConfig defines an automation filter rule resource.
const testAccAutomationFilterResourceConfig = `
	resource "opnsense_firewall_automation_filter" "test_acc_resource_filter" {
		enabled    = true
		sequence   = 10
		action  = "pass"
		quick = true
		interfaces   = [
			"lan",
			"wan"
		]
		direction   = "in"
		ip_version = "ipv4"
		protocol = "tcp"
		source = "perm_test_acc_alias"
		source_not = true
		source_port = "55"
		destination = "perm_test_acc_alias"
		destination_not = true
		destination_port = "55"
		gateway = "WAN_GW"
		log = true
		categories = [
			"perm_test_acc_category"
		]
		description = "automation filter rule for terraform resource testing"
	}
`

// testAccAutomationFilterResourceConfig_modified defines a modified automation filter rule resource.
const testAccAutomationFilterResourceConfig_modified = `
	resource "opnsense_firewall_automation_filter" "test_acc_resource_filter" {
		enabled    = false
		sequence   = 20
		action  = "reject"
		quick = false
		interfaces   = [
			"lan"
		]
		direction   = "out"
		ip_version = "ipv6"
		protocol = "udp"
		source = "lanip"
		source_not = false
		source_port = "ssh"
		destination = "lanip"
		destination_not = false
		destination_port = "ssh"
		gateway = "WAN_DHCP6"
		log = false
		categories = [
			"perm_test_acc_category",
			"perm_test_acc_category2"
		]
		description = "[Updated] automation filter rule for terraform resource testing"
	}
`

// testAccAutomationFilterResourceConfig_emptyLists defines a modified automation filter rule resource with empty lists.
const testAccAutomationFilterResourceConfig_emptyLists = `
	resource "opnsense_firewall_automation_filter" "test_acc_resource_filter" {
		enabled    = false
		sequence   = 20
		action  = "reject"
		quick = false
		interfaces   = []
		direction   = "out"
		ip_version = "ipv6"
		protocol = "udp"
		source = "lanip"
		source_not = false
		source_port = "ssh"
		destination = "lanip"
		destination_not = false
		destination_port = "ssh"
		gateway = "WAN_DHCP6"
		log = false
		categories = []
		description = "[Updated] automation filter rule for terraform resource testing"
	}
`

// testAccAutomationFilterResourceConfig_defaults defines an automation filter rule resource with default values.
const testAccAutomationFilterResourceConfig_defaults = `
	resource "opnsense_firewall_automation_filter" "test_acc_resource_filter" {
	}
`
