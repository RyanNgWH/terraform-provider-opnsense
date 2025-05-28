package rules_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccShaperRulesResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccShaperRulesResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sequence"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface2"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("protocol"), knownvalue.StringExact("igmp")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("max_packet_length"), knownvalue.Int32Exact(255)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sources"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("1.1.1.1"),
						knownvalue.StringExact("2.2.2.2"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destinations"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("1.1.1.1"),
						knownvalue.StringExact("2.2.2.2"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("dscp"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("af11"),
						knownvalue.StringExact("best effort"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("direction"), knownvalue.StringExact("in")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("target"), knownvalue.StringExact("de21d36c-bd97-4477-9c2d-c4a8f23818d0")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper rule for terraform resource testing (uses pipe as target)")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_shaper_rules.test_acc_resource_rules",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccShaperRulesResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sequence"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface2"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("protocol"), knownvalue.StringExact("tcp_ack_not")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("max_packet_length"), knownvalue.Int32Exact(100)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sources"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("any"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destinations"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("any"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("dscp"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("best effort"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("direction"), knownvalue.StringExact("out")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("target"), knownvalue.StringExact("d93c6000-d8ea-4d12-a26f-5cac6e92b023")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper rule for terraform resource testing (uses queue as target)")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_shaper_rules.test_acc_resource_rules",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Empty list checking
			{
				Config: testAccShaperRulesResourceConfig_emptyLists,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sequence"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface2"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("protocol"), knownvalue.StringExact("tcp_ack_not")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("max_packet_length"), knownvalue.Int32Exact(100)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sources"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("1.1.1.1"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destinations"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("1.1.1.1"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("dscp"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("direction"), knownvalue.StringExact("both")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("target"), knownvalue.StringExact("d93c6000-d8ea-4d12-a26f-5cac6e92b023")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper rule for terraform resource testing (uses queue as target)")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_shaper_rules.test_acc_resource_rules",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccShaperRulesResource_default(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccShaperRulesResourceConfig_default,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sequence"), knownvalue.Int32Exact(1)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("interface2"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("protocol"), knownvalue.StringExact("ip")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("max_packet_length"), knownvalue.Int32Exact(-1)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("sources"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("any"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("source_port"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destinations"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("any"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("destination_port"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("dscp"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("direction"), knownvalue.StringExact("both")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("target"), knownvalue.StringExact("d93c6000-d8ea-4d12-a26f-5cac6e92b023")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_rules.test_acc_resource_rules", tfjsonpath.New("description"), knownvalue.StringExact("")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_shaper_rules.test_acc_resource_rules",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

// testAccShaperRulesResourceConfig defines a traffic shaper rule resource.
const testAccShaperRulesResourceConfig = `
	resource "opnsense_firewall_shaper_rules" "test_acc_resource_rules" {
		enabled    = true
		sequence   = 10
		interface  = "wan"
		interface2 = "lan"
		protocol   = "igmp"
		max_packet_length   = 255
		sources = [
			"1.1.1.1",
			"2.2.2.2"
		]
		source_not = true
		source_port = "55"
		destinations = [
			"1.1.1.1",
			"2.2.2.2"
		]
		destination_not = true
		destination_port = "55"
		dscp = [
			"af11",
			"best effort"
		]
		direction = "in"
		target = "de21d36c-bd97-4477-9c2d-c4a8f23818d0"
		description = "traffic shaper rule for terraform resource testing (uses pipe as target)"
	}
`

// testAccShaperRulesResourceConfig_modified defines a modified traffic shaper rule resource.
const testAccShaperRulesResourceConfig_modified = `
	resource "opnsense_firewall_shaper_rules" "test_acc_resource_rules" {
		enabled    = false
		sequence   = 20
		interface  = "lan"
		interface2 = "wan"
		protocol   = "tcp_ack_not"
		max_packet_length   = 100
		sources = [
			"any"
		]
		source_not = false
		source_port = "ssh"
		destinations = [
			"any"
		]
		destination_not = false
		destination_port = "ssh"
		dscp = [
			"best effort"
		]
		direction = "out"
		target = "d93c6000-d8ea-4d12-a26f-5cac6e92b023"
		description = "traffic shaper rule for terraform resource testing (uses queue as target)"
	}
`

// testAccShaperRulesResourceConfig_emptyLists defines a modified traffic shaper rule resource (tests empty lists).
const testAccShaperRulesResourceConfig_emptyLists = `
	resource "opnsense_firewall_shaper_rules" "test_acc_resource_rules" {
		enabled    = false
		sequence   = 20
		interface  = "lan"
		interface2 = "wan"
		protocol   = "tcp_ack_not"
		max_packet_length   = 100
		sources = [
			"1.1.1.1"
		]
		source_not = false
		source_port = "ssh"
		destinations = [
			"1.1.1.1"
		]
		destination_not = false
		destination_port = "ssh"
		dscp = []
		direction = "both"
		target = "d93c6000-d8ea-4d12-a26f-5cac6e92b023"
		description = "traffic shaper rule for terraform resource testing (uses queue as target)"
	}
`

// testAccShaperRulesResourceConfig_default defines a traffic shaper rule with default values.
const testAccShaperRulesResourceConfig_default = `
	resource "opnsense_firewall_shaper_rules" "test_acc_resource_rules" {
		interface  = "lan"
		target = "d93c6000-d8ea-4d12-a26f-5cac6e92b023"
	}
`
