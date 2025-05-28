package rules_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccShaperRulesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccShaperRulesDataSourceConfig_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("sequence"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("interface2"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("protocol"), knownvalue.StringExact("igmp")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("max_packet_length"), knownvalue.Int32Exact(255)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("sources"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("1.1.1.1"),
						knownvalue.StringExact("2.2.2.2"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("source_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("source_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("destinations"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("1.1.1.1"),
						knownvalue.StringExact("2.2.2.2"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("destination_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("destination_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("dscp"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("af11"),
						knownvalue.StringExact("best effort"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("direction"), knownvalue.StringExact("in")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("target"), knownvalue.StringExact("de21d36c-bd97-4477-9c2d-c4a8f23818d0")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_rules.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper rule for terraform resource testing (uses pipe as target)")),
				},
			},
		},
	})
}

// testAccShaperRulesDataSourceConfig_id creates a traffic shaper rule resource and imports it as a data source via its id.
const testAccShaperRulesDataSourceConfig_id = `
	resource "opnsense_firewall_shaper_rules" "test_acc_data_source" {
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

	data "opnsense_firewall_shaper_rules" "test_acc_data_source" {
		id = opnsense_firewall_shaper_rules.test_acc_data_source.id
	}
`
