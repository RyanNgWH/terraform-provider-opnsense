package filter_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

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
				Config: testAccAutomationFilterDataSourceConfig_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("sequence"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("action"), knownvalue.StringExact("pass")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("quick"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("lan"),
						knownvalue.StringExact("wan"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("direction"), knownvalue.StringExact("in")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("protocol"), knownvalue.StringExact("tcp")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("source"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("source_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("source_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("destination"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("destination_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("destination_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("gateway"), knownvalue.StringExact("WAN_GW")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_filter.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("automation filter rule for terraform resource testing")),
				},
			},
		},
	})
}

// testAccAutomationFilterDataSourceConfig_id creates an automation filter rule resource and imports it as a data source via its id.
const testAccAutomationFilterDataSourceConfig_id = `
	resource "opnsense_firewall_automation_filter" "test_acc_data_source" {
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

	data "opnsense_firewall_automation_filter" "test_acc_data_source" {
		id = opnsense_firewall_automation_filter.test_acc_data_source.id
	}
`
