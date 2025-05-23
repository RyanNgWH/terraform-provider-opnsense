package group_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccGroupDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccGroupDataSourceConfig_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_id", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_group")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_id", tfjsonpath.New("members"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("lan"),
						knownvalue.StringExact("wan"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_id", tfjsonpath.New("no_group"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_id", tfjsonpath.New("no_group"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_id", tfjsonpath.New("sequence"), knownvalue.Int64Exact(100)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_id", tfjsonpath.New("description"), knownvalue.StringExact("firewall group for terraform resource testing")),
				},
			},
			// Read testing (via name)
			{
				Config: testAccGroupDataSourceConfig_name,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_name", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_group")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_name", tfjsonpath.New("members"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("lan"),
						knownvalue.StringExact("wan"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_name", tfjsonpath.New("no_group"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_name", tfjsonpath.New("no_group"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_name", tfjsonpath.New("sequence"), knownvalue.Int64Exact(100)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_group.test_acc_data_source_name", tfjsonpath.New("description"), knownvalue.StringExact("firewall group for terraform resource testing")),
				},
			},
		},
	})
}

// testAccGroupDataSourceConfig_id creates a group before importing it as a data source by its id.
const testAccGroupDataSourceConfig_id = `
	resource "opnsense_firewall_group" "test_acc_resource" {
		name = "test_acc_group"
		members = [
			"lan",
			"wan"
		]

		no_group    = true
		sequence    = 100
		description = "firewall group for terraform resource testing"
	}

	data "opnsense_firewall_group" "test_acc_data_source_id" {
		id = opnsense_firewall_group.test_acc_resource.id
	}
`

// testAccGroupDataSourceConfig_name creates a group before importing it as a data source by its name.
const testAccGroupDataSourceConfig_name = `
	resource "opnsense_firewall_group" "test_acc_resource" {
		name = "test_acc_group"
		members = [
			"lan",
			"wan"
		]

		no_group    = true
		sequence    = 100
		description = "firewall group for terraform resource testing"
	}
	data "opnsense_firewall_group" "test_acc_data_source_name" {
		name = opnsense_firewall_group.test_acc_resource.name
	}
`
