package nptv6_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccNptv6NatDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id) - external interface
			{
				Config: testAccNptv6NatDataSourceConfig_id_externalPrefix,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("sequence"), knownvalue.Int32Exact(1)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("internal_prefix"), knownvalue.StringExact("1::")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("external_prefix"), knownvalue.StringExact("1::")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("track_interface"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("NPTv6 nat rule for terraform resource testing")),
				},
			},
			// Read testing (via id) - track interface
			{
				Config: testAccNptv6NatDataSourceConfig_id_trackif,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("sequence"), knownvalue.Int32Exact(1)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("internal_prefix"), knownvalue.StringExact("1::")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("external_prefix"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("track_interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("NPTv6 nat rule for terraform resource testing")),
				},
			},
		},
	})
}

// testAccNptv6NatDataSourceConfig_id_externalPrefix creates a NPTv6 nat resource with an external prefix and imports it as a data source via its id.
const testAccNptv6NatDataSourceConfig_id_externalPrefix = `
	resource "opnsense_firewall_nat_nptv6" "test_acc_data_source" {
		enabled         = true
		log             = true
		sequence        = 1
		interface       = "lan"
		internal_prefix = "1::"
		external_prefix = "1::"
		categories = [
			"perm_test_acc_category"
		]
		description = "NPTv6 nat rule for terraform resource testing"
	}

	data "opnsense_firewall_nat_nptv6" "test_acc_data_source" {
		id = opnsense_firewall_nat_nptv6.test_acc_data_source.id
	}
`

// testAccNptv6NatDataSourceConfig_id_trackif creates a NPTv6 nat resource with a tracked interface and imports it as a data source via its id.
const testAccNptv6NatDataSourceConfig_id_trackif = `
	resource "opnsense_firewall_nat_nptv6" "test_acc_data_source" {
		enabled         = true
		log             = true
		sequence        = 1
		interface       = "wan"
		internal_prefix = "1::"
		track_interface = "lan"
		categories = [
			"perm_test_acc_category"
		]
		description = "NPTv6 nat rule for terraform resource testing"
	}

	data "opnsense_firewall_nat_nptv6" "test_acc_data_source" {
		id = opnsense_firewall_nat_nptv6.test_acc_data_source.id
	}
`
