package onetoone_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccOneToOneNatDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccOneToOneNatDataSourceConfig_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("sequence"), knownvalue.Int32Exact(2)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("type"), knownvalue.StringExact("nat")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("source_net"), knownvalue.StringExact("1.1.1.1")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("destination_net"), knownvalue.StringExact("2.2.2.2")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("external"), knownvalue.StringExact("3.3.3.3")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("nat_reflection"), knownvalue.StringExact("default")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("one-to-one nat rule for terraform data source testing")),
				},
			},
		},
	})
}

// testAccOneToOneNatDataSourceConfig_id creates a one-to-one nat resource and imports it as a data source via its id.
const testAccOneToOneNatDataSourceConfig_id = `
	resource "opnsense_firewall_nat_one_to_one" "test_acc_data_source" {
		enabled         = true
		log             = true
		sequence        = 2
		interface       = "wan"
		type            = "nat"
		source_net      = "1.1.1.1"
		source_not      = false
		destination_net = "2.2.2.2"
		destination_not = false
		external        = "3.3.3.3"
		nat_reflection  = "default"
		categories = [
			"perm_test_acc_category"
		]
		description = "one-to-one nat rule for terraform data source testing"
	}

	data "opnsense_firewall_nat_one_to_one" "test_acc_data_source" {
		id = opnsense_firewall_nat_one_to_one.test_acc_data_source.id
	}
`
