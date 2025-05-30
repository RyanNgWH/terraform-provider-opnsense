package sourcenat_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccAutomationSourceNatDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccAutomationSourceNatDataSourceConfig_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("no_nat"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("sequence"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("protocol"), knownvalue.StringExact("tcp")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("source"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("source_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("source_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("destination"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("destination_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("destination_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("target"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("target_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_automation_source_nat.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("automation source nat rule for terraform resource testing")),
				},
			},
		},
	})
}

// testAccAutomationSourceNatDataSourceConfig_id creates an automation source nat rule resource and imports it as a data source via its id.
const testAccAutomationSourceNatDataSourceConfig_id = `
	resource "opnsense_firewall_automation_source_nat" "test_acc_data_source" {
		enabled     	   = true
		no_nat 		  	   = true
		sequence    	   = 10
		interface   	   = "lan"
		ip_version  	   = "ipv4"
		protocol 	  	   = "tcp"
		source 		  	   = "perm_test_acc_alias"
		source_not  	   = true
		source_port 	   = "55"
		destination 	   = "perm_test_acc_alias"
		destination_not  = true
		destination_port = "55"
		target 					 = "perm_test_acc_alias"
		target_port 		 = "55"
		log 						 = true
		categories 			 = [
			"perm_test_acc_category"
		]
		description = "automation source nat rule for terraform resource testing"
	}

	data "opnsense_firewall_automation_source_nat" "test_acc_data_source" {
		id = opnsense_firewall_automation_source_nat.test_acc_data_source.id
	}
`
