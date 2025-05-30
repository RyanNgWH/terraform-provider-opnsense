package sourcenat_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccAutomationSourceNatResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAutomationSourceNatResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("no_nat"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("sequence"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("protocol"), knownvalue.StringExact("tcp")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target_port"), knownvalue.StringExact("55")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("description"), knownvalue.StringExact("automation source nat rule for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_automation_source_nat.test_acc_resource_source_nat",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccAutomationSourceNatResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("no_nat"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("sequence"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv6")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("protocol"), knownvalue.StringExact("udp")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
						knownvalue.StringExact("perm_test_acc_category2"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("description"), knownvalue.StringExact("[updated] automation source nat rule for terraform resource testing")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_automation_source_nat.test_acc_resource_source_nat",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Empty list testing
			{
				Config: testAccAutomationSourceNatResourceConfig_emptyLists,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("no_nat"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("sequence"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv6")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("protocol"), knownvalue.StringExact("udp")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target_port"), knownvalue.StringExact("ssh")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("description"), knownvalue.StringExact("[updated] automation source nat rule for terraform resource testing")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_automation_source_nat.test_acc_resource_source_nat",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccAutomationSourceNatResource_default(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAutomationSourceNatResourceConfig_default,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("no_nat"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("sequence"), knownvalue.Int32Exact(1)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv4")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("protocol"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("source_port"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination"), knownvalue.StringExact("any")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("destination_port"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("target_port"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_automation_source_nat.test_acc_resource_source_nat", tfjsonpath.New("description"), knownvalue.StringExact("")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_automation_source_nat.test_acc_resource_source_nat",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

// testAccAutomationSourceNatResourceConfig defines an automation source nat resource.
const testAccAutomationSourceNatResourceConfig = `
	resource "opnsense_firewall_automation_source_nat" "test_acc_resource_source_nat" {
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
`

// testAccAutomationSourceNatResourceConfig_modified defines a modified automation source nat resource.
const testAccAutomationSourceNatResourceConfig_modified = `
	resource "opnsense_firewall_automation_source_nat" "test_acc_resource_source_nat" {
		enabled     	   = false
		no_nat 		  	   = false
		sequence    	   = 20
		interface   	   = "wan"
		ip_version  	   = "ipv6"
		protocol 	  	   = "udp"
		source 		  	   = "any"
		source_not  	   = false
		source_port 	   = "ssh"
		destination 	   = "any"
		destination_not  = false
		destination_port = "ssh"
		target 					 = "any"
		target_port 		 = "ssh"
		log 						 = false
		categories 			 = [
			"perm_test_acc_category",
			"perm_test_acc_category2"
		]
		description = "[updated] automation source nat rule for terraform resource testing"
	}
`

// testAccAutomationSourceNatResourceConfig_emptyLists defines an automation source nat resource with empty lists.
const testAccAutomationSourceNatResourceConfig_emptyLists = `
	resource "opnsense_firewall_automation_source_nat" "test_acc_resource_source_nat" {
		enabled     	   = false
		no_nat 		  	   = false
		sequence    	   = 20
		interface   	   = "wan"
		ip_version  	   = "ipv6"
		protocol 	  	   = "udp"
		source 		  	   = "any"
		source_not  	   = false
		source_port 	   = "ssh"
		destination 	   = "any"
		destination_not  = false
		destination_port = "ssh"
		target 					 = "any"
		target_port 		 = "ssh"
		log 						 = false
		categories 			 = []
		description = "[updated] automation source nat rule for terraform resource testing"
	}
`

// testAccAutomationSourceNatResourceConfig_default defines an automation source nat resource with default values.
const testAccAutomationSourceNatResourceConfig_default = `
	resource "opnsense_firewall_automation_source_nat" "test_acc_resource_source_nat" {
		interface   	   = "wan"
		target 					 = "perm_test_acc_alias"
	}
`
