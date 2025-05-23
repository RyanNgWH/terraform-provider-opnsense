package nat_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccOneToOneNatResource_Nat(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccOneToOneNatResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("sequence"), knownvalue.Int32Exact(2)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("type"), knownvalue.StringExact("nat")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("source_net"), knownvalue.StringExact("1.1.1.1")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("destination_net"), knownvalue.StringExact("2.2.2.2")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("external"), knownvalue.StringExact("3.3.3.3")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("nat_reflection"), knownvalue.StringExact("default")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("description"), knownvalue.StringExact("one-to-one nat rule for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_nat_one_to_one.test_acc_resource_nat",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccOneToOneNatResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("sequence"), knownvalue.Int32Exact(3)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("type"), knownvalue.StringExact("nat")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("source_net"), knownvalue.StringExact("perm_test_acc_alias")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("source_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("destination_net"), knownvalue.StringExact("1.1.1.1")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("destination_not"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("external"), knownvalue.StringExact("1.1.1.1")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("nat_reflection"), knownvalue.StringExact("enable")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("description"), knownvalue.StringExact("[Updated] one-to-one nat rule for terraform resource testing")),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccOneToOneNatResource_Defaults(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccOneToOneNatResourceConfig_default,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("sequence"), knownvalue.Int32Exact(1)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("type"), knownvalue.StringExact("nat")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("source_net"), knownvalue.StringExact("1.1.1.1")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("source_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("destination_net"), knownvalue.StringExact("1.1.1.1")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("destination_not"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("external"), knownvalue.StringExact("1.1.1.1")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("nat_reflection"), knownvalue.StringExact("default")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_one_to_one.test_acc_resource_nat", tfjsonpath.New("description"), knownvalue.StringExact("")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_nat_one_to_one.test_acc_resource_nat",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccOneToOneNatResourceConfig defines a one-to-one NAT resource of type `nat`.
const testAccOneToOneNatResourceConfig = `
	resource "opnsense_firewall_nat_one_to_one" "test_acc_resource_nat" {
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
		description = "one-to-one nat rule for terraform resource testing"
	}
`

// testAccOneToOneNatResourceConfig_modified defines a modified one-to-one NAT resource of type `nat`.
const testAccOneToOneNatResourceConfig_modified = `
	resource "opnsense_firewall_nat_one_to_one" "test_acc_resource_nat" {
		enabled         = false
		log             = false
		sequence        = 3
		interface       = "lan"
		type            = "nat"
		source_net      = "perm_test_acc_alias"
		source_not      = true
		destination_net = "1.1.1.1"
		destination_not = true
		external        = "1.1.1.1"
		nat_reflection  = "enable"
		categories = []
		description = "[Updated] one-to-one nat rule for terraform resource testing"
	}
`

// testAccOneToOneNatResourceConfig_default defines a one-to-one NAT resource of type `nat` with default values.
const testAccOneToOneNatResourceConfig_default = `
	resource "opnsense_firewall_nat_one_to_one" "test_acc_resource_nat" {
		interface       = "wan"
		type            = "nat"
		source_net      = "1.1.1.1"
		destination_net = "1.1.1.1"
		external        = "1.1.1.1"
	}
`
