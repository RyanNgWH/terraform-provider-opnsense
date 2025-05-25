package nptv6_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccOneToOneNatResource_nat(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccNptv6NatResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("log"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("sequence"), knownvalue.Int32Exact(1)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("internal_prefix"), knownvalue.StringExact("1::")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("external_prefix"), knownvalue.StringExact("1::")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("track_interface"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("description"), knownvalue.StringExact("NPTv6 nat rule for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_nat_nptv6.test_acc_resource_nptv6",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccNptv6NatResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("log"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("sequence"), knownvalue.Int32Exact(2)),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("interface"), knownvalue.StringExact("wan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("internal_prefix"), knownvalue.StringExact("2::")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("external_prefix"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("track_interface"), knownvalue.StringExact("lan")),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_nat_nptv6.test_acc_resource_nptv6", tfjsonpath.New("description"), knownvalue.StringExact("[Updated] NPTv6 nat rule for terraform resource testing")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_nat_nptv6.test_acc_resource_nptv6",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccNptv6NatResourceConfig defines a NPTv6 NAT resource.
const testAccNptv6NatResourceConfig = `
	resource "opnsense_firewall_nat_nptv6" "test_acc_resource_nptv6" {
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
`

// testAccNptv6NatResourceConfig_modified defines a modified NPTv6 NAT resource.
const testAccNptv6NatResourceConfig_modified = `
	resource "opnsense_firewall_nat_nptv6" "test_acc_resource_nptv6" {
		enabled         = false
		log             = false
		sequence        = 2
		interface       = "wan"
		internal_prefix = "2::"
		track_interface = "lan"
		categories = []
		description = "[Updated] NPTv6 nat rule for terraform resource testing"
	}
`
