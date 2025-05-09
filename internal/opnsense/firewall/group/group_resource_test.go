package group_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccGroupResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccGroupResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_group")),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("members"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("lan"),
						knownvalue.StringExact("wan"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("no_group"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("sequence"), knownvalue.Int64Exact(100)),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("description"), knownvalue.StringExact("firewall group for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_group.test_acc_resource",
				ImportState:             true,
				ImportStateId:           "test_acc_group",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccGroupDefaultResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_ugroup")),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("members"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("lan"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("no_group"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("sequence"), knownvalue.Int64Exact(0)),
					statecheck.ExpectKnownValue("opnsense_firewall_group.test_acc_resource", tfjsonpath.New("description"), knownvalue.StringExact("")),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccGroupResourceConfig defines a group resource.
const testAccGroupResourceConfig = `
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
`

// testAccGroupDefaultResourceConfig defines a group resource with only required fields.
const testAccGroupDefaultResourceConfig = `
	resource "opnsense_firewall_group" "test_acc_resource" {
		name = "test_acc_ugroup"
		members = [
			"lan",
		]
	}
`
