package alias_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccAliasResource_host(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAliasHostResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_host_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("type"), knownvalue.StringExact("host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("counters"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("updatefreq"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"days":  knownvalue.Int32Exact(0),
						"hours": knownvalue.Float64Exact(0),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("description"), knownvalue.StringExact("host alias for terraform resource testing")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(false),
						"ipv6": knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("content"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("1.1.1.1")})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("perm_test_acc_category"),
					})),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_alias.test_acc_resource_host",
				ImportState:             true,
				ImportStateId:           "test_acc_alias_host_resource",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccAliasHostResourceModifiedConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_host_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("type"), knownvalue.StringExact("host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("counters"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("updatefreq"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"days":  knownvalue.Int32Exact(0),
						"hours": knownvalue.Float64Exact(0),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("description"), knownvalue.StringExact("[Updated] host alias for terraform resource testing")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(false),
						"ipv6": knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("content"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("1.1.1.1"),
						knownvalue.StringExact("2.2.2.2"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccAliasResource_defaults(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAliasHostResourceDefaultConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_host_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("type"), knownvalue.StringExact("host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("counters"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("updatefreq"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"days":  knownvalue.Int32Exact(0),
						"hours": knownvalue.Float64Exact(0),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("description"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(false),
						"ipv6": knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("content"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interfaces"), knownvalue.ListExact([]knownvalue.Check{})),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_alias.test_acc_resource_host",
				ImportState:             true,
				ImportStateId:           "test_acc_alias_host_resource",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccAliasHostResourceConfig defines an alias resource of type `host`.
const testAccAliasHostResourceConfig = `
	resource "opnsense_firewall_alias" "test_acc_resource_host" {
		enabled = true
		name = "test_acc_alias_host_resource"
		type = "host"
		counters = true
		description = "host alias for terraform resource testing"
		content = [
			"1.1.1.1"
		]
		categories = [
			"perm_test_acc_category"
		]
	}
`

// testAccAliasHostResourceModifiedConfig defines a modified alias resource of type `host`.
const testAccAliasHostResourceModifiedConfig = `
	resource "opnsense_firewall_alias" "test_acc_resource_host" {
		enabled = false
		name = "test_acc_alias_host_resource"
		type = "host"
		counters = false
		description = "[Updated] host alias for terraform resource testing"
		content = [
			"1.1.1.1",
			"2.2.2.2"
		]
	}
`

// testAccAliasHostResourceDefaultConfig defines an alias resource of type `host` with default values.
const testAccAliasHostResourceDefaultConfig = `
	resource "opnsense_firewall_alias" "test_acc_resource_host" {
		name = "test_acc_alias_host_resource"
		type = "host"
	}
`
