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
				Config: testAccAliasResourceConfig_host,
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
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interface"), knownvalue.StringExact("")),
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
				Config: testAccAliasResourceConfig_host_modified,
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
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interface"), knownvalue.StringExact("")),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccAliasResource_dynipv6(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAliasResourceConfig_dynipv6,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_dynipv6_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("type"), knownvalue.StringExact("dynipv6host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interface"), knownvalue.StringExact("opt1")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_alias.test_acc_resource_host",
				ImportState:             true,
				ImportStateId:           "test_acc_alias_dynipv6_resource",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update testing
			{
				Config: testAccAliasResourceConfig_dynipv6_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_dynipv6_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("type"), knownvalue.StringExact("dynipv6host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
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
				Config: testAccAliasResourceConfig_default,
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
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("interface"), knownvalue.StringExact("")),
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

// testAccAliasResourceConfig_host defines an alias resource of type `host`.
const testAccAliasResourceConfig_host = `
	resource "opnsense_firewall_alias" "test_acc_resource_host" {
		enabled = true
		name = "test_acc_alias_host_resource"
		type = "host"
		counters = true
		description = "host alias for terraform resource testing"
		content = [
			"1.1.1.1"
		]
	}
`

// testAccAliasResourceConfig_host_modified defines a modified alias resource of type `host`.
const testAccAliasResourceConfig_host_modified = `
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

// testAccAliasResourceConfig_dynipv6 defines an alias resource of type `dynipv6host`.
const testAccAliasResourceConfig_dynipv6 = `
	resource "opnsense_firewall_alias" "test_acc_resource_host" {
		name = "test_acc_alias_dynipv6_resource"
		type = "dynipv6host"
		interface = "opt1"
	}
`

// testAccAliasResourceConfig_dynipv6_modified defines a modified alias resource of type `dynipv6host`.
const testAccAliasResourceConfig_dynipv6_modified = `
	resource "opnsense_firewall_alias" "test_acc_resource_host" {
		name = "test_acc_alias_dynipv6_resource"
		type = "dynipv6host"
		interface = "lan"
	}
`

// testAccAliasResourceConfig_default defines an alias resource of type `host` with default values.
const testAccAliasResourceConfig_default = `
	resource "opnsense_firewall_alias" "test_acc_resource_host" {
		name = "test_acc_alias_host_resource"
		type = "host"
	}
`
