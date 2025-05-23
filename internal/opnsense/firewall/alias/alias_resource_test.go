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
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_host", tfjsonpath.New("categories"), knownvalue.ListExact([]knownvalue.Check{})),
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
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_dynipv6", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_dynipv6_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_dynipv6", tfjsonpath.New("type"), knownvalue.StringExact("dynipv6host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_dynipv6", tfjsonpath.New("interface"), knownvalue.StringExact("opt1")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_alias.test_acc_resource_dynipv6",
				ImportState:             true,
				ImportStateId:           "test_acc_alias_dynipv6_resource",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update testing
			{
				Config: testAccAliasResourceConfig_dynipv6_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_dynipv6", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_dynipv6_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_dynipv6", tfjsonpath.New("type"), knownvalue.StringExact("dynipv6host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_dynipv6", tfjsonpath.New("interface"), knownvalue.StringExact("lan")),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccAliasResource_asn(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAliasResourceConfig_asn,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_asn", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_asn_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_asn", tfjsonpath.New("type"), knownvalue.StringExact("asn")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_asn", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(true),
						"ipv6": knownvalue.Bool(true),
					})),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_alias.test_acc_resource_asn",
				ImportState:             true,
				ImportStateId:           "test_acc_alias_asn_resource",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update testing
			{
				Config: testAccAliasResourceConfig_asn_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_asn", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_asn_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_asn", tfjsonpath.New("type"), knownvalue.StringExact("asn")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_asn", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(false),
						"ipv6": knownvalue.Bool(false),
					})),
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
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_host_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("type"), knownvalue.StringExact("host")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("counters"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("updatefreq"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"days":  knownvalue.Int32Exact(0),
						"hours": knownvalue.Float64Exact(0),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("description"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(false),
						"ipv6": knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("content"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue("opnsense_firewall_alias.test_acc_resource_default", tfjsonpath.New("interface"), knownvalue.StringExact("")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_alias.test_acc_resource_default",
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
		categories = [
			"perm_test_acc_category"
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

// testAccAliasResourceConfig_dynipv6 defines an alias resource of type `dynipv6host` tests interface).
const testAccAliasResourceConfig_dynipv6 = `
	resource "opnsense_firewall_alias" "test_acc_resource_dynipv6" {
		name = "test_acc_alias_dynipv6_resource"
		type = "dynipv6host"
		interface = "opt1"
	}
`

// testAccAliasResourceConfig_dynipv6_modified defines a modified alias resource of type `dynipv6host` (tests interface).
const testAccAliasResourceConfig_dynipv6_modified = `
	resource "opnsense_firewall_alias" "test_acc_resource_dynipv6" {
		name = "test_acc_alias_dynipv6_resource"
		type = "dynipv6host"
		interface = "lan"
	}
`

// testAccAliasResourceConfig_asn defines an alias resource of type `asn` (tests proto).
const testAccAliasResourceConfig_asn = `
	resource "opnsense_firewall_alias" "test_acc_resource_asn" {
		name = "test_acc_alias_asn_resource"
		type = "asn"
		proto = {
			ipv4 = true
			ipv6 = true
		}
	}
`

// testAccAliasResourceConfig_asn_modified defines a modified alias resource of type `asn` (tests proto).
const testAccAliasResourceConfig_asn_modified = `
	resource "opnsense_firewall_alias" "test_acc_resource_asn" {
		name = "test_acc_alias_asn_resource"
		type = "asn"
		proto = {
			ipv4 = false
			ipv6 = false
		}
	}
`

// testAccAliasResourceConfig_default defines an alias resource of type `host` with default values.
const testAccAliasResourceConfig_default = `
	resource "opnsense_firewall_alias" "test_acc_resource_default" {
		name = "test_acc_alias_host_resource"
		type = "host"
	}
`
