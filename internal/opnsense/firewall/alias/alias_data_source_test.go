package alias_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccAliasDataSource_host(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccAliasDataSourceConfig_host_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_host_data_source")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("type"), knownvalue.StringExact("host")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("counters"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("updatefreq"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"days":  knownvalue.Int32Exact(0),
						"hours": knownvalue.Float64Exact(0),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("description"), knownvalue.StringExact("host alias for terraform datasource testing")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(false),
						"ipv6": knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("content"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("1.1.1.1")})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("interface"), knownvalue.StringExact("")),
				},
			},
			// Read testing (via name)
			{
				Config: testAccAliasDataSourceConfig_host_name,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_host_data_source")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("type"), knownvalue.StringExact("host")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("counters"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("updatefreq"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"days":  knownvalue.Int32Exact(0),
						"hours": knownvalue.Float64Exact(0),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("description"), knownvalue.StringExact("host alias for terraform datasource testing")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("proto"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.Bool(false),
						"ipv6": knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("content"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("1.1.1.1")})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("interface"), knownvalue.StringExact("")),
				},
			},
		},
	})
}

func TestAccAliasDataSource_dynipv6(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccAliasDataSourceConfig_dynipv6_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_dynipv6", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_dyn_data_source")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_dynipv6", tfjsonpath.New("type"), knownvalue.StringExact("dynipv6host")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_dynipv6", tfjsonpath.New("interface"), knownvalue.StringExact("opt1")),
				},
			},
			// Read testing (via name)
			{
				Config: testAccAliasDataSourceConfig_dynipv6_name,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_dynipv6", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_alias_dyn_data_source")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_dynipv6", tfjsonpath.New("type"), knownvalue.StringExact("dynipv6host")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_dynipv6", tfjsonpath.New("interface"), knownvalue.StringExact("opt1")),
				},
			},
		},
	})
}

// testAccAliasDataSourceConfig_host_id creates an alias resource of type 'host' and imports it as a data source via its id.
const testAccAliasDataSourceConfig_host_id = `
	resource "opnsense_firewall_alias" "test_acc_data_source_host" {
		enabled = true
		name = "test_acc_alias_host_data_source"
		type = "host"
		counters = true
		description = "host alias for terraform datasource testing"
		content = [
			"1.1.1.1"
		]
	}

	data "opnsense_firewall_alias" "test_acc_data_source_host" {
		id = opnsense_firewall_alias.test_acc_data_source_host.id
	}
`

// testAccAliasHostDataSourceNameConfig creates an alias resource of type 'host' and imports it as a data source via its name.
const testAccAliasDataSourceConfig_host_name = `
	resource "opnsense_firewall_alias" "test_acc_data_source_host" {
		enabled = true
		name = "test_acc_alias_host_data_source"
		type = "host"
		counters = true
		description = "host alias for terraform datasource testing"
		content = [
			"1.1.1.1"
		]
	}

	data "opnsense_firewall_alias" "test_acc_data_source_host" {
		name = opnsense_firewall_alias.test_acc_data_source_host.name
	}
`

// testAccAliasDataSourceConfig_dynipv6_id creates an alias resource of type 'dynipv6host' and imports it as a data source via its id.
const testAccAliasDataSourceConfig_dynipv6_id = `
	resource "opnsense_firewall_alias" "test_acc_data_source_dynipv6" {
		name = "test_acc_alias_dyn_data_source"
		type = "dynipv6host"
		interface = "opt1"
	}

	data "opnsense_firewall_alias" "test_acc_data_source_dynipv6" {
		id = opnsense_firewall_alias.test_acc_data_source_dynipv6.id
	}
`

// testAccAliasDataSourceConfig_dynipv6_name creates an alias resource of type 'dynipv6host' and imports it as a data source via its name.
const testAccAliasDataSourceConfig_dynipv6_name = `
	resource "opnsense_firewall_alias" "test_acc_data_source_dynipv6" {
		name = "test_acc_alias_dyn_data_source"
		type = "dynipv6host"
		interface = "opt1"
	}

	data "opnsense_firewall_alias" "test_acc_data_source_dynipv6" {
		name = opnsense_firewall_alias.test_acc_data_source_dynipv6.name
	}
`
