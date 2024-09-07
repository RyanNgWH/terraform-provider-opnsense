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
				Config: acctest.ProviderConfig + testAccAliasHostDataSourceIdConfig,
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
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("interfaces"), knownvalue.Null()),
				},
			},
			// Read testing (via name)
			{
				Config: acctest.ProviderConfig + testAccAliasHostDataSourceNameConfig,
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
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias.test_acc_data_source_host", tfjsonpath.New("interfaces"), knownvalue.Null()),
				},
			},
		},
	})
}

// testAccAliasHostDataSourceIdConfig creates an alias resource and imports it as a data source via its id.
const testAccAliasHostDataSourceIdConfig = `
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

// testAccAliasHostDataSourceNameConfig creates an alias resource and imports it as a data source via its name.
const testAccAliasHostDataSourceNameConfig = `
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
