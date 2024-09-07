package alias_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccGeoIpDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccGeoIpDataSourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias_geoip.test_acc_data_source", tfjsonpath.New("address_count"), knownvalue.Int64Exact(951473)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias_geoip.test_acc_data_source", tfjsonpath.New("address_sources"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"ipv4": knownvalue.StringExact("GeoLite2-Country-Blocks-IPv4.csv"),
						"ipv6": knownvalue.StringExact("GeoLite2-Country-Blocks-IPv6.csv"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias_geoip.test_acc_data_source", tfjsonpath.New("file_count"), knownvalue.Int64Exact(502)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias_geoip.test_acc_data_source", tfjsonpath.New("locations_filename"), knownvalue.StringExact("GeoLite2-Country-Locations-en.csv")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias_geoip.test_acc_data_source", tfjsonpath.New("url"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_alias_geoip.test_acc_data_source", tfjsonpath.New("usages"), knownvalue.Int64Exact(0)),
				},
			},
		},
	})
}

// testAccGeoIpDataSourceConfig imports the geoip configuration as a data source.
const testAccGeoIpDataSourceConfig = `
	data "opnsense_firewall_alias_geoip" "test_acc_data_source"{}
`
