package alias_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccGeoIpResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccGeoIpResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias_geoip.test_acc_resource", tfjsonpath.New("url"), knownvalue.StringExact("https://test.com")),
				},
			},
			// ImportState testing
			{
				ResourceName:                         "opnsense_firewall_alias_geoip.test_acc_resource",
				ImportState:                          true,
				ImportStateId:                        "",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "url",
				ImportStateVerifyIgnore:              []string{"last_updated"},
			},

			// Update and Read testing
			{
				Config: testAccGeoIpResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_alias_geoip.test_acc_resource", tfjsonpath.New("url"), knownvalue.StringExact("https://hello.com")),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccGeoIpResourceConfig defines a geoip resource.
const testAccGeoIpResourceConfig = `
	resource "opnsense_firewall_alias_geoip" "test_acc_resource" {
		url = "https://test.com"
	}
`

// testAccGeoIpResourceConfig_modified defines a modified geoip resource.
const testAccGeoIpResourceConfig_modified = `
	resource "opnsense_firewall_alias_geoip" "test_acc_resource" {
		url = "https://hello.com"
	}
`
