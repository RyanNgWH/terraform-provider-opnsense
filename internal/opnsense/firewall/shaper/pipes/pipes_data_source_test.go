package pipes_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccNptv6NatDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccShaperPipesDataSourceConfig_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("bandwidth"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"value":  knownvalue.Int32Exact(10),
						"metric": knownvalue.StringExact("Kbit"),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("queue"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("mask"), knownvalue.StringExact("src-ip")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("buckets"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("scheduler"), knownvalue.StringExact("deficit round robin")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(true),
						"target":   knownvalue.Int32Exact(10),
						"interval": knownvalue.Int32Exact(10),
						"ecn":      knownvalue.Bool(true),
						"quantum":  knownvalue.Int32Exact(10),
						"limit":    knownvalue.Int32Exact(10),
						"flows":    knownvalue.Int32Exact(10),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("pie"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("delay"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_pipes.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper pipe for terraform resource testing")),
				},
			},
		},
	})
}

// testAccShaperPipesDataSourceConfig_id creates a traffic shaper pipe resource and imports it as a data source via its id.
const testAccShaperPipesDataSourceConfig_id = `
	resource "opnsense_firewall_shaper_pipes" "test_acc_data_source" {
		enabled   = true
		bandwidth = {
			value  = 10
			metric = "Kbit"
		}
		queue     = 10
		mask      = "src-ip"
		buckets   = 10
		scheduler = "deficit round robin"
		codel     = {
			enabled  = true
			target   = 10
			interval = 10
			ecn      = true
			quantum  = 10
			limit    = 10
			flows    = 10
		}
		pie         = false
		delay       = 10
		description = "traffic shaper pipe for terraform resource testing"
	}

	data "opnsense_firewall_shaper_pipes" "test_acc_data_source" {
		id = opnsense_firewall_shaper_pipes.test_acc_data_source.id
	}
`
