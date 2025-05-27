package queues_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccShaperQueuesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: testAccShaperQueuesDataSourceConfig_id,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("pipe"), knownvalue.StringExact("de21d36c-bd97-4477-9c2d-c4a8f23818d0")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("weight"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("mask"), knownvalue.StringExact("src-ip")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("buckets"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(true),
						"target":   knownvalue.Int32Exact(10),
						"interval": knownvalue.Int32Exact(10),
						"ecn":      knownvalue.Bool(true),
					})),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("pie"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_shaper_queues.test_acc_data_source", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper queue for terraform resource testing")),
				},
			},
		},
	})
}

// testAccShaperPipesDataSourceConfig_id creates a traffic shaper pipe resource and imports it as a data source via its id.
const testAccShaperQueuesDataSourceConfig_id = `
	resource "opnsense_firewall_shaper_queues" "test_acc_data_source" {
  enabled   = true
  pipe      = "de21d36c-bd97-4477-9c2d-c4a8f23818d0"
  weight    = 10
  mask      = "src-ip"
  buckets   = 10
  codel     = {
    enabled  = true
    target   = 10
    interval = 10
    ecn      = true
  }
  pie         = false
  description = "traffic shaper queue for terraform resource testing"
	}

	data "opnsense_firewall_shaper_queues" "test_acc_data_source" {
		id = opnsense_firewall_shaper_queues.test_acc_data_source.id
	}
`
