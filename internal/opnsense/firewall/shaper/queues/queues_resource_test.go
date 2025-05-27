package queues_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccShaperQueuesResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccShaperQueuesResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("pipe"), knownvalue.StringExact("de21d36c-bd97-4477-9c2d-c4a8f23818d0")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("weight"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("mask"), knownvalue.StringExact("src-ip")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("buckets"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(true),
						"target":   knownvalue.Int32Exact(10),
						"interval": knownvalue.Int32Exact(10),
						"ecn":      knownvalue.Bool(true),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("pie"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper queue for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_shaper_queues.test_acc_resource_queue",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccShaperQueuesResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("pipe"), knownvalue.StringExact("58f5e010-9288-4d18-b8e1-bf5c219436e7")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("weight"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("mask"), knownvalue.StringExact("dst-ip")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("buckets"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(false),
						"target":   knownvalue.Int32Exact(20),
						"interval": knownvalue.Int32Exact(20),
						"ecn":      knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("pie"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("description"), knownvalue.StringExact("[Updated] traffic shaper queue for terraform resource testing")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_shaper_queues.test_acc_resource_queue",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccShaperQueuesResource_default(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccShaperQueuesResourceConfig_default,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("pipe"), knownvalue.StringExact("de21d36c-bd97-4477-9c2d-c4a8f23818d0")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("weight"), knownvalue.Int32Exact(100)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("mask"), knownvalue.StringExact("none")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("buckets"), knownvalue.Int32Exact(-1)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(false),
						"target":   knownvalue.Int32Exact(-1),
						"interval": knownvalue.Int32Exact(-1),
						"ecn":      knownvalue.Bool(false),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("pie"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_queues.test_acc_resource_queue", tfjsonpath.New("description"), knownvalue.StringExact("[Default] traffic shaper queue for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_shaper_queues.test_acc_resource_queue",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccShaperQueuesResourceConfig defines a traffic shaper queue resource.
const testAccShaperQueuesResourceConfig = `
	resource "opnsense_firewall_shaper_queues" "test_acc_resource_queue" {
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
`

// testAccShaperQueuesResourceConfig_modified defines a modified traffic shaper queue resource.
const testAccShaperQueuesResourceConfig_modified = `
	resource "opnsense_firewall_shaper_queues" "test_acc_resource_queue" {
  enabled   = false
  pipe      = "58f5e010-9288-4d18-b8e1-bf5c219436e7"
  weight    = 20
  mask      = "dst-ip"
  buckets   = 20
  codel     = {
    enabled  = false
    target   = 20
    interval = 20
    ecn      = false
  }
  pie         = true
  description = "[Updated] traffic shaper queue for terraform resource testing"
	}
`

// testAccShaperQueuesResourceConfig_default defines a traffic shaper queue resource with default values.
const testAccShaperQueuesResourceConfig_default = `
	resource "opnsense_firewall_shaper_queues" "test_acc_resource_queue" {
  pipe      = "de21d36c-bd97-4477-9c2d-c4a8f23818d0"
  description = "[Default] traffic shaper queue for terraform resource testing"
	}
`
