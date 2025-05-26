package pipes_test

import (
	"terraform-provider-opnsense/internal/acctest"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccShaperPipeResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccShaperPipesResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("bandwidth"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"value":  knownvalue.Int32Exact(10),
						"metric": knownvalue.StringExact("Kbit"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("queue"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("mask"), knownvalue.StringExact("src-ip")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("buckets"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("scheduler"), knownvalue.StringExact("deficit round robin")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(true),
						"target":   knownvalue.Int32Exact(10),
						"interval": knownvalue.Int32Exact(10),
						"ecn":      knownvalue.Bool(true),
						"quantum":  knownvalue.Int32Exact(10),
						"limit":    knownvalue.Int32Exact(10),
						"flows":    knownvalue.Int32Exact(10),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("pie"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("delay"), knownvalue.Int32Exact(10)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("description"), knownvalue.StringExact("traffic shaper pipe for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_shaper_pipes.test_acc_resource_pipes",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: testAccShaperPipesResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("bandwidth"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"value":  knownvalue.Int32Exact(20),
						"metric": knownvalue.StringExact("Mbit"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("queue"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("mask"), knownvalue.StringExact("dst-ip")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("buckets"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("scheduler"), knownvalue.StringExact("flowqueue-codel")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(false),
						"target":   knownvalue.Int32Exact(20),
						"interval": knownvalue.Int32Exact(20),
						"ecn":      knownvalue.Bool(false),
						"quantum":  knownvalue.Int32Exact(20),
						"limit":    knownvalue.Int32Exact(20),
						"flows":    knownvalue.Int32Exact(20),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("pie"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("delay"), knownvalue.Int32Exact(20)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("description"), knownvalue.StringExact("[Updated] traffic shaper pipe for terraform resource testing")),
				},
			},
			{
				ResourceName:            "opnsense_firewall_shaper_pipes.test_acc_resource_pipes",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccShaperPipeResource_default(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccShaperPipesResourceConfig_default,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("bandwidth"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"value":  knownvalue.Int32Exact(10),
						"metric": knownvalue.StringExact("bit"),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("queue"), knownvalue.Int32Exact(-1)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("mask"), knownvalue.StringExact("none")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("buckets"), knownvalue.Int32Exact(-1)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("scheduler"), knownvalue.StringExact("weighted fair queueing")),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("codel"), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"enabled":  knownvalue.Bool(false),
						"target":   knownvalue.Int32Exact(-1),
						"interval": knownvalue.Int32Exact(-1),
						"ecn":      knownvalue.Bool(false),
						"quantum":  knownvalue.Int32Exact(-1),
						"limit":    knownvalue.Int32Exact(-1),
						"flows":    knownvalue.Int32Exact(-1),
					})),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("pie"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("delay"), knownvalue.Int32Exact(-1)),
					statecheck.ExpectKnownValue("opnsense_firewall_shaper_pipes.test_acc_resource_pipes", tfjsonpath.New("description"), knownvalue.StringExact("[Default] traffic shaper pipe for terraform resource testing")),
				},
			},
			// ImportState testing
			{
				ResourceName:            "opnsense_firewall_shaper_pipes.test_acc_resource_pipes",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccShaperPipesResourceConfig defines a traffic shaper pipe resource.
const testAccShaperPipesResourceConfig = `
	resource "opnsense_firewall_shaper_pipes" "test_acc_resource_pipes" {
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
`

// testAccShaperPipesResourceConfig_modified defines a modified traffic shaper pipe resource.
const testAccShaperPipesResourceConfig_modified = `
	resource "opnsense_firewall_shaper_pipes" "test_acc_resource_pipes" {
		enabled   = false
		bandwidth = {
			value  = 20
			metric = "Mbit"
		}
		queue     = 20
		mask      = "dst-ip"
		buckets   = 20
		scheduler = "flowqueue-codel"
		codel     = {
			enabled  = false
			target   = 20
			interval = 20
			ecn      = false
			quantum  = 20
			limit    = 20
			flows    = 20
		}
		pie         = true
		delay       = 20
		description = "[Updated] traffic shaper pipe for terraform resource testing"
	}
`

// testAccShaperPipesResourceConfig_default defines a modified traffic shaper pipe resource with default values.
const testAccShaperPipesResourceConfig_default = `
	resource "opnsense_firewall_shaper_pipes" "test_acc_resource_pipes" {
		bandwidth = {
			value  = 10
		}
		description = "[Default] traffic shaper pipe for terraform resource testing"
	}
`
