package category_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCategoryResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCategoryResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_category.test_acc_resource", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_category_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_category.test_acc_resource", tfjsonpath.New("auto"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("opnsense_firewall_category.test_acc_resource", tfjsonpath.New("color"), knownvalue.StringExact("000000")),
				},
			},
			// ImportState testing
			{
				ResourceName:      "opnsense_firewall_category.test_acc_resource",
				ImportState:       true,
				ImportStateId:     "test_acc_category_resource",
				ImportStateVerify: true,
				// The last_updated attribute does not exist in the HashiCups
				// API, therefore there is no value for it during import.
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + testAccCategoryResourceModifiedConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_firewall_category.test_acc_resource", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_category_resource")),
					statecheck.ExpectKnownValue("opnsense_firewall_category.test_acc_resource", tfjsonpath.New("auto"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("opnsense_firewall_category.test_acc_resource", tfjsonpath.New("color"), knownvalue.StringExact("")),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccCategoryResourceConfig defines a category resource.
const testAccCategoryResourceConfig = `
	resource "opnsense_firewall_category" "test_acc_resource" {
		name  = "test_acc_category_resource"
		auto  = true
		color = "000000"
	}
`

// testAccCategoryResourceModifiedConfig defines a category resource with a modified name.
const testAccCategoryResourceModifiedConfig = `
	resource "opnsense_firewall_category" "test_acc_resource" {
		name  = "test_acc_category_resource"
	}
`
