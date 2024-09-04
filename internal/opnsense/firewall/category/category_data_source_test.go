package category_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCategoryDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing (via id)
			{
				Config: acctest.ProviderConfig + testAccCategoryIdDataSourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_id", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_category_resource")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_id", tfjsonpath.New("auto"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_id", tfjsonpath.New("color"), knownvalue.StringExact("000000")),
				},
			},
			// Read testing (via name)
			{
				Config: acctest.ProviderConfig + testAccCategoryNameDataSourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_name", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_category_resource")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_name", tfjsonpath.New("auto"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_name", tfjsonpath.New("color"), knownvalue.StringExact("000000")),
				},
			},
		},
	})
}

// testAccCategoryIdDataSourceConfig creates a category before importing it as a data source by its id.
const testAccCategoryIdDataSourceConfig = `
	resource "opnsense_firewall_category" "test_acc_resource" {
		name  = "test_acc_category_resource"
		auto  = true
		color = "000000"
	}

	data "opnsense_firewall_category" "test_acc_data_source_id" {
		id = opnsense_firewall_category.test_acc_resource.id
	}

	output "test_acc_alias_host_id" {
		value = data.opnsense_firewall_category.test_acc_data_source_id
	}
`

// testAccCategoryNameDataSourceConfig creates a category before importing it as a data source by its name.
const testAccCategoryNameDataSourceConfig = `
	resource "opnsense_firewall_category" "test_acc_resource" {
		name  = "test_acc_category_resource"
		auto  = true
		color = "000000"
	}

	data "opnsense_firewall_category" "test_acc_data_source_name" {
		name = opnsense_firewall_category.test_acc_resource.name
	}

	output "test_acc_alias_host_name" {
		value = data.opnsense_firewall_category.test_acc_data_source_name
	}
`
