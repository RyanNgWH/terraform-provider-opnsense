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
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_id", tfjsonpath.New("name"), knownvalue.StringExact("perm_test_acc_data_source")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_id", tfjsonpath.New("auto"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_id", tfjsonpath.New("color"), knownvalue.StringExact("")),
				},
			},
			// Read testing (via name)
			{
				Config: acctest.ProviderConfig + testAccCategoryNameDataSourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_name", tfjsonpath.New("name"), knownvalue.StringExact("perm_test_acc_data_source")),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_name", tfjsonpath.New("auto"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("data.opnsense_firewall_category.test_acc_data_source_name", tfjsonpath.New("color"), knownvalue.StringExact("")),
				},
			},
		},
	})
}

// testAccCategoryIdDataSourceConfig imports a category as a data source by its id
const testAccCategoryIdDataSourceConfig = `
	data "opnsense_firewall_category" "test_acc_data_source_id" {
		id = "483aa27a-dad0-4285-b68c-f87abd37f41d"
	}

	output "test_acc_alias_host_id" {
		value = data.opnsense_firewall_category.test_acc_data_source_id
	}
`

// testAccCategoryNameDataSourceConfig imports a category as a data source by its name
const testAccCategoryNameDataSourceConfig = `
	data "opnsense_firewall_category" "test_acc_data_source_name" {
		name = "perm_test_acc_data_source"
	}

	output "test_acc_alias_host_name" {
		value = data.opnsense_firewall_category.test_acc_data_source_name
	}
`
