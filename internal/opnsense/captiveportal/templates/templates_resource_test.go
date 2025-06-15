package templates_test

import (
	"testing"

	"terraform-provider-opnsense/internal/acctest"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCaptivePortalTemplatesResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCaptivePortalTemplatesResourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_captive_portal_templates.test_acc_resource_template", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_template")),
					statecheck.ExpectKnownValue("opnsense_captive_portal_templates.test_acc_resource_template", tfjsonpath.New("template"), knownvalue.StringExact("testdata/captive-portal-template-default.zip")),
					statecheck.ExpectKnownValue("opnsense_captive_portal_templates.test_acc_resource_template", tfjsonpath.New("template_hash"), knownvalue.StringExact("fd8d3b144ce974707f9fcb87567bdc9bca8d1ad2687fced47f7fc4fb60712c2185517f25c7aab6299879d66346203b74c8abbf4d5b2f5419858fefa132ea28aa")),
				},
			},
			// ImportState testing
			{
				ResourceName:      "opnsense_captive_portal_templates.test_acc_resource_template",
				ImportState:       true,
				ImportStateId:     "test_acc_template",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
					"template",
					"template_hash",
				},
			},
			// Update and Read testing
			{
				Config: testAccCaptivePortalTemplatesResourceConfig_modified,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("opnsense_captive_portal_templates.test_acc_resource_template", tfjsonpath.New("name"), knownvalue.StringExact("test_acc_template_modified")),
					statecheck.ExpectKnownValue("opnsense_captive_portal_templates.test_acc_resource_template", tfjsonpath.New("template"), knownvalue.StringExact("testdata/captive-portal-template-modified.zip")),
					statecheck.ExpectKnownValue("opnsense_captive_portal_templates.test_acc_resource_template", tfjsonpath.New("template_hash"), knownvalue.StringExact("cb63384fcd92239f53b648f0a0f66f4cd9967a681cc4f16f3d82ef4721c3566dcab4f22b751632c246e87526d62e758abcc15ec224084a75cc44ffd3a37727d0")),
				},
			},
			{
				ResourceName:      "opnsense_captive_portal_templates.test_acc_resource_template",
				ImportState:       true,
				ImportStateId:     "test_acc_template_modified",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
					"template",
					"template_hash",
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// testAccCaptivePortalTemplatesResourceConfig defines a captive portal template resource.
const testAccCaptivePortalTemplatesResourceConfig = `
	resource "opnsense_captive_portal_templates" "test_acc_resource_template" {
		name = "test_acc_template"
		template = "testdata/captive-portal-template-default.zip"
		template_hash = filesha512("testdata/captive-portal-template-default.zip")
	}
`

// testAccCaptivePortalTemplatesResourceConfig_modified defines a modified captive portal template resource.
const testAccCaptivePortalTemplatesResourceConfig_modified = `
	resource "opnsense_captive_portal_templates" "test_acc_resource_template" {
		name = "test_acc_template_modified"
		template = "testdata/captive-portal-template-modified.zip"
		template_hash = filesha512("testdata/captive-portal-template-modified.zip")
	}
`
