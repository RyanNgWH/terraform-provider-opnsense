package acctest

import (
	"os"
	"testing"

	"terraform-provider-opnsense/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	// ProviderConfig is a shared configuration to combine with the actual
	// test configuration so the opnsense client is properly configured.
	ProviderConfig = `
		provider "opnsense" {
			insecure   = true
		}
	`
)

// TestAccProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var TestAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"opnsense": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// testAccPreCheck validates the necessary test API keys exist in the testing environment
func TestAccPreCheck(t *testing.T) {
	if env := os.Getenv("OPNSENSE_ENDPOINT"); env == "" {
		t.Fatal("OPNSENSE_ENDPOINT must be set for acceptance tests")
	}
	if env := os.Getenv("OPNSENSE_API_KEY"); env == "" {
		t.Fatal("OPNSENSE_API_KEY must be set for acceptance tests")
	}
	if env := os.Getenv("OPNSENSE_API_SECRET"); env == "" {
		t.Fatal("OPNSENSE_API_SECRET must be set for acceptance tests")
	}
}
