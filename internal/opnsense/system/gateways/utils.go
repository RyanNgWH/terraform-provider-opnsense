package gateways

import (
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
)

// VerifyGateway checks if the specified gateway exist on the OPNsense firewall.
func VerifyGateway(client *opnsense.Client, gateway string) (bool, error) {
	uuid, err := searchGateway(client, gateway)
	if err != nil {
		return false, fmt.Errorf("Verify gateway exists error: %s", err)
	}

	if uuid == "" {
		return false, nil
	}

	return true, nil
}
