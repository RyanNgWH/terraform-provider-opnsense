package gateways

import (
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
)

const (
	resourceName string = "gateway"
)

// VerifyGateway checks if the specified gateway exist on the OPNsense firewall.
func VerifyGateway(client *opnsense.Client, gateway string) (bool, error) {
	uuid, err := searchGateway(client, gateway)
	if err != nil {
		return false, fmt.Errorf("Verify %s exists error: %s", resourceName, err)
	}

	if uuid == "" {
		return false, nil
	}

	return true, nil
}
