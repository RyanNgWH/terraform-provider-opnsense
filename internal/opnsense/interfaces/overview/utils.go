package overview

import (
	"fmt"
	"terraform-provider-opnsense/internal/opnsense"
)

const (
	controller = "overview"
)

// verifyInterfaces checks if the specified interfaces exist on the OPNsense firewall.
func VerifyInterfaces(client *opnsense.Client, interfacesList []string) (bool, error) {
	for _, iface := range interfacesList {
		ifaceExists, err := checkInterfaceExists(client, iface)
		if err != nil {
			return false, fmt.Errorf("failed to verify if interfaces exists on OPNsense - %s", err)
		}

		if !ifaceExists {
			return false, nil
		}
	}
	return true, nil
}
