package overview

import (
	"fmt"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/utils"
)

const (
	controller = "overview"

	resourceName string = "interface"
)

// VerifyInterfaces checks if the specified list of interfaces exist on the OPNsense firewall.
func VerifyInterfaces(client *opnsense.Client, interfacesList *utils.Set) (bool, error) {
	for _, iface := range interfacesList.Elements() {
		ifaceExists, err := VerifyInterface(client, iface)
		if err != nil {
			return false, fmt.Errorf("%s", err)
		}

		if !ifaceExists {
			return false, nil
		}
	}
	return true, nil
}

// VerifyInterface checks if the specified interface exist on the OPNsense firewall.
func VerifyInterface(client *opnsense.Client, iface string) (bool, error) {
	ifaceExists, err := checkInterfaceExists(client, iface)
	if err != nil {
		return false, fmt.Errorf("Verify %s exists error: %s", resourceName, err)
	}

	if !ifaceExists {
		return false, nil
	}

	return true, nil
}
