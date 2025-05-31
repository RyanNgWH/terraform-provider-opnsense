package overview

import (
	"encoding/json"
	"fmt"
	"net/http"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/interfaces"
)

const (
	interfacesInfoCommand opnsense.Command = "interfacesInfo"
)

// HTTP request bodies

type interfacesInfoRequestBody struct {
	Current      int32
	RowCount     int32
	SearchPhrase string
	Sort         struct{}
}

// HTTP response types

type interfacesInfoResponse struct {
	Rows     []interfaceResponse `json:"rows"`
	RowCount int32               `json:"rowCount"`
	Total    int32               `json:"total"`
	Current  int32               `json:"current"`
}

type interfaceResponse struct {
	Identifier string `json:"identifier"`
}

// Helper functions

// CheckInterfaceExists searches the OPNsense firewall for the interface with a matching identifier.
func checkInterfaceExists(client *opnsense.Client, identifier string) (bool, error) {
	path := fmt.Sprintf("%s/%s/%s", interfaces.Module, controller, interfacesInfoCommand)

	body := interfacesInfoRequestBody{
		SearchPhrase: identifier,
		RowCount:     -1,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return false, fmt.Errorf("Check %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return false, fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return false, fmt.Errorf("Check %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var interfacesInfoResponse interfacesInfoResponse
	err = json.NewDecoder(httpResp.Body).Decode(&interfacesInfoResponse)
	if err != nil {
		return false, fmt.Errorf("Check %s error (http): %s", resourceName, err)
	}

	for _, iface := range interfacesInfoResponse.Rows {
		if iface.Identifier == identifier {
			return true, nil
		}
	}

	return false, nil
}
