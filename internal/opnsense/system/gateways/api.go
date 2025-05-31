package gateways

import (
	"encoding/json"
	"fmt"
	"net/http"

	"terraform-provider-opnsense/internal/opnsense"
)

const (
	gatewayModule        string = "routing"
	gatewayController    string = "settings"
	searchGatewayCommand string = "search_gateway"
)

// HTTP request bodies

type searchGatewayRequestBody struct {
	Current      int32    `json:"current"`
	RowCount     int32    `json:"rowCount"`
	SearchPhrase string   `json:"searchPhrase"`
	Sort         struct{} `json:"sort"`
}

// HTTP response types

type searchGatewayResponse struct {
	Rows     []gatewayType `json:"rows"`
	RowCount int32         `json:"rowCount"`
	Total    int32         `json:"total"`
	Current  int32         `json:"current"`
}

type gatewayType struct {
	Uuid string `json:"uuid"`
	Name string `json:"name"`
}

// Helper functions

// searchGateway searches the OPNsense firewall for the gateway with a matching name, returning its uuid if it exists.
func searchGateway(client *opnsense.Client, name string) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", gatewayModule, gatewayController, searchGatewayCommand)

	body := searchGatewayRequestBody{
		SearchPhrase: name,
		RowCount:     -1,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Search %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Search %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response searchGatewayResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Search %s error (http): %s", resourceName, err)
	}

	for _, gateway := range response.Rows {
		if gateway.Name == name {
			return gateway.Uuid, nil
		}
	}

	return "", nil
}
