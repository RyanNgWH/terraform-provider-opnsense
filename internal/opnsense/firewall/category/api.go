package category

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
)

const (
	searchCategoryCommand opnsense.Command = "searchItem"
	getCategoryCommand    opnsense.Command = "getItem"
)

// HTTP request bodies

type searchCategoryRequestBody struct {
	Current      int32    `json:"current"`
	RowCount     int32    `json:"rowCount"`
	SearchPhrase string   `json:"searchPhrase"`
	Sort         struct{} `json:"sort"`
}

// HTTP response types

type searchCategoryResponse struct {
	Rows     []searchCategoryType `json:"rows"`
	RowCount int32                `json:"rowCount"`
	Total    int32                `json:"total"`
	Current  int32                `json:"current"`
}

type getCategoryResponse struct {
	Category getCategoryType `json:"category"`
}

type searchCategoryType struct {
	Uuid  string `json:"uuid"`
	Name  string `json:"name"`
	Auto  uint8  `json:"auto,string"`
	Color string `json:"color"`
}

type getCategoryType struct {
	Name  string `json:"name"`
	Auto  uint8  `json:"auto,string"`
	Color string `json:"color"`
}

// Helper functions

// SearchCategory searches the OPNsense firewall for the category with a matching name
func SearchCategory(client *opnsense.Client, name string) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, searchCategoryCommand)

	body := searchCategoryRequestBody{
		SearchPhrase: name,
		RowCount:     -1,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("search category error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("search category http error: abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var searchCategoryResponse searchCategoryResponse
	err = json.NewDecoder(httpResp.Body).Decode(&searchCategoryResponse)
	if err != nil {
		return "", fmt.Errorf("search category http error: %s", err)
	}

	for _, category := range searchCategoryResponse.Rows {
		if category.Name == name {
			return category.Uuid, nil
		}
	}

	return "", errors.New("category error: category does not exist")
}

// GetCategory searches the OPNsense firewall for the category with a matching uuid
func GetCategory(client *opnsense.Client, uuid string) (*category, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, getCategoryCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("get category http error: abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp getCategoryResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return nil, fmt.Errorf("get category http error: %s", err)
	}
	if resp == (getCategoryResponse{}) {
		return nil, fmt.Errorf("get category error: category with uuid `%s` does not exist", uuid)
	}

	return &category{
		Name:  resp.Category.Name,
		Auto:  resp.Category.Auto == 1,
		Color: resp.Category.Color,
	}, nil
}

// GetCategoryName searches the OPNsense firewall for the category with a matching uuid and returns its name
func GetCategoryName(client *opnsense.Client, uuid string) (string, error) {
	category, err := GetCategory(client, uuid)
	if err != nil {
		return "", err
	}
	return category.Name, nil
}
