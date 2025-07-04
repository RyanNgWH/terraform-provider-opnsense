package category

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/utils"
)

const (
	searchCategoryCommand opnsense.Command = "searchItem"
	getCategoryCommand    opnsense.Command = "getItem"
	addCategoryCommand    opnsense.Command = "addItem"
	setCategoryCommand    opnsense.Command = "setItem"
	deleteAliasCommand    opnsense.Command = "delItem"
)

// HTTP request bodies

type searchCategoryRequestBody struct {
	Current      int32    `json:"current"`
	RowCount     int32    `json:"rowCount"`
	SearchPhrase string   `json:"searchPhrase"`
	Sort         struct{} `json:"sort"`
}

type categoryHttpBody struct {
	Category categoryRequest `json:"category"`
}

type categoryRequest struct {
	Name  string `json:"name"`
	Auto  uint8  `json:"auto"`
	Color string `json:"color"`
}

// HTTP response types

type searchCategoryResponse struct {
	Rows     []categoryType `json:"rows"`
	RowCount int32          `json:"rowCount"`
	Total    int32          `json:"total"`
	Current  int32          `json:"current"`
}

type getCategoryResponse struct {
	Category categoryType `json:"category"`
}

type categoryType struct {
	Uuid  string `json:"uuid"`
	Name  string `json:"name"`
	Auto  uint8  `json:"auto,string"`
	Color string `json:"color"`
}

// Helper functions

// categoryToHttpBody converts a Category object to an categoryToHttpBody object for sending to the OPNsense API.
func categoryToHttpBody(category category) categoryHttpBody {
	return categoryHttpBody{
		Category: categoryRequest{
			Name:  category.Name,
			Auto:  utils.BoolToInt(category.Auto),
			Color: category.Color,
		},
	}
}

// searchCategory searches the OPNsense firewall for the category with a matching name, returning its uuid if it exists.
func searchCategory(client *opnsense.Client, name string) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, searchCategoryCommand)

	body := searchCategoryRequestBody{
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

	var searchCategoryResponse searchCategoryResponse
	err = json.NewDecoder(httpResp.Body).Decode(&searchCategoryResponse)
	if err != nil {
		return "", fmt.Errorf("Search %s error (http): %s", resourceName, err)
	}

	for _, category := range searchCategoryResponse.Rows {
		if category.Name == name {
			return category.Uuid, nil
		}
	}

	return "", nil
}

// GetCategory searches the OPNsense firewall for the category with a matching uuid.
func GetCategory(client *opnsense.Client, uuid string) (*category, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, getCategoryCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var resp getCategoryResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return nil, fmt.Errorf("Get %s error (http): %s", resourceName, err)
	}
	if resp == (getCategoryResponse{}) {
		return nil, fmt.Errorf("Get %[1]s error: %[1]s with uuid `%s` does not exist", resourceName, uuid)
	}

	return &category{
		Name:  resp.Category.Name,
		Auto:  resp.Category.Auto == 1,
		Color: resp.Category.Color,
	}, nil
}

// GetCategoryName searches the OPNsense firewall for the category with a matching uuid and returns its name.
func GetCategoryName(client *opnsense.Client, uuid string) (string, error) {
	category, err := GetCategory(client, uuid)
	if err != nil {
		return "", err
	}
	return category.Name, nil
}

// addCategory creates a category on the OPNsense firewall. Returns the UUID on successful creation.
func addCategory(client *opnsense.Client, category category) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, addCategoryCommand)

	// Generate API body from alias
	body := categoryToHttpBody(category)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Add %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Add %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Add %s error (http): failed to decode http response - %s", resourceName, err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("Add %[1]s error: failed to add %[1]s to OPNsense - failed validations:\n%s", resourceName, opnsense.ValidationsToString(response.Validations))
	}

	return response.Uuid, nil
}

// setCategory updates an existing category on the OPNsense firewall with a matching UUID.
func setCategory(client *opnsense.Client, category category, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, setCategoryCommand, uuid)

	// Generate API body from alias
	body := categoryToHttpBody(category)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Set %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set %s error (http): failed to decode http response - %s", resourceName, err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set %[1]s error: failed to update %[1]s on OPNsense - failed validations:/n%s", resourceName, opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteCategory removes an existing alias from the OPNsense firewall with a matching UUID.
func deleteCategory(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, deleteAliasCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Delete %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Delete %s error (http): failed to decode http response - %s", resourceName, err)
	}

	if strings.ToLower(response.Result) != "deleted" && strings.ToLower(response.Result) != "not found" {
		return fmt.Errorf("Delete %s error: failed to delete alias on OPNsense. Please contact the provider maintainers for assistance", resourceName)
	}
	return nil
}
