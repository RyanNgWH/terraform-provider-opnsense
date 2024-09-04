package category

import (
	"encoding/json"
	"errors"
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
	Rows     []searchCategoryType `json:"rows"`
	RowCount int32                `json:"rowCount"`
	Total    int32                `json:"total"`
	Current  int32                `json:"current"`
}

type getCategoryResponse struct {
	Category getCategoryType `json:"category"`
}

type addItemResponse struct {
	Result      string          `json:"result"`
	Uuid        string          `json:"uuid"`
	Validations itemValidations `json:"validations"`
}

type setItemResponse struct {
	Result      string          `json:"result"`
	Validations itemValidations `json:"validations"`
}

type delItemResponse struct {
	Result string `json:"result"`
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

type itemValidations struct {
	Name   string      `json:"category.name"`
	Color  string      `json:"category.color"`
	Others interface{} `json:"-"`
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

// SearchCategory searches the OPNsense firewall for the category with a matching name, returning its uuid if it exists.
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

// GetCategory searches the OPNsense firewall for the category with a matching uuid.
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
		return "", fmt.Errorf("add category error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("add category error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var addItemResponse addItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&addItemResponse)
	if err != nil {
		return "", fmt.Errorf("add category error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(addItemResponse.Result) == "failed" {
		return "", fmt.Errorf("add category error: failed to add category to OPNsense - failed validations: %+v", addItemResponse.Validations)
	}

	return addItemResponse.Uuid, nil
}

// setCategory updates an existing category on the OPNsense firewall with a matching UUID.
func setCategory(client *opnsense.Client, category category, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, setCategoryCommand, uuid)

	// Generate API body from alias
	body := categoryToHttpBody(category)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("set category error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("set category error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var setItemResponse setItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&setItemResponse)
	if err != nil {
		return fmt.Errorf("set category error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(setItemResponse.Result) == "failed" {
		return fmt.Errorf("set category error: failed to update category on OPNsense - failed validations: %+v", setItemResponse.Validations)
	}

	return nil
}

// deleteCategory removes an existing alias from the OPNsense firewall with a matching UUID.
func deleteCategory(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, deleteAliasCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("delete category error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("delete category error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp delItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("delete category error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("delete item error: failed to delete alias on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
