package alias

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/utils"
)

const (
	getAliasUuidCommand opnsense.Command = "getAliasUUID"
	getAliasCommand     opnsense.Command = "getItem"
	addAliasCommand     opnsense.Command = "addItem"
	setAliasCommand     opnsense.Command = "setItem"
	deleteAliasCommand  opnsense.Command = "delItem"
)

// HTTP errors
type getAliasStatusCodeError struct{}

func (e getAliasStatusCodeError) Error() string {
	return "get alias error (http): status code 500 in HTTP response. This is usually because the alias is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing alias from the terraform state to rectify the error. If you believe that this is not the case, please contact the provider for assistance"
}

// HTTP request bodies
type aliasHttpBody struct {
	Alias aliasRequest `json:"alias"`
}

type aliasRequest struct {
	Enabled     uint8   `json:"enabled"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Proto       string  `json:"proto"`
	Categories  string  `json:"categories"`
	UpdateFreq  float64 `json:"updatefreq"`
	Content     string  `json:"content"`
	Interface   string  `json:"interface"`
	Counters    uint8   `json:"counters"`
	Description string  `json:"description"`
}

// HTTP response types
type getAliasUuidResponse struct {
	Uuid string `json:"uuid"`
}

type getAliasResponse struct {
	Alias aliasResponse `json:"alias"`
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

type itemValidations struct {
	Name   string      `json:"alias.name"`
	Others interface{} `json:"-"`
}

type aliasResponse struct {
	Enabled   uint8  `json:"enabled,string"`
	Name      string `json:"name"`
	AliasType map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"type"`
	Proto map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"proto"`
	AliasInterface map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"interface"`
	Counters   opnsense.Uint8AsString   `json:"counters"`
	UpdateFreq opnsense.Float64AsString `json:"updatefreq"`
	Content    map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"content"`
	Categories map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"categories"`
	Description string `json:"description"`
}

// Helper functions

// aliasToHttpBody converts an Alias object to an aliasHttpBody object for sending to the OPNsense API
func aliasToHttpBody(alias alias) aliasHttpBody {
	return aliasHttpBody{
		Alias: aliasRequest{
			Enabled:     utils.BoolToInt(alias.Enabled),
			Name:        alias.Name,
			Type:        alias.Type,
			Proto:       strings.Join(alias.Proto, ","),
			Categories:  strings.Join(alias.Categories, ","),
			UpdateFreq:  alias.UpdateFreq,
			Content:     strings.Join(alias.Content, "\n"),
			Counters:    utils.BoolToInt(alias.Counters),
			Description: alias.Description,
		},
	}
}

// getAliasUuid searches the OPNsense firewall for the UUID of the alias with a matching name
func getAliasUuid(client *opnsense.Client, name string) (string, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, getAliasUuidCommand, name)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("get alias uuid error (http): Abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var uuidResponse getAliasUuidResponse
	err = json.NewDecoder(httpResp.Body).Decode(&uuidResponse)
	if err != nil {
		var unmarshalTypeError *json.UnmarshalTypeError

		// Alias does not exist
		if errors.As(err, &unmarshalTypeError) {
			return "", errors.New("get alias uuid error: Alias does not exist")
		}

		return "", err
	}

	return uuidResponse.Uuid, nil
}

// getAlias searches the OPNsense firewall for the alias with a matching UUID
func getAlias(client *opnsense.Client, uuid string) (*alias, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, getAliasCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	switch httpResp.StatusCode {
	case 200:
	case 500:
		return nil, getAliasStatusCodeError{}
	default:
		return nil, fmt.Errorf("get alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)

	}

	var aliasResponse getAliasResponse
	err = json.NewDecoder(httpResp.Body).Decode(&aliasResponse)
	if err != nil {
		return nil, fmt.Errorf("get alias error (http): %s", err)
	}
	if reflect.DeepEqual(aliasResponse, getAliasResponse{}) {
		return nil, fmt.Errorf("get alias error: alias with uuid `%s` does not exist", uuid)
	}

	// Extract values from response
	var aliasType string
	for name, value := range aliasResponse.Alias.AliasType {
		if value.Selected == 1 {
			aliasType = name
			break
		}
	}

	var protos []string
	for name, value := range aliasResponse.Alias.Proto {
		if value.Selected == 1 {
			protos = append(protos, name)
		}
	}

	var interfaces []string
	for name, value := range aliasResponse.Alias.AliasInterface {
		if value.Selected == 1 && strings.ToLower(value.Value) != "none" {
			interfaces = append(interfaces, name)
		}
	}

	var contents []string
	for name, value := range aliasResponse.Alias.Content {
		if value.Selected == 1 && value.Value != "" {
			contents = append(contents, name)
		}
	}

	var categories []string
	for name, value := range aliasResponse.Alias.Categories {
		if value.Selected == 1 && value.Value != "" {
			categoryName, err := category.GetCategoryName(client, name)
			if err != nil {
				return nil, fmt.Errorf("get alias error: failed to get category - %s", err)
			}

			categories = append(categories, categoryName)
		}
	}

	// Sort lists for predictable output
	sort.Strings(categories)
	sort.Strings(contents)
	sort.Strings(interfaces)

	return &alias{
		Enabled:     aliasResponse.Alias.Enabled == 1,
		Name:        aliasResponse.Alias.Name,
		Counters:    uint8(aliasResponse.Alias.Counters) == 1,
		UpdateFreq:  float64(aliasResponse.Alias.UpdateFreq),
		Description: aliasResponse.Alias.Description,
		Type:        aliasType,
		Proto:       protos,
		Interfaces:  interfaces,
		Content:     contents,
		Categories:  categories,
	}, nil
}

// addAlias creates an alias on the OPNsense firewall. Returns the UUID on successful creation.
func addAlias(client *opnsense.Client, alias alias) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, addAliasCommand)

	// Generate API body from alias
	body := aliasToHttpBody(alias)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("add alias error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("add alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var addItemResponse addItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&addItemResponse)
	if err != nil {
		return "", fmt.Errorf("add item error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(addItemResponse.Result) == "failed" {
		return "", fmt.Errorf("add item error: failed to add alias to OPNsense - failed validations: %+v", addItemResponse.Validations)
	}

	return addItemResponse.Uuid, nil
}

// setAlias updates an existing alias on the OPNsense firewall with a matching UUID
func setAlias(client *opnsense.Client, alias alias, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, setAliasCommand, uuid)

	// Generate API body from alias
	body := aliasToHttpBody(alias)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("set alias error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("set alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var setItemResponse setItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&setItemResponse)
	if err != nil {
		return fmt.Errorf("set item error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(setItemResponse.Result) == "failed" {
		return fmt.Errorf("set item error: failed to update alias on OPNsense - failed validations: %+v", setItemResponse.Validations)
	}

	return nil
}

// deleteAlias removes an existing alias from the OPNsense firewall with a matching UUID
func deleteAlias(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, deleteAliasCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("set alias error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("set alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp delItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("set item error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("delete item error: failed to delete alias on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
