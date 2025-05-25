package alias

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

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
	getGeoIpCommand     opnsense.Command = "getGeoIP"
	setGeoIPCommand     opnsense.Command = "set"
	applyConfigCommand  opnsense.Command = "reconfigure"
)

// HTTP errors

type getAliasStatusCodeError struct{}

func (e getAliasStatusCodeError) Error() string {
	return "Get alias error (http): status code 500 in HTTP response. This is usually because the alias is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing alias from the terraform state to rectify the error. If you believe that this is not the case, please contact the provider for assistance"
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

type setHttpRequest struct {
	Alias setAliasRequest `json:"alias"`
}

type setAliasRequest struct {
	GeoIp geoIpRequest `json:"geoip"`
}

type geoIpRequest struct {
	Url string `json:"url"`
}

// HTTP response types

type getAliasUuidResponse struct {
	Uuid string `json:"uuid"`
}

type getAliasResponse struct {
	Alias aliasResponse `json:"alias"`
}

type getGeoIpResponse struct {
	Alias struct {
		GeoIp geoIpResponse `json:"geoip"`
	} `json:"alias"`
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

type geoIpResponse struct {
	AddressCount   int64 `json:"address_count"`
	AddressSources struct {
		Ipv4 string `json:"IPv4"`
		Ipv6 string `json:"IPv6"`
	} `json:"address_sources"`
	FileCount         int64  `json:"file_count"`
	LocationsFilename string `json:"locations_filename"`
	Timestamp         string `json:"timestamp"`
	Url               string `json:"url"`
	Usages            int64  `json:"usages"`
}

// Helper functions

// aliasToHttpBody converts an Alias object to an aliasHttpBody object for sending to the OPNsense API.
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
			Interface:   alias.Interface,
		},
	}
}

// getAliasUuid searches the OPNsense firewall for the UUID of the alias with a matching name.
func getAliasUuid(client *opnsense.Client, name string) (string, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, getAliasUuidCommand, name)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Get alias uuid error (http): Abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var uuidResponse getAliasUuidResponse
	err = json.NewDecoder(httpResp.Body).Decode(&uuidResponse)
	if err != nil {
		var unmarshalTypeError *json.UnmarshalTypeError

		// Alias does not exist
		if errors.As(err, &unmarshalTypeError) {
			return "", errors.New("Get alias uuid error: Alias does not exist")
		}

		return "", err
	}

	return uuidResponse.Uuid, nil
}

// getAlias searches the OPNsense firewall for the alias with a matching UUID.
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
		return nil, fmt.Errorf("Get alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)

	}

	var aliasResponse getAliasResponse
	err = json.NewDecoder(httpResp.Body).Decode(&aliasResponse)
	if err != nil {
		return nil, fmt.Errorf("Get alias error (http): %s", err)
	}
	if reflect.DeepEqual(aliasResponse, getAliasResponse{}) {
		return nil, fmt.Errorf("Get alias error: alias with uuid `%s` does not exist", uuid)
	}

	// Extract values from response
	var aliasType string
	for name, value := range aliasResponse.Alias.AliasType {
		if value.Selected == 1 {
			aliasType = name
			break
		}
	}

	protos := make([]string, 0)
	for name, value := range aliasResponse.Alias.Proto {
		if value.Selected == 1 {
			protos = append(protos, name)
		}
	}

	contents := make([]string, 0)
	for name, value := range aliasResponse.Alias.Content {
		if value.Selected == 1 && value.Value != "" {
			contents = append(contents, name)
		}
	}

	categories := make([]string, 0)
	for name, value := range aliasResponse.Alias.Categories {
		if value.Selected == 1 && value.Value != "" {
			categoryName, err := category.GetCategoryName(client, name)
			if err != nil {
				return nil, fmt.Errorf("Get alias error: failed to get category - %s", err)
			}

			categories = append(categories, categoryName)
		}
	}

	var aliasInterface string
	for name, value := range aliasResponse.Alias.AliasInterface {
		if value.Selected == 1 {
			aliasInterface = name
			break
		}
	}

	// Sort lists for predictable output
	sort.Strings(categories)
	sort.Strings(contents)

	return &alias{
		Enabled:     aliasResponse.Alias.Enabled == 1,
		Name:        aliasResponse.Alias.Name,
		Counters:    uint8(aliasResponse.Alias.Counters) == 1,
		UpdateFreq:  float64(aliasResponse.Alias.UpdateFreq),
		Description: aliasResponse.Alias.Description,
		Type:        aliasType,
		Proto:       protos,
		Interface:   aliasInterface,
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
		return "", fmt.Errorf("Add alias error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Add alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Add alias error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("Add alias error: failed to add alias to OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return response.Uuid, nil
}

// setAlias updates an existing alias on the OPNsense firewall with a matching UUID.
func setAlias(client *opnsense.Client, alias alias, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, setAliasCommand, uuid)

	// Generate API body from alias
	body := aliasToHttpBody(alias)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Set alias error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set alias error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set alias error: failed to update alias on OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteAlias removes an existing alias from the OPNsense firewall with a matching UUID.
func deleteAlias(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, deleteAliasCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete alias error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Delete alias error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Delete alias error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) != "deleted" && strings.ToLower(response.Result) != "not found" {
		return fmt.Errorf("Delete alias error: failed to delete alias on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}

// getGeoIp gets the GeoIP configuration from the OPNsense firewall.
func getGeoIp(client *opnsense.Client) (*geoip, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, getGeoIpCommand)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	switch httpResp.StatusCode {
	case 200:
	default:
		return nil, fmt.Errorf("Get geoip error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)

	}

	var getGeoIpResponse getGeoIpResponse
	err = json.NewDecoder(httpResp.Body).Decode(&getGeoIpResponse)
	if err != nil {
		return nil, fmt.Errorf("Get geoip error (http): %s", err)
	}

	// Convert timestamp to RFC3339 format
	timestamp := ""
	if getGeoIpResponse.Alias.GeoIp.Timestamp != "" {
		tstamp, err := time.Parse("2006-01-02T15:04:05", getGeoIpResponse.Alias.GeoIp.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("Format timestamp error: %s", err)
		}
		timestamp = tstamp.Format(time.RFC3339)
	}

	return &geoip{
		AddressCount: getGeoIpResponse.Alias.GeoIp.AddressCount,
		AddressSources: struct {
			Ipv4 string
			Ipv6 string
		}{
			Ipv4: getGeoIpResponse.Alias.GeoIp.AddressSources.Ipv4,
			Ipv6: getGeoIpResponse.Alias.GeoIp.AddressSources.Ipv6,
		},
		FileCount:         getGeoIpResponse.Alias.GeoIp.FileCount,
		LocationsFilename: getGeoIpResponse.Alias.GeoIp.LocationsFilename,
		Timestamp:         timestamp,
		Url:               getGeoIpResponse.Alias.GeoIp.Url,
		Usages:            getGeoIpResponse.Alias.GeoIp.Usages,
	}, nil
}

// setGeoIp sets the GeoIP url in the OPNsense firewall.
func setGeoIp(client *opnsense.Client, url string) error {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, setGeoIPCommand)

	// Generate API body
	body := setHttpRequest{
		Alias: setAliasRequest{
			GeoIp: geoIpRequest{
				Url: url,
			},
		},
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Set geoip error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set geoip error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set geoip error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set geoip error: failed to set geoip on OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// applyConfig applies the alias configuration on the OPNsense firewall.
func applyConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, applyConfigCommand)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Apply configuration error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Apply configuration error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseApplyConfigResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Apply configuration error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Status) != "ok" {
		return fmt.Errorf("Apply configuration error: failed to apply configuration on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
