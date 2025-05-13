package nat

import (
	"encoding/json"
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
	addOneToOneNatCommand         opnsense.Command = "add_rule"
	getOneToOneNatCommand         opnsense.Command = "get_rule"
	setOneToOneNatCommand         opnsense.Command = "set_rule"
	deleteOneToOneNatCommand      opnsense.Command = "del_rule"
	applyOneToOneNatConfigCommand opnsense.Command = "apply"
)

// HTTP request bodies
type oneToOneNatHttpBody struct {
	Rule oneToOneNatRequest `json:"rule"`
}

type oneToOneNatRequest struct {
	Enabled        uint8  `json:"enabled"`
	Log            uint8  `json:"log"`
	Sequence       int32  `json:"sequence"`
	Interface      string `json:"interface"`
	Type           string `json:"type"`
	SourceNet      string `json:"source_net"`
	SourceNot      uint8  `json:"source_not"`
	DestinationNet string `json:"destination_net"`
	DestinationNot uint8  `json:"destination_not"`
	External       string `json:"external"`
	NatRefection   string `json:"natreflection"`
	Categories     string `json:"categories"`
	Description    string `json:"description"`
}

// HTTP Response types

type getOneToOneNatResponse struct {
	Rule oneToOneNatRuleResponse `json:"rule"`
}

type oneToOneNatRuleResponse struct {
	Enabled   uint8 `json:"enabled,string"`
	Log       uint8 `json:"log,string"`
	Sequence  int32 `json:"sequence,string"`
	Interface map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"interface"`
	Type map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"type"`
	SourceNet      string `json:"source_net"`
	SourceNot      uint8  `json:"source_not,string"`
	DestinationNet string `json:"destination_net"`
	DestinationNot uint8  `json:"destination_not,string"`
	External       string `json:"external"`
	NatReflection  map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"natreflection"`
	Categories map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"categories"`
	Description string `json:"description"`
}

// Helper functions

// oneToOneNatToHttpBody converts a one-to-one NAT object to an oneToOneNatHttpBody object for sending to the OPNsense API.
func oneToOneNatToHttpBody(oneToOneNat oneToOneNat) oneToOneNatHttpBody {
	return oneToOneNatHttpBody{
		Rule: oneToOneNatRequest{
			Enabled:        utils.BoolToInt(oneToOneNat.Enabled),
			Log:            utils.BoolToInt(oneToOneNat.Log),
			Sequence:       oneToOneNat.Sequence,
			Interface:      oneToOneNat.Interface,
			Type:           oneToOneNat.Type,
			SourceNet:      oneToOneNat.SourceNet,
			SourceNot:      utils.BoolToInt(oneToOneNat.SourceNot),
			DestinationNet: oneToOneNat.DestinationNet,
			DestinationNot: utils.BoolToInt(oneToOneNat.DestinationNot),
			External:       oneToOneNat.External,
			NatRefection:   oneToOneNat.NatRefection,
			Categories:     strings.Join(oneToOneNat.Categories, ","),
			Description:    oneToOneNat.Description,
		},
	}
}

// addOneToOneNat creates a one-to-one NAT entry on the OPNsense firewall. Returns the UUID on successful creation.
func addOneToOneNat(client *opnsense.Client, oneToOneNat oneToOneNat) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, oneToOneController, addOneToOneNatCommand)

	// Generate API body from one-to-one NAT object
	body := oneToOneNatToHttpBody(oneToOneNat)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("add one-to-one NAT rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("add one-to-one NAT rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("add one-to-one NAT rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("add one-to-one NAT rule error: failed to add one-to-one NAT rule to OPNsense - failed validations: %+v", response.Validations)
	}

	return response.Uuid, nil
}

// getOneToOneNat searches the OPNsense firewall for the one-to-one NAT rule with a matching UUID.
func getOneToOneNat(client *opnsense.Client, uuid string) (*oneToOneNat, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, oneToOneController, getOneToOneNatCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("get one-to-one NAT error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response getOneToOneNatResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("get one-to-one NAT rule error: one-to-one NAT rule with uuid `%s` does not exist. This is potentially because the one-to-one NAT rule is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing one-to-one NAT rule from the terraform state to rectify the error.", uuid)
		}
		return nil, fmt.Errorf("get one-to-one NAT rule error (http): %s", err)
	}

	// Extract values from response
	var natType string
	for name, value := range response.Rule.Type {
		if value.Selected == 1 {
			natType = name
			break
		}
	}

	var natInterface string
	for name, value := range response.Rule.Interface {
		if value.Selected == 1 {
			natInterface = name
			break
		}
	}

	var natReflection string
	for name, value := range response.Rule.NatReflection {
		if value.Selected == 1 {
			if strings.ToLower(value.Value) == "default" {
				natReflection = "default"
			} else {
				natReflection = name
			}
			break
		}
	}

	var categories []string
	for name, value := range response.Rule.Categories {
		if value.Selected == 1 && value.Value != "" {
			categoryName, err := category.GetCategoryName(client, name)
			if err != nil {
				return nil, fmt.Errorf("get one-to-one NAT rule error: failed to get category - %s", err)
			}

			categories = append(categories, categoryName)
		}
	}

	// Sort lists for predictable output
	sort.Strings(categories)

	return &oneToOneNat{
		Enabled:        response.Rule.Enabled == 1,
		Log:            response.Rule.Log == 1,
		Sequence:       int32(response.Rule.Sequence),
		Interface:      natInterface,
		Type:           natType,
		SourceNet:      response.Rule.SourceNet,
		SourceNot:      response.Rule.SourceNot == 1,
		DestinationNet: response.Rule.DestinationNet,
		DestinationNot: response.Rule.DestinationNot == 1,
		External:       response.Rule.External,
		NatRefection:   natReflection,
		Categories:     categories,
		Description:    response.Rule.Description,
	}, nil
}

// setOneToOneNat updates an existing one-to-one NAT rule on the OPNsense firewall with a matching UUID.
func setOneToOneNat(client *opnsense.Client, oneToOneNat oneToOneNat, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, oneToOneController, setOneToOneNatCommand, uuid)

	// Generate API body from one-to-one NAT object
	body := oneToOneNatToHttpBody(oneToOneNat)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("set one-to-one NAT rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("set one-to-one NAT rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("set one-to-one NAT rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("set one-to-one NAT rule error: failed to update one-to-one NAT rule on OPNsense - failed validations: %+v", response.Validations)
	}

	return nil
}

// deleteOneToOneNat removes an existing one-to-one NAT rule from the OPNsense firewall with a matching UUID.
func deleteOneToOneNat(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, oneToOneController, deleteOneToOneNatCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("delete one-to-one NAT rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("delete one-to-one NAT rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("delete one-to-one NAT rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("delete one-to-one NAT rule error: failed to delete one-to-one NAT rule on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}

// applyOneToOneNatConfig applies the one-to-one NAT configuration on the OPNsense firewall.
func applyOneToOneNatConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, oneToOneController, applyOneToOneNatConfigCommand)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("apply configuration error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("apply configuration error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp opnsense.OpnsenseApplyConfigResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("apply configuration error (http): failed to decode http response - %s", err)
	}

	if strings.Trim(strings.ToLower(resp.Status), "\n") != "ok" {
		return fmt.Errorf("apply configuration error: failed to apply configuration on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
