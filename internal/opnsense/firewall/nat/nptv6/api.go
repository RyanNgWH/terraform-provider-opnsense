package nptv6

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/utils"
)

const (
	nptv6OpnsenseController string           = "npt"
	addNptv6Command         opnsense.Command = "add_rule"
	getNptv6Command         opnsense.Command = "get_rule"
	setNptv6Command         opnsense.Command = "set_rule"
	deleteNptv6Command      opnsense.Command = "del_rule"
	applyNptv6Command       opnsense.Command = "apply"
)

// HTTP request bodies

type nptv6HttpBody struct {
	Rule nptv6Request `json:"rule"`
}

type nptv6Request struct {
	Enabled        uint8  `json:"enabled"`
	Log            uint8  `json:"log"`
	Sequence       int32  `json:"sequence"`
	Interface      string `json:"interface"`
	InternalPrefix string `json:"source_net"`
	ExternalPrefix string `json:"destination_net"`
	TrackInterface string `json:"trackif"`
	Categories     string `json:"categories"`
	Description    string `json:"description"`
}

// HTTP Response types

type getNptv6Response struct {
	Rule nptv6RuleResponse `json:"rule"`
}

type nptv6RuleResponse struct {
	Enabled   uint8 `json:"enabled,string"`
	Log       uint8 `json:"log,string"`
	Sequence  int32 `json:"sequence,string"`
	Interface map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"interface"`
	InternalPrefix string `json:"source_net"`
	ExternalPrefix string `json:"destination_net"`
	TrackInterface map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"trackif"`
	Categories map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"categories"`
	Description string `json:"description"`
}

// Helper functions

// nptv6ToHttpBody converts a NPTv6 NAT object to a nptv6HttpBody object for sending to the OPNsense API.
func nptv6ToHttpBody(nptv6 nptv6) nptv6HttpBody {
	return nptv6HttpBody{
		Rule: nptv6Request{
			Enabled:        utils.BoolToInt(nptv6.Enabled),
			Log:            utils.BoolToInt(nptv6.Log),
			Sequence:       nptv6.Sequence,
			Interface:      nptv6.Interface,
			InternalPrefix: nptv6.InternalPrefix,
			ExternalPrefix: nptv6.ExternalPrefix,
			TrackInterface: nptv6.TrackInterface,
			Categories:     strings.Join(nptv6.Categories.Elements(), ","),
			Description:    nptv6.Description,
		},
	}
}

// addNptv6Nat creates a NPTv6 NAT entry on the OPNsense firewall. Returns the UUID on successful creation.
func addNptv6Nat(client *opnsense.Client, nptv6 nptv6) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, nptv6OpnsenseController, addNptv6Command)

	// Generate API body from one-to-one NAT object
	body := nptv6ToHttpBody(nptv6)
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

// getNptv6Nat searches the OPNsense firewall for the NPTv6 NAT rule with a matching UUID.
func getNptv6Nat(client *opnsense.Client, uuid string) (*nptv6, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, nptv6OpnsenseController, getNptv6Command, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response getNptv6Response
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get %[1]s error: %[1]s with uuid `%s` does not exist.\n\nIf this occurs in a resource block, it is usually because the %[1]s is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing %[1]s from the terraform state to rectify the error.", resourceName, uuid)
		}
		return nil, fmt.Errorf("Get %s error (http): %s", resourceName, err)
	}

	// Extract values from response
	var natInterface string
	for name, value := range response.Rule.Interface {
		if value.Selected == 1 {
			natInterface = name
			break
		}
	}

	var natTrackInterface string
	for name, value := range response.Rule.TrackInterface {
		if value.Selected == 1 {
			natTrackInterface = name
			break
		}
	}

	categories := utils.NewSet()
	for name, value := range response.Rule.Categories {
		if value.Selected == 1 && value.Value != "" {
			categoryName, err := category.GetCategoryName(client, name)
			if err != nil {
				return nil, fmt.Errorf("Get %s error: failed to get category - %s", resourceName, err)
			}

			categories.Add(categoryName)
		}
	}

	return &nptv6{
		Enabled:        response.Rule.Enabled == 1,
		Log:            response.Rule.Log == 1,
		Sequence:       int32(response.Rule.Sequence),
		Interface:      natInterface,
		InternalPrefix: response.Rule.InternalPrefix,
		ExternalPrefix: response.Rule.ExternalPrefix,
		TrackInterface: natTrackInterface,
		Categories:     categories,
		Description:    response.Rule.Description,
	}, nil
}

// setNptv6Nat updates an existing NATv6 NAT rule on the OPNsense firewall with a matching UUID.
func setNptv6Nat(client *opnsense.Client, nptv6 nptv6, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, nptv6OpnsenseController, setNptv6Command, uuid)

	// Generate API body from NPTv6 NAT object
	body := nptv6ToHttpBody(nptv6)
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
		return fmt.Errorf("Set %[1]s error: failed to update %[1]s on OPNsense - failed validations:\n%s", resourceName, opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteNptv6Nat removes an existing NPTv6 NAT rule from the OPNsense firewall with a matching UUID.
func deleteNptv6Nat(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, nptv6OpnsenseController, deleteNptv6Command, uuid)

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

	var resp opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("Delete %s error (http): failed to decode http response - %s", resourceName, err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("Delete %[1]s error: failed to delete %[1]s on OPNsense. Please contact the provider maintainers for assistance", resourceName)
	}
	return nil
}

// applyNptv6NatConfig applies the NPTv6 NAT configuration on the OPNsense firewall.
func applyNptv6NatConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, nptv6OpnsenseController, applyNptv6Command)

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

	var resp opnsense.OpnsenseApplyConfigResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("Apply configuration error (http): failed to decode http response - %s", err)
	}

	if strings.Trim(strings.ToLower(resp.Status), "\n") != "ok" {
		return fmt.Errorf("Apply configuration error: failed to apply configuration on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
