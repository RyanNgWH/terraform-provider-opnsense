package sourcenat

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/utils"
)

const (
	sourceNatOpnsenseController string = "source_nat"

	addAutomationSourceNatCommand         opnsense.Command = "add_rule"
	getAutomationSourceNatCommand         opnsense.Command = "get_rule"
	setAutomationSourceNatCommand         opnsense.Command = "set_rule"
	deleteAutomationSourceNatCommand      opnsense.Command = "del_rule"
	applyAutomationSourceNatConfigCommand opnsense.Command = "apply"
)

// HTTP request bodies

type automationSourceNatRuleHttpBody struct {
	Rule automationSoureNatRuleRequest `json:"rule"`
}

type automationSoureNatRuleRequest struct {
	Enabled         uint8  `json:"enabled"`
	NoNat           uint8  `json:"nonat"`
	Sequence        int32  `json:"sequence"`
	Interface       string `json:"interface"`
	IpVersion       string `json:"ipprotocol"`
	Protocol        string `json:"protocol"`
	Source          string `json:"source_net"`
	SourceNot       uint8  `json:"source_not"`
	SourcePort      string `json:"source_port"`
	Destination     string `json:"destination_net"`
	DestinationNot  uint8  `json:"destination_not"`
	DestinationPort string `json:"destination_port"`
	Target          string `json:"target"`
	TargetPort      string `json:"target_port"`
	Log             uint8  `json:"log"`
	Categories      string `json:"categories"`
	Description     string `json:"description"`
}

// HTTP response types

type getAutomationSourceNatResponse struct {
	Rule automationSourceNatRuleResponse `json:"rule"`
}

type automationSourceNatRuleResponse struct {
	Enabled   uint8 `json:"enabled,string"`
	NoNat     uint8 `json:"nonat,string"`
	Sequence  int32 `json:"sequence,string"`
	Interface map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"interface"`
	IpVersion map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"ipprotocol"`
	Protocol map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"protocol"`
	Source          string `json:"source_net"`
	SourceNot       uint8  `json:"source_not,string"`
	SourcePort      string `json:"source_port"`
	Destination     string `json:"destination_net"`
	DestinationNot  uint8  `json:"destination_not,string"`
	DestinationPort string `json:"destination_port"`
	Target          string `json:"target"`
	TargetPort      string `json:"target_port"`
	Log             uint8  `json:"log,string"`
	Categories      map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"categories"`
	Description string `json:"description"`
}

// Helper functions

// automationSourceNatToHttpBody converts an automation source nat object to a automationSourceNatRuleHttpBody object for sending to the OPNsense API.
func automationSourceNatToHttpBody(automationSourceNat automationSourceNat) automationSourceNatRuleHttpBody {
	return automationSourceNatRuleHttpBody{
		Rule: automationSoureNatRuleRequest{
			Enabled:         utils.BoolToInt(automationSourceNat.Enabled),
			NoNat:           utils.BoolToInt(automationSourceNat.NoNat),
			Sequence:        automationSourceNat.Sequence,
			Interface:       automationSourceNat.Interface,
			IpVersion:       automationSourceNat.IpVersion,
			Protocol:        automationSourceNat.Protocol,
			Source:          automationSourceNat.Source,
			SourceNot:       utils.BoolToInt(automationSourceNat.SourceNot),
			SourcePort:      automationSourceNat.SourcePort,
			Destination:     automationSourceNat.Destination,
			DestinationNot:  utils.BoolToInt(automationSourceNat.DestinationNot),
			DestinationPort: automationSourceNat.DestinationPort,
			Target:          automationSourceNat.Target,
			TargetPort:      automationSourceNat.TargetPort,
			Log:             utils.BoolToInt(automationSourceNat.Log),
			Categories:      strings.Join(automationSourceNat.Categories, ","),
			Description:     automationSourceNat.Description,
		},
	}
}

// addAutomationSourceNatRule creates an automation source nat rule on the OPNsense firewall. Returns the UUID on successful creation.
func addAutomationSourceNatRule(client *opnsense.Client, automationSourceNat automationSourceNat) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, sourceNatOpnsenseController, addAutomationSourceNatCommand)

	// Generate API body from automation source nat rule object
	body := automationSourceNatToHttpBody(automationSourceNat)
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

// getAutomationSourceNatRule searches the OPNsense firewall for the automation source nat rule with a matching UUID.
func getAutomationSourceNatRule(client *opnsense.Client, uuid string) (*automationSourceNat, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, sourceNatOpnsenseController, getAutomationSourceNatCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response getAutomationSourceNatResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get %[1]s error: %[1]s with uuid `%[2]s` does not exist.\n\nIf this occurs in a resource block, it is usually because the %[1]s is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing %[1]s from the terraform state to rectify the error.", resourceName, uuid)
		}
		return nil, fmt.Errorf("Get %s error (http): %s", resourceName, err)
	}

	// Extract values from response
	var iface string
	for name, value := range response.Rule.Interface {
		if value.Selected == 1 {
			iface = name
		}
	}

	var ipVersion string
	for name, value := range response.Rule.IpVersion {
		if value.Selected == 1 {
			var exists bool
			ipVersion, exists = ipVersions.GetByValue(name)
			if !exists {
				return nil, fmt.Errorf("Get %s error: Ip version `%s` not supported. Please contact the provider maintainers.", resourceName, name)
			}
			break
		}
	}

	var protocol string
	for name, value := range response.Rule.Protocol {
		if value.Selected == 1 {
			protocol = strings.ToLower(name)
			break
		}
	}

	categories := make([]string, 0)
	for name, value := range response.Rule.Categories {
		if value.Selected == 1 && value.Value != "" {
			categoryName, err := category.GetCategoryName(client, name)
			if err != nil {
				return nil, fmt.Errorf("Get %s error: failed to get category - %s", resourceName, err)
			}

			categories = append(categories, categoryName)
		}
	}

	// Sort lists for predictable output
	sort.Strings(categories)

	return &automationSourceNat{
		Enabled:         response.Rule.Enabled == 1,
		NoNat:           response.Rule.NoNat == 1,
		Sequence:        response.Rule.Sequence,
		Interface:       iface,
		IpVersion:       ipVersion,
		Protocol:        protocol,
		Source:          response.Rule.Source,
		SourceNot:       response.Rule.SourceNot == 1,
		SourcePort:      response.Rule.SourcePort,
		Destination:     response.Rule.Destination,
		DestinationNot:  response.Rule.DestinationNot == 1,
		DestinationPort: response.Rule.DestinationPort,
		Target:          response.Rule.Target,
		TargetPort:      response.Rule.TargetPort,
		Log:             response.Rule.Log == 1,
		Categories:      categories,
		Description:     response.Rule.Description,
	}, nil
}

// setAutomationSourceNatRule updates an existing automation source nat rule on the OPNsense firewall with a matching UUID.
func setAutomationSourceNatRule(client *opnsense.Client, automationSourceNat automationSourceNat, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, sourceNatOpnsenseController, setAutomationSourceNatCommand, uuid)

	// Generate API body from automation source nat rule object
	body := automationSourceNatToHttpBody(automationSourceNat)
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

// deleteAutomationSourceNatRule removes an existing automation source nat rule from the OPNsense firewall with a matching UUID.
func deleteAutomationSourceNatRule(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, sourceNatOpnsenseController, deleteAutomationSourceNatCommand, uuid)

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

// applyAutomationSourceNatConfig applies the automation source nat configuration on the OPNsense firewall.
func applyAutomationSourceNatConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, sourceNatOpnsenseController, applyAutomationSourceNatConfigCommand)

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
