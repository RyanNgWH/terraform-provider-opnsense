package filter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/utils"
)

const (
	addAutomationFilterCommand         opnsense.Command = "add_rule"
	getAutomationFilterCommand         opnsense.Command = "get_rule"
	setAutomationFilterCommand         opnsense.Command = "set_rule"
	deleteAutomationFilterCommand      opnsense.Command = "del_rule"
	applyAutomationFilterConfigCommand opnsense.Command = "apply"
)

// HTTP request bodies

type automationFilterRuleHttpBody struct {
	Rule automationFilterRuleRequest `json:"rule"`
}

type automationFilterRuleRequest struct {
	Enabled         uint8  `json:"enabled"`
	Sequence        int32  `json:"sequence"`
	Action          string `json:"action"`
	Quick           uint8  `json:"quick"`
	Interfaces      string `json:"interface"`
	Direction       string `json:"direction"`
	IpVersion       string `json:"ipprotocol"`
	Protocol        string `json:"protocol"`
	Source          string `json:"source_net"`
	SourceNot       uint8  `json:"source_not"`
	SourcePort      string `json:"source_port"`
	Destination     string `json:"destination"`
	DestinationNot  uint8  `json:"destination_not"`
	DestinationPort string `json:"destination_port"`
	Gateway         string `json:"gateway"`
	Log             uint8  `json:"log"`
	Categories      string `json:"categories"`
	Description     string `json:"description"`
}

// HTTP response types
type getAutomationFilterResponse struct {
	Rule automationFilterRuleResponse `json:"rule"`
}

type automationFilterRuleResponse struct {
	Enabled  uint8 `json:"enabled,string"`
	Sequence int32 `json:"sequence,string"`
	Action   map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"action"`
	Quick      uint8 `json:"quick,string"`
	Interfaces map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"interface"`
	Direction map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"direction"`
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
	Gateway         map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"gateway"`
	Log        uint8 `json:"log,string"`
	Categories map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"categories"`
	Description string `json:"description"`
}

// Helper functions

// automationFilterToHttpBody converts a automation filter rule object to a automationFilterToHttpBody object for sending to the OPNsense API.
func automationFilterToHttpBody(automationFilter automationFilter) automationFilterRuleHttpBody {
	return automationFilterRuleHttpBody{
		Rule: automationFilterRuleRequest{
			Enabled:         utils.BoolToInt(automationFilter.Enabled),
			Sequence:        automationFilter.Sequence,
			Action:          automationFilter.Action,
			Quick:           utils.BoolToInt(automationFilter.Quick),
			Interfaces:      strings.Join(automationFilter.Interfaces, ","),
			Direction:       automationFilter.Direction,
			IpVersion:       automationFilter.IpVersion,
			Protocol:        automationFilter.Protocol,
			Source:          automationFilter.Source,
			SourceNot:       utils.BoolToInt(automationFilter.SourceNot),
			SourcePort:      automationFilter.SourcePort,
			Destination:     automationFilter.Destination,
			DestinationNot:  utils.BoolToInt(automationFilter.DestinationNot),
			DestinationPort: automationFilter.DestinationPort,
			Gateway:         automationFilter.Gateway,
			Log:             utils.BoolToInt(automationFilter.Log),
			Categories:      strings.Join(automationFilter.Categories, ","),
			Description:     automationFilter.Description,
		},
	}
}

// addAutomationFilterRule creates a automation filter rule on the OPNsense firewall. Returns the UUID on successful creation.
func addAutomationFilterRule(client *opnsense.Client, automationFilter automationFilter) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, filterController, addAutomationFilterCommand)

	// Generate API body from automation filter rule object
	body := automationFilterToHttpBody(automationFilter)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Add automation filter rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Add automation filter rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Add automation filter rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("Add automation filter rule error: failed to add automation filter rule to OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return response.Uuid, nil
}

// getAutomationFilterRule searches the OPNsense firewall for the automation filter rule with a matching UUID.
func getAutomationFilterRule(client *opnsense.Client, uuid string) (*automationFilter, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, filterController, getAutomationFilterCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get automation filter rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response getAutomationFilterResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get automation filter rule error: automation filter rule with uuid `%s` does not exist.\n\nIf this occurs in a resource block, it is usually because the automation filter rule is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing automation filter rule from the terraform state to rectify the error.", uuid)
		}
		return nil, fmt.Errorf("Get automation filter rule error (http): %s", err)
	}

	// Extract values from response
	var action string
	for name, value := range response.Rule.Action {
		if value.Selected == 1 {
			action = name
			break
		}
	}

	var interfaces []string
	for name, value := range response.Rule.Interfaces {
		if value.Selected == 1 {
			interfaces = append(interfaces, name)
		}
	}

	var direction string
	for name, value := range response.Rule.Direction {
		if value.Selected == 1 {
			direction = name
			break
		}
	}

	var ipVersion string
	for name, value := range response.Rule.IpVersion {
		if value.Selected == 1 {
			var exists bool
			direction, exists = ipVersions.GetByValue(name)
			if !exists {
				return nil, fmt.Errorf("Get automation filter rule error: Ip version `%s` not supported. Please contact the provider maintainers.", name)
			}
			break
		}
	}

	var protocol string
	for name, value := range response.Rule.Protocol {
		if value.Selected == 1 {
			protocol = name
			break
		}
	}

	var gateway string
	for name, value := range response.Rule.Gateway {
		if value.Selected == 1 {
			gateway = name
			break
		}
	}

	var categories []string
	for name, value := range response.Rule.Categories {
		if value.Selected == 1 {
			categories = append(categories, name)
		}

	}

	// Sort lists for predictable output
	sort.Strings(interfaces)
	sort.Strings(categories)

	return &automationFilter{
		Enabled:         response.Rule.Enabled == 1,
		Sequence:        response.Rule.Sequence,
		Action:          action,
		Quick:           response.Rule.Quick == 1,
		Interfaces:      interfaces,
		Direction:       direction,
		IpVersion:       ipVersion,
		Protocol:        protocol,
		Source:          response.Rule.Source,
		SourceNot:       response.Rule.SourceNot == 1,
		SourcePort:      response.Rule.SourcePort,
		Destination:     response.Rule.Destination,
		DestinationNot:  response.Rule.DestinationNot == 1,
		DestinationPort: response.Rule.DestinationPort,
		Gateway:         gateway,
		Log:             response.Rule.Log == 1,
		Categories:      categories,
		Description:     response.Rule.Description,
	}, nil
}

// setAutomationFilterRule updates an existing automation filter rule on the OPNsense firewall with a matching UUID.
func setAutomationFilterRule(client *opnsense.Client, automationFilter automationFilter, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, filterController, setAutomationFilterCommand, uuid)

	// Generate API body from automation filter rule object
	body := automationFilterToHttpBody(automationFilter)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Set automation filter rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set automation filter rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set automation filter rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set automation filter rule error: failed to update traffic shaper rule on OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteAutomationFilterRule removes an existing automation filter rule from the OPNsense firewall with a matching UUID.
func deleteAutomationFilterRule(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, filterController, deleteAutomationFilterCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete automation filter rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Delete automation filter rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("Delete automation filter rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("Delete automation filter rule error: failed to delete automation filter rule on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}

// applyAutomationFilterConfig applies the automation filter configuration on the OPNsense firewall.
func applyAutomationFilterConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, filterController, applyAutomationFilterConfigCommand)

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
