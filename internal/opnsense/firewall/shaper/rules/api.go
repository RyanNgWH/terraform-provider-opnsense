package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper"
	"terraform-provider-opnsense/internal/utils"
)

const (
	addShaperRuleCommand    opnsense.Command = "add_rule"
	getShaperRuleCommand    opnsense.Command = "get_rule"
	setShaperRuleCommand    opnsense.Command = "set_rule"
	deleteShaperRuleCommand opnsense.Command = "del_rule"
)

// HTTP request bodies

type shaperRuleHttpBody struct {
	Rule shaperRuleRequest `json:"rule"`
}

type shaperRuleRequest struct {
	Enabled         uint8                   `json:"enabled"`
	Sequence        int32                   `json:"sequence"`
	Interface       string                  `json:"interface"`
	Interface2      string                  `json:"interface2"`
	Protocol        string                  `json:"proto"`
	MaxPacketLength opnsense.Pint32AsString `json:"iplen"`
	Sources         string                  `json:"source"`
	SourceNot       uint8                   `json:"source_not"`
	SourcePort      string                  `json:"src_port"`
	Destinations    string                  `json:"destination"`
	DestinationNot  uint8                   `json:"destination_not"`
	DestinationPort string                  `json:"dst_port"`
	Dscp            string                  `json:"dscp"`
	Direction       string                  `json:"direction"`
	Target          string                  `json:"target"`
	Description     string                  `json:"description"`
}

// Helper functions

// shaperRuleToHttpBody converts a traffic shaper rule object to a shaperRuleToHttpBody object for sending to the OPNsense API.
func shaperRuleToHttpBody(shaperRule shaperRule) shaperRuleHttpBody {
	return shaperRuleHttpBody{
		Rule: shaperRuleRequest{
			Enabled:         utils.BoolToInt(shaperRule.Enabled),
			Sequence:        shaperRule.Sequence,
			Interface:       shaperRule.Interface,
			Interface2:      shaperRule.Interface2,
			Protocol:        shaperRule.Protocol,
			MaxPacketLength: opnsense.Pint32AsString(shaperRule.MaxPacketLength),
			Sources:         strings.Join(shaperRule.Sources, ","),
			SourceNot:       utils.BoolToInt(shaperRule.SourceNot),
			SourcePort:      shaperRule.SourcePort,
			Destinations:    strings.Join(shaperRule.Destinations, ","),
			DestinationNot:  utils.BoolToInt(shaperRule.DestinationNot),
			DestinationPort: shaperRule.DestinationPort,
			Dscp:            strings.Join(shaperRule.Dscp, ","),
			Direction:       shaperRule.Direction,
			Target:          shaperRule.Target,
			Description:     shaperRule.Description,
		},
	}
}

// HTTP Response types

type getShaperRuleResponse struct {
	Rule shaperRuleResponse `json:"rule"`
}

type shaperRuleResponse struct {
	Enabled   uint8 `json:"enabled,string"`
	Sequence  int32 `json:"sequence,string"`
	Interface map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"interface"`
	Interface2 map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"interface2"`
	Protocol map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"proto"`
	MaxPacketLength opnsense.Pint32AsString `json:"iplen"`
	Sources         map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"source"`
	SourceNot    uint8  `json:"source_not,string"`
	SourcePort   string `json:"source_port"`
	Destinations map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"destination"`
	DestinationNot  uint8  `json:"destination_not,string"`
	DestinationPort string `json:"destination_port"`
	Dscp            map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"dscp"`
	Direction map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"direction"`
	Target map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"target"`
	Description string `json:"description"`
}

// addShaperRule creates a traffic shaper rule on the OPNsense firewall. Returns the UUID on successful creation.
func addShaperRule(client *opnsense.Client, shaperRule shaperRule) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, addShaperRuleCommand)

	// Generate API body from traffic shaper rule object
	body := shaperRuleToHttpBody(shaperRule)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Add traffic shaper rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Add traffic shaper rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Add traffic shaper rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("Add traffic shaper rule error: failed to add traffic shaper rule to OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return response.Uuid, nil
}

// getShaperRule searches the OPNsense firewall for the traffic shaper rule with a matching UUID.
func getShaperRule(client *opnsense.Client, uuid string) (*shaperRule, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, getShaperRuleCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get traffic shaper rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response getShaperRuleResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get traffic shaper rule error: traffic shaper rule with uuid `%s` does not exist.\n\nIf this occurs in a resource block, it is usually because the traffic shaper rule is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing traffic shaper rule from the terraform state to rectify the error.", uuid)
		}
		return nil, fmt.Errorf("Get traffic shaper rule error (http): %s", err)
	}

	// Extract values from response
	var interface1 string
	for name, value := range response.Rule.Interface {
		if value.Selected == 1 {
			interface1 = name
			break
		}
	}

	var interface2 string
	for name, value := range response.Rule.Interface2 {
		if value.Selected == 1 {
			interface2 = name
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

	var sources []string
	for name, value := range response.Rule.Sources {
		if value.Selected == 1 {
			sources = append(sources, name)
		}
	}

	var destinations []string
	for name, value := range response.Rule.Destinations {
		if value.Selected == 1 {
			destinations = append(destinations, name)
		}

	}
	var dscp []string
	for name, value := range response.Rule.Dscp {
		if value.Selected == 1 {
			dscp = append(dscp, name)
		}
	}

	var direction string
	for name, value := range response.Rule.Direction {
		if value.Selected == 1 {
			direction = name
			break
		}

	}
	var target string
	for name, value := range response.Rule.Target {
		if value.Selected == 1 {
			target = name
			break
		}
	}

	return &shaperRule{
		Enabled:         response.Rule.Enabled == 1,
		Sequence:        response.Rule.Sequence,
		Interface:       interface1,
		Interface2:      interface2,
		Protocol:        protocol,
		MaxPacketLength: int32(response.Rule.MaxPacketLength),
		Sources:         sources,
		SourceNot:       response.Rule.SourceNot == 1,
		SourcePort:      response.Rule.SourcePort,
		Destinations:    destinations,
		DestinationNot:  response.Rule.DestinationNot == 1,
		DestinationPort: response.Rule.DestinationPort,
		Dscp:            dscp,
		Direction:       direction,
		Target:          target,
		Description:     response.Rule.Description,
	}, nil
}

// setShaperRule updates an existing traffic shaper rule on the OPNsense firewall with a matching UUID.
func setShaperRule(client *opnsense.Client, shaperRule shaperRule, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, setShaperRuleCommand, uuid)

	// Generate API body from traffic shaper rule object
	body := shaperRuleToHttpBody(shaperRule)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Set traffic shaper rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set traffic shaper rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set traffic shaper rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set traffic shaper rule error: failed to update traffic shaper rule on OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteShaperRule removes an existing traffic shaper rule from the OPNsense firewall with a matching UUID.
func deleteShaperRule(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, deleteShaperRuleCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete traffic shaper rule error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Delete traffic shaper rule error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("Delete traffic shaper rule error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("Delete traffic shaper rule error: failed to delete traffic shaper rule on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
