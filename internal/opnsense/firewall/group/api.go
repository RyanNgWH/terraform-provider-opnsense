package group

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
	searchGroupCommand opnsense.Command = "searchItem"
	getGroupCommand    opnsense.Command = "getItem"
	addGroupCommand    opnsense.Command = "addItem"
	setGroupCommand    opnsense.Command = "setItem"
	deleteGroupCommand opnsense.Command = "delItem"
	applyConfigCommand opnsense.Command = "reconfigure"
)

// HTTP request bodies

type groupHttpBody struct {
	Group groupRequest `json:"group"`
}

type groupRequest struct {
	IfName      string `json:"ifname"`
	Members     string `json:"members"`
	NoGroup     uint8  `json:"nogroup"`
	Sequence    int64  `json:"sequence"`
	Description string `json:"descr"`
}

type searchGroupRequestBody struct {
	Current      int32    `json:"current"`
	RowCount     int32    `json:"rowCount"`
	SearchPhrase string   `json:"searchPhrase"`
	Sort         struct{} `json:"sort"`
}

// HTTP response types

type searchGroupResponse struct {
	Rows     []searchGroupType `json:"rows"`
	RowCount int32             `json:"rowCount"`
	Total    int32             `json:"total"`
	Current  int32             `json:"current"`
}

type searchGroupType struct {
	Uuid        string `json:"uuid"`
	IfName      string `json:"ifname"`
	Description string `json:"descr"`
	Members     string `json:"members"`
	Sequence    uint8  `json:"sequence,string"`
}

type getGroupResponse struct {
	Group groupResponse `json:"group"`
}

type groupResponse struct {
	IfName  string `json:"ifname"`
	Members map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"members"`
	NoGroup     uint8  `json:"nogroup,string"`
	Sequence    int64  `json:"sequence,string"`
	Description string `json:"descr"`
}

// Helper functions

// groupToHttpBody converts a group object to a groupHttpBody object for sending to the OPNsense API.
func groupToHttpBody(group group) groupHttpBody {
	return groupHttpBody{
		Group: groupRequest{
			IfName:      group.Name,
			Members:     strings.Join(group.Members, ","),
			NoGroup:     utils.BoolToInt(group.NoGroup),
			Sequence:    group.Sequence,
			Description: group.Description,
		},
	}
}

// searchGroup searches the OPNsense firewall for the group with a matching name, returning its uuid if it exists.
func searchGroup(client *opnsense.Client, name string) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, searchGroupCommand)

	body := searchGroupRequestBody{
		SearchPhrase: name,
		RowCount:     -1,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Search group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Search group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp searchGroupResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return "", fmt.Errorf("Search group error (http): %s", err)
	}

	for _, group := range resp.Rows {
		if group.IfName == name {
			return group.Uuid, nil
		}
	}

	return "", errors.New("Search group error: group does not exist")
}

// getGroup searches the OPNsense firewall for the group with a matching UUID.
func getGroup(client *opnsense.Client, uuid string) (*group, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, getGroupCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	switch httpResp.StatusCode {
	case 200:
	default:
		return nil, fmt.Errorf("Get group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)

	}

	var resp getGroupResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get group error: group with uuid `%s` does not exist. This is potentially because the group is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing group from the terraform state to rectify the error.", uuid)
		}
		return nil, fmt.Errorf("Get group error (http): %s", err)
	}

	// Extract values from response
	var members []string
	for name, value := range resp.Group.Members {
		if value.Selected == 1 {
			members = append(members, name)
		}
	}

	// Sort lists for predictable output
	sort.Strings(members)

	return &group{
		Name:        resp.Group.IfName,
		Members:     members,
		NoGroup:     resp.Group.NoGroup == 1,
		Sequence:    resp.Group.Sequence,
		Description: resp.Group.Description,
	}, nil
}

// addGroup creates a group on the OPNsense firewall. Returns the UUID on successful creation.
func addGroup(client *opnsense.Client, group group) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, addGroupCommand)

	// Generate API body from group
	body := groupToHttpBody(group)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Add group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Add group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Add group error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("Add group error: failed to add alias to OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return response.Uuid, nil
}

// setGroup updates an existing group on the OPNsense firewall with a matching UUID.
func setGroup(client *opnsense.Client, group group, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, setGroupCommand, uuid)

	// Generate API body from group
	body := groupToHttpBody(group)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Set group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set group error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set group error: failed to update group on OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteGroup removes an existing group from the OPNsense firewall with a matching UUID.
func deleteGroup(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, deleteGroupCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Delete group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Delete group error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) != "deleted" && strings.ToLower(response.Result) != "not found" {
		return fmt.Errorf("Delete group error: failed to delete group on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}

// applyConfig applies the group configuration on the OPNsense firewall.
func applyConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", firewall.Module, controller, applyConfigCommand)

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
