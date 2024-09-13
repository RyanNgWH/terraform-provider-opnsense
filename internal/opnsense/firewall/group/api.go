package group

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

type addGroupResponse struct {
	Result      string          `json:"result"`
	Uuid        string          `json:"uuid"`
	Validations itemValidations `json:"validations"`
}

type setGroupResponse struct {
	Result      string          `json:"result"`
	Validations itemValidations `json:"validations"`
}

type deleteGroupResponse struct {
	Result string `json:"result"`
}

type applyConfigResponse struct {
	Status string `json:"status"`
}

type itemValidations struct {
	Name    string      `json:"group.ifname"`
	Members string      `json:"group.members"`
	Others  interface{} `json:"-"`
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
		return "", fmt.Errorf("search group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("search group http error: abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp searchGroupResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return "", fmt.Errorf("search group http error: %s", err)
	}

	for _, group := range resp.Rows {
		if group.IfName == name {
			return group.Uuid, nil
		}
	}

	return "", errors.New("group error: group does not exist")
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
		return nil, fmt.Errorf("get group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)

	}

	var resp getGroupResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return nil, fmt.Errorf("get group error (http): %s", err)
	}
	if reflect.DeepEqual(resp, getGroupResponse{}) {
		return nil, fmt.Errorf("get group error: group with uuid `%s` does not exist", uuid)
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
		return "", fmt.Errorf("add group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("add group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var addGroupResponse addGroupResponse
	err = json.NewDecoder(httpResp.Body).Decode(&addGroupResponse)
	if err != nil {
		return "", fmt.Errorf("add group error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(addGroupResponse.Result) == "failed" {
		return "", fmt.Errorf("add group error: failed to add alias to OPNsense - failed validations: %+v", addGroupResponse.Validations)
	}

	return addGroupResponse.Uuid, nil
}

// setGroup updates an existing group on the OPNsense firewall with a matching UUID.
func setGroup(client *opnsense.Client, group group, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, setGroupCommand, uuid)

	// Generate API body from group
	body := groupToHttpBody(group)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("set group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("set group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp setGroupResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("set group error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) == "failed" {
		return fmt.Errorf("set group error: failed to update group on OPNsense - failed validations: %+v", resp.Validations)
	}

	return nil
}

// deleteGroup removes an existing group from the OPNsense firewall with a matching UUID.
func deleteGroup(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", firewall.Module, controller, deleteGroupCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("delete group error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("delete group error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp deleteGroupResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("delete group error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("delete group error: failed to delete group on OPNsense. Please contact the provider maintainers for assistance")
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
		return fmt.Errorf("apply configuration error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp applyConfigResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("apply configuration error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Status) != "ok" {
		return fmt.Errorf("apply configuration error: failed to apply configuration on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
