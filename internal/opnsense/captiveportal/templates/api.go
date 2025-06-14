package templates

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/captiveportal"
)

const (
	templatesOpnsenseController string = "service"

	addCaptivePortalTemplateCommand         opnsense.Command = "save_template"
	getCaptivePortalTemplateCommand         opnsense.Command = "get_template"
	setCaptivePortalTemplateCommand         opnsense.Command = "save_template"
	deleteCaptivePortalTemplateCommand      opnsense.Command = "del_template"
	applyCaptivePortalTemplateConfigCommand opnsense.Command = "reconfigure"
	searchCaptivePortalTemplateCommand      opnsense.Command = "search_templates"
)

// HTTP request bodies

type searchTemplatesRequestBody struct {
	Current      int32    `json:"current"`
	RowCount     int32    `json:"rowCount"`
	SearchPhrase string   `json:"searchPhrase"`
	Sort         struct{} `json:"sort"`
}

type captivePortalTemplateHttpBody struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Uuid    string `json:"uuid,omitempty"`
}

// HTTP response types

type searchTemplatesResponse struct {
	Rows     []captivePortalTemplateResponse `json:"rows"`
	RowCount int32                           `json:"rowCount"`
	Total    int32                           `json:"total"`
	Current  int32                           `json:"current"`
}

type captivePortalTemplateResponse struct {
	Uuid   string `json:"uuid"`
	Name   string `json:"name"`
	FileId string `json:"fileid"`
}

// captivePortalTemplateToHttpBody converts a captive portal tempalte object to a captivePortalTemplateToHttpBody object for sending to the OPNsense API.
func captivePortalTemplateToHttpBody(captivePortalTemplate captivePortalTemplate, uuid string) captivePortalTemplateHttpBody {
	return captivePortalTemplateHttpBody{
		Name:    captivePortalTemplate.Name,
		Content: captivePortalTemplate.TemplateBase64,
		Uuid:    uuid,
	}
}

// searchCaptivePortalTemplateName searches the OPNsense firewall for the captive portal template with a matching name, returning its uuid & file id if it exists.
func searchCaptivePortalTemplateName(client *opnsense.Client, name string) (string, string, error) {
	path := fmt.Sprintf("%s/%s/%s", captiveportal.Module, templatesController, searchCaptivePortalTemplateCommand)

	body := searchTemplatesRequestBody{
		SearchPhrase: name,
		RowCount:     -1,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("Search %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", "", fmt.Errorf("Search %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var searchTemplatesResponse searchTemplatesResponse
	err = json.NewDecoder(httpResp.Body).Decode(&searchTemplatesResponse)
	if err != nil {
		return "", "", fmt.Errorf("Search %s error (http): %s", resourceName, err)
	}

	for _, template := range searchTemplatesResponse.Rows {
		if template.Name == name {
			return template.Uuid, template.FileId, nil
		}
	}

	return "", "", nil
}

// searchCaptivePortalTemplateUuid searches the OPNsense firewall for the captive portal template with a matching uuid, returning its name & file id if it exists.
func searchCaptivePortalTemplateUuid(client *opnsense.Client, uuid string) (string, string, error) {
	path := fmt.Sprintf("%s/%s/%s", captiveportal.Module, templatesController, searchCaptivePortalTemplateCommand)

	body := searchTemplatesRequestBody{
		RowCount: -1,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("Search %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", "", fmt.Errorf("Search %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var searchTemplatesResponse searchTemplatesResponse
	err = json.NewDecoder(httpResp.Body).Decode(&searchTemplatesResponse)
	if err != nil {
		return "", "", fmt.Errorf("Search %s error (http): %s", resourceName, err)
	}

	for _, template := range searchTemplatesResponse.Rows {
		if template.Uuid == uuid {
			return template.Name, template.FileId, nil
		}
	}

	return "", "", nil
}

// addCaptivePortalTemplate creates a captive portal template on the OPNsense firewall. Returns the UUID and file id on successful creation.
func addCaptivePortalTemplate(client *opnsense.Client, captivePortalTemplate captivePortalTemplate) (string, string, error) {
	path := fmt.Sprintf("%s/%s/%s", captiveportal.Module, templatesOpnsenseController, addCaptivePortalTemplateCommand)

	// Generate API body from the captive portal template object
	body := captivePortalTemplateToHttpBody(captivePortalTemplate, "")
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("Add %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", "", fmt.Errorf("Add %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	// Check if captive portal template has been created on OPNsense
	uuid, fileid, err := searchCaptivePortalTemplateName(client, captivePortalTemplate.Name)
	if err != nil {
		return "", "", fmt.Errorf("Add %[1]s error: %[1]s not found on OPNsense. Please contact the provider for assistance", resourceName)
	}

	return uuid, fileid, nil
}

// getCaptivePortalTemplate searches the OPNsense firewall for the captive portal template with a matching UUID.
func getCaptivePortalTemplate(client *opnsense.Client, uuid string) (*captivePortalTemplate, error) {
	name, fileid, err := searchCaptivePortalTemplateUuid(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("Get %[1]s error: %[1]s with uuid `%[2]s` does not exist.\n\nIf this occurs in a resource block, it is usually because the %[1]s is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing %[1]s from the terraform state to rectify the error.", resourceName, uuid)
	}

	path := fmt.Sprintf("%s/%s/%s/%s", captiveportal.Module, templatesOpnsenseController, getCaptivePortalTemplateCommand, fileid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	// Extract values from response
	templateFile, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("Get %s error (http): failed to read file in http body. Please contact the provider for assistance", resourceName)
	}
	sha512Template := hex.EncodeToString(sha512.New().Sum(templateFile))

	return &captivePortalTemplate{
		TemplateSha512: sha512Template,
		Name:           name,
		FileId:         fileid,
	}, nil
}

// setCaptivePortalTemplate updates an existing captive portal template on the OPNsense firewall with a matching UUID. Returns the file id on successful update
func setCaptivePortalTemplate(client *opnsense.Client, captivePortalTemplate captivePortalTemplate, uuid string) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", captiveportal.Module, templatesController, setCaptivePortalTemplateCommand)

	// Generate API body from captive portal template object
	body := captivePortalTemplateToHttpBody(captivePortalTemplate, uuid)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Set %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Set %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	// Check if captive portal template has been created on OPNsense
	_, fileid, err := searchCaptivePortalTemplateName(client, captivePortalTemplate.Name)
	if err != nil {
		return "", fmt.Errorf("Add %[1]s error: %[1]s not found on OPNsense. Please contact the provider for assistance", resourceName)
	}

	return fileid, nil
}

// deleteCaptivePortalTemplate removes an existing captive portal template from the OPNsense firewall with a matching UUID.
func deleteCaptivePortalTemplate(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", captiveportal.Module, templatesController, deleteCaptivePortalTemplateCommand, uuid)

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

// applyCaptivePortalTemplateConfig applies the captive portal template configuration on the OPNsense firewall.
func applyCaptivePortalTemplateConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", captiveportal.Module, templatesController, applyCaptivePortalTemplateConfigCommand)

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
