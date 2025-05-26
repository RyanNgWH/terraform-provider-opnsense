package shaper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
)

const (
	ShaperSettingsController string = "settings"
	ShaperServiceController  string = "service"

	applyShaperCommand string = "reconfigure"
)

// applyShaperConfig applies the traffic shaper configuration on the OPNsense firewall.
func ApplyShaperConfig(client *opnsense.Client) error {
	path := fmt.Sprintf("%s/%s/%s", Module, ShaperServiceController, applyShaperCommand)

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
