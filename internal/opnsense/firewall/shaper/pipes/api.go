package pipes

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
	addShaperPipeCommand    opnsense.Command = "add_pipe"
	getShaperPipeCommand    opnsense.Command = "get_pipe"
	setShaperPipeCommand    opnsense.Command = "set_pipe"
	deleteShaperPipeCommand opnsense.Command = "del_pipe"
)

// HTTP request bodies

type shaperPipeHttpBody struct {
	Pipe shaperPipeRequest `json:"pipe"`
}

type shaperPipeRequest struct {
	Enabled         uint8                   `json:"enabled"`
	Bandwidth       int64                   `json:"bandwidth"`
	BandwidthMetric string                  `json:"bandwidthMetric"`
	Queue           opnsense.Pint32AsString `json:"queue"`
	Mask            string                  `json:"mask"`
	Buckets         opnsense.Pint32AsString `json:"buckets"`
	Scheduler       string                  `json:"scheduler"`
	CodelEnable     uint8                   `json:"codel_enable"`
	CodelTarget     opnsense.Pint32AsString `json:"codel_target"`
	CodelInterval   opnsense.Pint32AsString `json:"codel_interval"`
	CodelEcn        uint8                   `json:"codel_ecn_enable"`
	CodelQuantum    opnsense.Pint32AsString `json:"fqcodel_quantum"`
	CodelLimit      opnsense.Pint32AsString `json:"fqcodel_limit"`
	CodelFlows      opnsense.Pint32AsString `json:"fqcodel_flows"`
	Pie             uint8                   `json:"pie_enable"`
	Delay           opnsense.Pint32AsString `json:"delay"`
	Description     string                  `json:"description"`
}

// HTTP Response types

type getShaperPipeResponse struct {
	Pipe shaperPipeResponse `json:"pipe"`
}

type shaperPipeResponse struct {
	Enabled         uint8 `json:"enabled,string"`
	Bandwidth       int64 `json:"bandwidth,string"`
	BandwidthMetric map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"bandwidthMetric"`
	Queue opnsense.Pint32AsString `json:"queue"`
	Mask  map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"mask"`
	Buckets   opnsense.Pint32AsString `json:"buckets"`
	Scheduler map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"scheduler"`
	CodelEnable   uint8                   `json:"codel_enable,string"`
	CodelTarget   opnsense.Pint32AsString `json:"codel_target"`
	CodelInterval opnsense.Pint32AsString `json:"codel_interval"`
	CodelEcn      uint8                   `json:"codel_ecn_enable,string"`
	CodelQuantum  opnsense.Pint32AsString `json:"fqcodel_quantum"`
	CodelLimit    opnsense.Pint32AsString `json:"fqcodel_limit"`
	CodelFlows    opnsense.Pint32AsString `json:"fqcodel_flows"`
	Pie           uint8                   `json:"pie_enable,string"`
	Delay         opnsense.Pint32AsString `json:"delay"`
	Description   string                  `json:"description"`
}

// Helper functions

// shaperPipeToHttpBody converts a traffic shaper pipe object to a shaperPipeToHttpBody object for sending to the OPNsense API.
func shaperPipeToHttpBody(shaperPipe shaperPipe) shaperPipeHttpBody {
	return shaperPipeHttpBody{
		Pipe: shaperPipeRequest{
			Enabled:         utils.BoolToInt(shaperPipe.Enabled),
			Bandwidth:       shaperPipe.Bandwidth.Value,
			BandwidthMetric: shaperPipe.Bandwidth.Metric,
			Queue:           opnsense.Pint32AsString(shaperPipe.Queue),
			Mask:            shaperPipe.Mask,
			Buckets:         opnsense.Pint32AsString(shaperPipe.Buckets),
			Scheduler:       shaperPipe.Scheduler,
			CodelEnable:     utils.BoolToInt(shaperPipe.Codel.Enabled),
			CodelTarget:     opnsense.Pint32AsString(shaperPipe.Codel.Target),
			CodelInterval:   opnsense.Pint32AsString(shaperPipe.Codel.Interval),
			CodelEcn:        utils.BoolToInt(shaperPipe.Codel.Ecn),
			CodelQuantum:    opnsense.Pint32AsString(shaperPipe.Codel.Quantum),
			CodelLimit:      opnsense.Pint32AsString(shaperPipe.Codel.Limit),
			CodelFlows:      opnsense.Pint32AsString(shaperPipe.Codel.Flows),
			Pie:             utils.BoolToInt(shaperPipe.Pie),
			Delay:           opnsense.Pint32AsString(shaperPipe.Delay),
			Description:     shaperPipe.Description,
		},
	}
}

// addShaperPipe creates a traffic shaper pipe on the OPNsense firewall. Returns the UUID on successful creation.
func addShaperPipe(client *opnsense.Client, shaperPipe shaperPipe) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, addShaperPipeCommand)

	// Generate API body from traffic shaper pipe object
	body := shaperPipeToHttpBody(shaperPipe)
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

// getShaperPipe searches the OPNsense firewall for the traffic shaper pipe with a matching UUID.
func getShaperPipe(client *opnsense.Client, uuid string) (*shaperPipe, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, getShaperPipeCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response getShaperPipeResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get %[1]s error: %[1]s with uuid `%s` does not exist.\n\nIf this occurs in a resource block, it is usually because the %[1]s is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing %[1]s from the terraform state to rectify the error.", resourceName, uuid)
		}
		return nil, fmt.Errorf("Get %s error (http): %s", resourceName, err)
	}

	// Extract values from response
	var bandwidthMetric string
	for name, value := range response.Pipe.BandwidthMetric {
		if value.Selected == 1 {
			bandwidthMetric = name
			break
		}
	}

	var mask string
	for name, value := range response.Pipe.Mask {
		if value.Selected == 1 {
			mask = name
			break
		}
	}

	var scheduler string
	var exists bool
	for name, value := range response.Pipe.Scheduler {
		if value.Selected == 1 {
			scheduler, exists = schedulers.GetByValue(name)
			if !exists {
				return nil, fmt.Errorf("Get %s error: scheduler %s is not supported. Please contact the provider maintainers for assistance", resourceName, name)
			}
			break
		}
	}

	bandwidth := struct {
		Value  int64
		Metric string
	}{
		Value:  response.Pipe.Bandwidth,
		Metric: bandwidthMetric,
	}

	codel := struct {
		Enabled  bool
		Target   int32
		Interval int32
		Ecn      bool
		Quantum  int32
		Limit    int32
		Flows    int32
	}{
		Enabled:  response.Pipe.CodelEnable == 1,
		Target:   int32(response.Pipe.CodelTarget),
		Interval: int32(response.Pipe.CodelInterval),
		Ecn:      response.Pipe.CodelEcn == 1,
		Quantum:  int32(response.Pipe.CodelQuantum),
		Limit:    int32(response.Pipe.CodelLimit),
		Flows:    int32(response.Pipe.CodelFlows),
	}

	return &shaperPipe{
		Enabled:     response.Pipe.Enabled == 1,
		Bandwidth:   bandwidth,
		Queue:       int32(response.Pipe.Queue),
		Mask:        mask,
		Buckets:     int32(response.Pipe.Buckets),
		Scheduler:   scheduler,
		Codel:       codel,
		Pie:         response.Pipe.Pie == 1,
		Delay:       int32(response.Pipe.Delay),
		Description: response.Pipe.Description,
	}, nil
}

// setShaperPipe updates an existing traffic shaper pipe on the OPNsense firewall with a matching UUID.
func setShaperPipe(client *opnsense.Client, shaperPipe shaperPipe, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, setShaperPipeCommand, uuid)

	// Generate API body from traffic shaper pipe object
	body := shaperPipeToHttpBody(shaperPipe)
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

// deleteShaperPipe removes an existing traffic shaper pipe from the OPNsense firewall with a matching UUID.
func deleteShaperPipe(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, deleteShaperPipeCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete %s error: failed to marshal json body - %s", resourceName, err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode == 500 {
		var resp opnsense.OpnsenseDelItemErrorResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		if err != nil {
			return fmt.Errorf("Delete %s error (http): failed to decode http response - %s", resourceName, err)
		}

		if strings.ToLower(resp.ErrorTitle) == "item in use by" {
			return fmt.Errorf("Delete %s error: pipe is currently in use by another object (usually a traffic shaper queue or rule).", resourceName)
		}

		return fmt.Errorf("Delete %s error:\n  Error title: %s\n  Error message: %s", resourceName, resp.ErrorTitle, resp.ErrorMessage)
	} else if httpResp.StatusCode == 200 {
		var resp opnsense.OpnsenseAddItemResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		if err != nil {
			return fmt.Errorf("Delete %s error (http): failed to decode http response - %s", resourceName, err)
		}

		if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
			return fmt.Errorf("Delete %[1]s error: failed to delete %[1]s on OPNsense. Please contact the provider maintainers for assistance", resourceName)
		}
	} else {
		return fmt.Errorf("Delete %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}
	return nil
}

// checkShaperPipeExists searches the OPNsense firewall for the traffic shaper pipe with a matching identifier.
func checkShaperPipeExists(client *opnsense.Client, identifier string) (bool, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, getShaperPipeCommand, identifier)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return false, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return false, fmt.Errorf("Get %s error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", resourceName, httpResp.StatusCode)
	}

	var response getShaperPipeResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return false, nil
		}
		return false, fmt.Errorf("Get %s error (http): %s", resourceName, err)
	}
	return true, nil
}
