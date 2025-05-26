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
	Enabled         uint8  `json:"enabled"`
	Bandwidth       int64  `json:"bandwidth"`
	BandwidthMetric string `json:"bandwidthMetric"`
	Queue           int32  `json:"queue"`
	Mask            string `json:"mask"`
	Buckets         int32  `json:"buckets"`
	Scheduler       string `json:"scheduler"`
	CodelEnable     uint8  `json:"codel_enable"`
	CodelTarget     int32  `json:"codel_target"`
	CodelInterval   int32  `json:"codel_interval"`
	CodelEcn        uint8  `json:"codel_ecn_enable"`
	CodelQuantum    int32  `json:"fqcodel_quantum"`
	CodelLimit      int32  `json:"fqcodel_limit"`
	CodelFlows      int32  `json:"fqcodel_flows"`
	Pie             uint8  `json:"pie_enable"`
	Delay           int32  `json:"delay"`
	Description     string `json:"description"`
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
	Queue int32 `json:"queue,string"`
	Mask  map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"mask"`
	Buckets   int32 `json:"buckets,string"`
	Scheduler map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"scheduler"`
	CodelEnable   uint8  `json:"codel_enable,string"`
	CodelTarget   int32  `json:"codel_target,string"`
	CodelInterval int32  `json:"codel_interval,string"`
	CodelEcn      uint8  `json:"codel_ecn_enable,string"`
	CodelQuantum  int32  `json:"fqcodel_quantum,string"`
	CodelLimit    int32  `json:"fqcodel_limit,string"`
	CodelFlows    int32  `json:"fqcodel_flows,string"`
	Pie           uint8  `json:"pie_enable,string"`
	Delay         int32  `json:"delay"`
	Description   string `json:"description"`
}

// Helper functions

// shaperPipeToHttpBody converts a traffic shaper pipe object to a shaperPipeToHttpBody object for sending to the OPNsense API.
func shaperPipeToHttpBody(shaperPipe shaperPipe) shaperPipeHttpBody {
	return shaperPipeHttpBody{
		Pipe: shaperPipeRequest{
			Enabled:         utils.BoolToInt(shaperPipe.Enabled),
			Bandwidth:       shaperPipe.Bandwidth.Value,
			BandwidthMetric: shaperPipe.Bandwidth.Metric,
			Queue:           shaperPipe.Queue,
			Mask:            shaperPipe.Mask,
			Buckets:         shaperPipe.Buckets,
			Scheduler:       shaperPipe.Scheduler,
			CodelEnable:     utils.BoolToInt(shaperPipe.Codel.Enabled),
			CodelTarget:     shaperPipe.Codel.Target,
			CodelInterval:   shaperPipe.Codel.Interval,
			CodelEcn:        utils.BoolToInt(shaperPipe.Codel.Ecn),
			CodelQuantum:    shaperPipe.Codel.Quantum,
			CodelLimit:      shaperPipe.Codel.Limit,
			CodelFlows:      shaperPipe.Codel.Flows,
			Pie:             utils.BoolToInt(shaperPipe.Pie),
			Delay:           shaperPipe.Delay,
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
		return "", fmt.Errorf("Add traffic shaper pipe error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Add traffic shaper pipe error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Add traffic shaper pipe error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("Add traffic shaper pipe error: failed to add one-to-one NAT rule to OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
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
		return nil, fmt.Errorf("Get traffic shaper pipe error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response getShaperPipeResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get traffic shaper pipe error: traffic shaper pipe with uuid `%s` does not exist.\n\nIf this occurs in a resource block, it is usually because the traffic shaper pipe is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing traffic shaper pipe from the terraform state to rectify the error.", uuid)
		}
		return nil, fmt.Errorf("Get traffic shaper pipe error (http): %s", err)
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
			bandwidthMetric = name
			break
		}
	}

	var scheduler string
	for name, value := range response.Pipe.Scheduler {
		if value.Selected == 1 {
			bandwidthMetric = name
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
		Target:   response.Pipe.CodelTarget,
		Interval: response.Pipe.CodelInterval,
		Ecn:      response.Pipe.CodelEcn == 1,
		Quantum:  response.Pipe.CodelQuantum,
		Limit:    response.Pipe.CodelLimit,
		Flows:    response.Pipe.CodelFlows,
	}

	return &shaperPipe{
		Enabled:     response.Pipe.Enabled == 1,
		Bandwidth:   bandwidth,
		Queue:       response.Pipe.Queue,
		Mask:        mask,
		Buckets:     response.Pipe.Buckets,
		Scheduler:   scheduler,
		Codel:       codel,
		Pie:         response.Pipe.Pie == 1,
		Delay:       response.Pipe.Delay,
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
		return fmt.Errorf("Set traffic shaper pipe error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set traffic shaper pipeerror (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set traffic shaper pipe error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set traffic shaper pipe error: failed to update traffic shaper pipe on OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteShaperPipe removes an existing traffic shaper pipe from the OPNsense firewall with a matching UUID.
func deleteShaperPipe(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, deleteShaperPipeCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete traffic shaper pipe error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Delete traffic shaper pipe error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var resp opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return fmt.Errorf("Delete traffic shaper pipe error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
		return fmt.Errorf("Delete traffic shaper pipe error: failed to delete traffic shaper pipe on OPNsense. Please contact the provider maintainers for assistance")
	}
	return nil
}
