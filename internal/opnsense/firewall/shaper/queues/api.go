package queues

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
	addShaperQueueCommand    opnsense.Command = "add_queue"
	getShaperQueueCommand    opnsense.Command = "get_queue"
	setShaperQueueCommand    opnsense.Command = "set_queue"
	deleteShaperQueueCommand opnsense.Command = "del_queue"
)

// HTTP request bodies

type shaperQueueHttpBody struct {
	Queue shaperQueueRequest `json:"queue"`
}

type shaperQueueRequest struct {
	Enabled       uint8                   `json:"enabled"`
	Pipe          string                  `json:"pipe"`
	Weight        int32                   `json:"weight"`
	Mask          string                  `json:"mask"`
	Buckets       opnsense.Pint32AsString `json:"buckets"`
	CodelEnable   uint8                   `json:"codel_enable"`
	CodelTarget   opnsense.Pint32AsString `json:"codel_target"`
	CodelInterval opnsense.Pint32AsString `json:"codel_interval"`
	CodelEcn      uint8                   `json:"codel_ecn_enable"`
	Pie           uint8                   `json:"pie_enable"`
	Description   string                  `json:"description"`
}

// HTTP Response types

type getShaperQueueResponse struct {
	Queue shaperQueueResponse `json:"queue"`
}

type shaperQueueResponse struct {
	Enabled uint8 `json:"enabled,string"`
	Pipe    map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"pipe"`
	Weight int32 `json:"weight,string"`
	Mask   map[string]struct {
		Value    string `json:"value"`
		Selected uint8  `json:"selected"`
	} `json:"mask"`
	Buckets       opnsense.Pint32AsString `json:"buckets"`
	CodelEnable   uint8                   `json:"codel_enable,string"`
	CodelTarget   opnsense.Pint32AsString `json:"codel_target"`
	CodelInterval opnsense.Pint32AsString `json:"codel_interval"`
	CodelEcn      uint8                   `json:"codel_ecn_enable,string"`
	Pie           uint8                   `json:"pie_enable,string"`
	Description   string                  `json:"description"`
}

// Helper functions

// shaperQueueToHttpBody converts a traffic shaper queue object to a shaperQueueToHttpBody object for sending to the OPNsense API.
func shaperQueueToHttpBody(shaperQueue shaperQueue) shaperQueueHttpBody {
	return shaperQueueHttpBody{
		Queue: shaperQueueRequest{
			Enabled:       utils.BoolToInt(shaperQueue.Enabled),
			Pipe:          shaperQueue.Pipe,
			Weight:        shaperQueue.Weight,
			Mask:          shaperQueue.Mask,
			Buckets:       opnsense.Pint32AsString(shaperQueue.Buckets),
			CodelEnable:   utils.BoolToInt(shaperQueue.Codel.Enabled),
			CodelTarget:   opnsense.Pint32AsString(shaperQueue.Codel.Target),
			CodelInterval: opnsense.Pint32AsString(shaperQueue.Codel.Interval),
			CodelEcn:      utils.BoolToInt(shaperQueue.Codel.Ecn),
			Pie:           utils.BoolToInt(shaperQueue.Pie),
			Description:   shaperQueue.Description,
		},
	}
}

// addShaperQueue creates a traffic shaper queue on the OPNsense firewall. Returns the UUID on successful creation.
func addShaperQueue(client *opnsense.Client, shaperQueue shaperQueue) (string, error) {
	path := fmt.Sprintf("%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, addShaperQueueCommand)

	// Generate API body from traffic shaper queue object
	body := shaperQueueToHttpBody(shaperQueue)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("Add traffic shaper queue error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return "", fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return "", fmt.Errorf("Add traffic shaper queue error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return "", fmt.Errorf("Add traffic shaper queue error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return "", fmt.Errorf("Add traffic shaper queue error: failed to add traffic shaper queue to OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return response.Uuid, nil
}

// getShaperQueue searches the OPNsense firewall for the traffic shaper queue with a matching UUID.
func getShaperQueue(client *opnsense.Client, uuid string) (*shaperQueue, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, getShaperQueueCommand, uuid)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("Get traffic shaper queue error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response getShaperQueueResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return nil, fmt.Errorf("Get traffic shaper queue error: traffic shaper queue with uuid `%s` does not exist.\n\nIf this occurs in a resource block, it is usually because the traffic shaper queue is removed from OPNsense (not using terraform) but is still present in the terraform state. Remove the missing traffic shaper queue from the terraform state to rectify the error.", uuid)
		}
		return nil, fmt.Errorf("Get traffic shaper queue error (http): %s", err)
	}

	// Extract values from response
	var pipe string
	for name, value := range response.Queue.Pipe {
		if value.Selected == 1 {
			pipe = name
			break
		}
	}

	var mask string
	for name, value := range response.Queue.Mask {
		if value.Selected == 1 {
			mask = name
			break
		}
	}

	codel := struct {
		Enabled  bool
		Target   int32
		Interval int32
		Ecn      bool
	}{
		Enabled:  response.Queue.CodelEnable == 1,
		Target:   int32(response.Queue.CodelTarget),
		Interval: int32(response.Queue.CodelInterval),
		Ecn:      response.Queue.CodelEcn == 1,
	}

	return &shaperQueue{
		Enabled:     response.Queue.Enabled == 1,
		Pipe:        pipe,
		Weight:      response.Queue.Weight,
		Mask:        mask,
		Buckets:     int32(response.Queue.Buckets),
		Codel:       codel,
		Pie:         response.Queue.Pie == 1,
		Description: response.Queue.Description,
	}, nil
}

// setShaperQueue updates an existing traffic shaper queue on the OPNsense firewall with a matching UUID.
func setShaperQueue(client *opnsense.Client, shaperQueue shaperQueue, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, setShaperQueueCommand, uuid)

	// Generate API body from traffic shaper queue object
	body := shaperQueueToHttpBody(shaperQueue)
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Set traffic shaper queue error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("Set traffic shaper queue error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response opnsense.OpnsenseAddItemResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Set traffic shaper queue error (http): failed to decode http response - %s", err)
	}

	if strings.ToLower(response.Result) == "failed" {
		return fmt.Errorf("Set traffic shaper queue error: failed to update traffic shaper queue on OPNsense - failed validations:\n%s", opnsense.ValidationsToString(response.Validations))
	}

	return nil
}

// deleteShaperQueue removes an existing traffic shaper queue from the OPNsense firewall with a matching UUID.
func deleteShaperQueue(client *opnsense.Client, uuid string) error {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, deleteShaperQueueCommand, uuid)

	// Generate empty body
	reqBody, err := json.Marshal(nil)
	if err != nil {
		return fmt.Errorf("Delete traffic shaper queue error: failed to marshal json body - %s", err)
	}

	httpResp, err := client.DoRequest(http.MethodPost, path, reqBody)
	if err != nil {
		return fmt.Errorf("OPNsense client error: %s", err)
	}

	if httpResp.StatusCode == 500 {
		var resp opnsense.OpnsenseDelItemErrorResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		if err != nil {
			return fmt.Errorf("Delete traffic shaper queue error (http): failed to decode http response - %s", err)
		}

		if strings.ToLower(resp.ErrorTitle) == "item in use by" {
			return fmt.Errorf("Delete traffic shaper queue error: queue is currently in use by another object (usually a traffic shaper rule).")
		}

		return fmt.Errorf("Delete traffic shaper queue error:\n  Error title: %s\n  Error message: %s", resp.ErrorTitle, resp.ErrorMessage)
	} else if httpResp.StatusCode == 200 {
		var resp opnsense.OpnsenseAddItemResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		if err != nil {
			return fmt.Errorf("Delete traffic shaper queue error (http): failed to decode http response - %s", err)
		}

		if strings.ToLower(resp.Result) != "deleted" && strings.ToLower(resp.Result) != "not found" {
			return fmt.Errorf("Delete traffic shaper queue error: failed to delete traffic shaper queue on OPNsense. Please contact the provider maintainers for assistance")
		}
	} else {
		return fmt.Errorf("Delete traffic shaper queue error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}
	return nil
}

// CheckShaperQueueExists searches the OPNsense firewall for the traffic shaper queue with a matching identifier.
func CheckShaperQueueExists(client *opnsense.Client, identifier string) (bool, error) {
	path := fmt.Sprintf("%s/%s/%s/%s", shaper.Module, shaper.ShaperSettingsController, getShaperQueueCommand, identifier)

	httpResp, err := client.DoRequest(http.MethodGet, path, nil)
	if err != nil {
		return false, fmt.Errorf("OPNsense client error: %s", err)
	}
	if httpResp.StatusCode != 200 {
		return false, fmt.Errorf("Get traffic shaper queue error (http): abnormal status code %d in HTTP response. Please contact the provider for assistance", httpResp.StatusCode)
	}

	var response getShaperQueueResponse
	err = json.NewDecoder(httpResp.Body).Decode(&response)
	if err != nil {
		var jsonTypeError *json.UnmarshalTypeError
		if errors.As(err, &jsonTypeError) && jsonTypeError.Value == "array" {
			return false, nil
		}
		return false, fmt.Errorf("Get traffic shaper queue error (http): %s", err)
	}
	return true, nil
}
