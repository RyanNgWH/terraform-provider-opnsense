package opnsense

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
)

type Command string

// Custom type for unmarshalling json string to float64.
type Float64AsString float64

func (f *Float64AsString) UnmarshalJSON(data []byte) error {
	if string(data) == `""` {
		*f = 0
		return nil
	}

	numString := strings.Trim(string(data), `"`)
	num, err := strconv.ParseFloat(numString, 64)
	if err != nil {
		return err
	}
	*f = Float64AsString(num)
	return nil
}

// Custom type for unmarshalling json string to uint8.
type Uint8AsString float64

func (f *Uint8AsString) UnmarshalJSON(data []byte) error {
	if string(data) == `""` {
		*f = 0
		return nil
	}

	numString := strings.Trim(string(data), `"`)
	num, err := strconv.ParseUint(numString, 10, 8)
	if err != nil {
		return err
	}
	*f = Uint8AsString(num)
	return nil
}

// Custom type for unmarshalling OPNsense add item json responses
type OpnsenseAddItemResponse struct {
	Result      string         `json:"result"`
	Uuid        string         `json:"uuid"`
	Validations map[string]any `json:"validations"`
}

func (res *OpnsenseAddItemResponse) UnmarshalJSON(data []byte) error {
	var responseMap map[string]interface{}

	if res == nil {
		return errors.New("RawString: UnmarshalJSON on nil pointer")
	}

	if err := json.Unmarshal(data, &responseMap); err != nil {
		return err
	}

	for key, val := range responseMap {
		switch key {
		case "result":
			res.Result = val.(string)
		case "uuid":
			res.Uuid = val.(string)
		case "validations":
			res.Validations = make(map[string]any)
			maps.Copy(res.Validations, val.(map[string]any))
		}
	}

	return nil
}

// Function to format the validations map as a string
func ValidationsToString(m map[string]any) string {
	var result string
	for key, value := range m {
		result += fmt.Sprintf("%s: %s\n", key, value)
	}
	return result
}

// Custom type for unmarshalling OPNsense apply config json responses
type OpnsenseApplyConfigResponse struct {
	Status string `json:"status"`
}
