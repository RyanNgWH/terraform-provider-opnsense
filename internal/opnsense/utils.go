package opnsense

import (
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
