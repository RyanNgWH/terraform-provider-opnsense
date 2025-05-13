package utils

import "github.com/hashicorp/terraform-plugin-framework/types"

// BoolToInt converts a `true` value to `1` and a `false` value to `0`.
func BoolToInt(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// StringListTerraformToGo converts a slice of terraform's `types.String` to a Go slice of strings.
func StringListTerraformToGo(terraformList []types.String) []string {
	var result []string
	for _, element := range terraformList {
		result = append(result, element.ValueString())
	}
	return result
}

// StringListGoToTerraform converts a Go slice of strings to a slice of terraform's `types.String`.
func StringListGoToTerraform(goList []string) []types.String {
	result := make([]types.String, 0)
	for _, element := range goList {
		result = append(result, types.StringValue(element))
	}
	return result
}
