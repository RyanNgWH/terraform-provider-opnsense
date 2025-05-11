package alias

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	controller string = "alias"
)

type alias struct {
	Enabled     bool
	Name        string
	Type        string
	Counters    bool
	UpdateFreq  float64
	Description string
	Proto       []string
	Categories  []string
	Content     []string
	Interfaces  []string
}

type geoip struct {
	AddressCount   int64
	AddressSources struct {
		Ipv4 string
		Ipv6 string
	}
	FileCount         int64
	LocationsFilename string
	Timestamp         string
	Url               string
	Usages            int64
}

// Alias values

func getAliasTypes() []string {
	return []string{
		"host",
		"network",
		"port",
		"url",
		"urltable",
		"geoip",
		"networkgroup",
		"mac",
		"asn",
		"dynipv6host",
		"authgroup",
		"internal",
		"external",
	}
}

// Helper functions

// freqFloatToObject converts an updateFreq value from a float64 value to an updateFreqType value.
func freqFloatToObject(freqFloat float64) map[string]attr.Value {
	days, hours := math.Modf(freqFloat)
	hours = hours * 24

	return map[string]attr.Value{
		"days":  types.Int32Value(int32(days)),
		"hours": types.Float64Value(math.Round(hours*100) / 100),
	}
}

// protoContains checks if the specified protoList contains the specified proto.
func protoContains(protoList []string, proto string) bool {
	for _, protocol := range protoList {
		if strings.EqualFold(protocol, proto) {
			return true
		}
	}
	return false
}

// createAlias creates an alias based on the specified plan.
func createAlias(ctx context.Context, client *opnsense.Client, plan aliasResourceModel) (alias, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify all categories exist
	tflog.Debug(ctx, "Verifying categories", map[string]interface{}{
		"categories": plan.Categories,
	})

	categories := utils.StringListTerraformToGo(plan.Categories)

	categoryUuids, err := category.GetCategoryUuids(client, categories)
	if err != nil {
		diagnostics.AddError("Add alias error", fmt.Sprintf("Failed to verify categories - %s", err))
	}

	tflog.Debug(ctx, "Successfully verified categories", map[string]any{"success": true})

	// Verify interfaces (if type is dynipv6)
	if plan.Type.Equal(types.StringValue("dynipv6")) {
		tflog.Debug(ctx, "Verifying interfaces", map[string]interface{}{
			"interfaces": plan.Interfaces,
		})

		interfaces := utils.StringListTerraformToGo(plan.Interfaces)

		interfacesExist, err := overview.VerifyInterfaces(client, interfaces)
		if err != nil {
			diagnostics.AddError("Add alias error", fmt.Sprintf("Failed to verify interfaces: %s", err))
		}
		if !interfacesExist {
			diagnostics.AddError("Add alias error", "One or more interfaces does not exist. Please verify that all specified interfaces exist on your OPNsense firewall")
		}

		tflog.Debug(ctx, "Successfully verified interfaces", map[string]any{"success": true})
	}

	// Create alias from plan
	tflog.Debug(ctx, "Creating alias object from plan", map[string]interface{}{"plan": plan})

	// Compute update frequency
	var planUpdateFreq updateFreqModel

	diags := plan.UpdateFreq.As(ctx, &planUpdateFreq, basetypes.ObjectAsOptions{})
	diagnostics.Append(diags...)

	var days int32
	if planUpdateFreq.Days.IsNull() {
		days = 0
	} else {
		days = planUpdateFreq.Days.ValueInt32()
	}

	var hours float64
	if planUpdateFreq.Hours.IsNull() {
		hours = 0
	} else {
		hours = planUpdateFreq.Hours.ValueFloat64()
	}

	updateFreqFloat := float64(days) + (hours / float64(24))

	// Replace updateFreq value (in event of abnormal days/hours values e.g 0 days, 48 hours)
	updateFreq, diags := types.ObjectValue(
		map[string]attr.Type{
			"days":  types.Int32Type,
			"hours": types.Float64Type,
		},
		freqFloatToObject(updateFreqFloat),
	)
	diagnostics.Append(diags...)
	plan.UpdateFreq = updateFreq

	// Extract protocols from plan
	var protos []string
	var planProtos protoModel
	diags = plan.Proto.As(ctx, &planProtos, basetypes.ObjectAsOptions{})
	diagnostics.Append(diags...)

	if planProtos.Ipv4.ValueBool() {
		protos = append(protos, "IPv4")
	}
	if planProtos.Ipv6.ValueBool() {
		protos = append(protos, "IPv6")
	}

	content := utils.StringListTerraformToGo(plan.Content)
	interfaces := utils.StringListTerraformToGo(plan.Interfaces)

	// Sort lists for predictable output
	sort.Strings(categoryUuids)
	sort.Strings(content)
	sort.Strings(interfaces)

	// Replace empty lists with nil values
	if len(categoryUuids) <= 0 {
		categoryUuids = nil
	}
	if len(content) <= 0 {
		content = nil
	}
	if len(interfaces) <= 0 {
		interfaces = nil
	}

	alias := alias{
		Enabled:     plan.Enabled.ValueBool(),
		Name:        plan.Name.ValueString(),
		Type:        plan.Type.ValueString(),
		Counters:    plan.Counters.ValueBool(),
		UpdateFreq:  updateFreqFloat,
		Description: plan.Description.ValueString(),
		Proto:       protos,
		Categories:  categoryUuids,
		Content:     content,
		Interfaces:  interfaces,
	}

	tflog.Debug(ctx, "Successfully created alias object from plan", map[string]any{"success": true})

	return alias, diagnostics
}
