package nptv6

import (
	"context"
	"fmt"
	"sort"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	nptv6Controller string = "nptv6"
)

type nptv6 struct {
	Enabled        bool
	Log            bool
	Sequence       int32
	Interface      string
	InternalPrefix string
	ExternalPrefix string
	TrackInterface string
	Categories     []string
	Description    string
}

// Helper functions

// createNptv6Nat creates a NPTv6 nat rule based on the specified plan.
func createNptv6Nat(ctx context.Context, client *opnsense.Client, plan natNptv6ResourceModel) (nptv6, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify all categories exist
	tflog.Debug(ctx, "Verifying categories", map[string]any{"categories": plan.Categories})

	categories := utils.StringListTerraformToGo(plan.Categories)

	categoryUuids, err := category.GetCategoryUuids(client, categories)
	if err != nil {
		diagnostics.AddError("Create NPTv6 NAT error", fmt.Sprintf("%s", err))
	}

	tflog.Debug(ctx, "Successfully verified categories", map[string]any{"success": true})

	// Verify interface
	tflog.Debug(ctx, "Verifying interface", map[string]any{"interface": plan.Interface})

	interfacesExist, err := overview.VerifyInterfaces(client, []string{plan.Interface.ValueString()})
	if err != nil {
		diagnostics.AddError("Create NPTv6 NAT error", fmt.Sprintf("%s", err))
	}
	if !interfacesExist {
		diagnostics.AddError("Create NPTv6 NAT error", "Interface does not exist. Please verify that the specified interface exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interface", map[string]any{"success": true})

	// Verify track interface
	if plan.TrackInterface.ValueString() != "" {
		tflog.Debug(ctx, "Verifying track interface", map[string]any{"interface": plan.TrackInterface})

		interfacesExist, err := overview.VerifyInterfaces(client, []string{plan.TrackInterface.ValueString()})
		if err != nil {
			diagnostics.AddError("Create NPTv6 NAT error", fmt.Sprintf("%s", err))
		}
		if !interfacesExist {
			diagnostics.AddError("Create NPTv6 NAT error", "Track interface does not exist. Please verify that the specified interface exist on your OPNsense firewall")
		}

		tflog.Debug(ctx, "Successfully verified track interface", map[string]any{"success": true})
	}

	// Create NPTv6 NAT rule from plan
	tflog.Debug(ctx, "Creating NPTv6 NAT object from plan", map[string]any{"plan": plan})

	// Sort lists for predictable output
	sort.Strings(categoryUuids)

	nptv6 := nptv6{
		Enabled:        plan.Enabled.ValueBool(),
		Log:            plan.Log.ValueBool(),
		Sequence:       plan.Sequence.ValueInt32(),
		Interface:      plan.Interface.ValueString(),
		InternalPrefix: plan.InternalPrefix.ValueString(),
		ExternalPrefix: plan.ExternalPrefix.ValueString(),
		TrackInterface: plan.TrackInterface.ValueString(),
		Categories:     categoryUuids,
		Description:    plan.Description.ValueString(),
	}

	tflog.Debug(ctx, "Successfully created NPTv6 NAT object from plan", map[string]any{"success": true})

	return nptv6, diagnostics
}
