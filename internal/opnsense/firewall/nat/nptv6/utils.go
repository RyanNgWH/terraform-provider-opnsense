package nptv6

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	nptv6Controller string = "nptv6"

	resourceName string = "NPTv6 NAT rule"
)

type nptv6 struct {
	Enabled        bool
	Log            bool
	Sequence       int32
	Interface      string
	InternalPrefix string
	ExternalPrefix string
	TrackInterface string
	Categories     *utils.Set
	Description    string
}

// Helper functions

// createNptv6Nat creates a NPTv6 nat rule based on the specified plan.
func createNptv6Nat(ctx context.Context, client *opnsense.Client, plan natNptv6ResourceModel) (nptv6, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify all categories exist
	tflog.Debug(ctx, "Verifying categories", map[string]any{"categories": plan.Categories})

	categories, diags := utils.SetTerraformToGo(ctx, plan.Categories)
	diagnostics.Append(diags...)

	categoryUuids, err := category.GetCategoryUuids(client, categories)
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}

	tflog.Debug(ctx, "Successfully verified categories", map[string]any{"success": true})

	// Verify interface
	tflog.Debug(ctx, "Verifying interface", map[string]any{"interface": plan.Interface})

	interfacesExist, err := overview.VerifyInterface(client, plan.Interface.ValueString())
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}
	if !interfacesExist {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), "Interface does not exist. Please verify that the specified interface exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interface", map[string]any{"success": true})

	// Verify track interface
	if plan.TrackInterface.ValueString() != "" {
		tflog.Debug(ctx, "Verifying track interface", map[string]any{"interface": plan.TrackInterface})

		interfacesExist, err := overview.VerifyInterface(client, plan.TrackInterface.ValueString())
		if err != nil {
			diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
		}
		if !interfacesExist {
			diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), "Track interface does not exist. Please verify that the specified interface exist on your OPNsense firewall")
		}

		tflog.Debug(ctx, "Successfully verified track interface", map[string]any{"success": true})
	}

	// Create NPTv6 NAT rule from plan
	tflog.Debug(ctx, fmt.Sprintf("Creating %s object from plan", resourceName), map[string]any{"plan": plan})

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

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return nptv6, diagnostics
}
