package onetoone

import (
	"context"
	"fmt"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	oneToOneController string = "one_to_one"

	resourceName string = "one-to-one NAT rule"
)

type oneToOneNat struct {
	Enabled        bool
	Log            bool
	Sequence       int32
	Interface      string
	Type           string
	Source         string
	SourceNot      bool
	Destination    string
	DestinationNot bool
	External       string
	NatRefection   string
	Categories     *utils.Set
	Description    string
}

// Nat values

func getNatTypes() []string {
	return []string{
		"nat",
		"binat",
	}
}

func getNatReflectionOptions() []string {
	return []string{
		"default",
		"enable",
		"disable",
	}
}

// Helper functions

// createOneToOneNat creates a one-to-one nat rule based on the specified plan.
func createOneToOneNat(ctx context.Context, client *opnsense.Client, plan natOneToOneResourceModel) (oneToOneNat, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify all categories exist
	tflog.Debug(ctx, "Verifying categories", map[string]any{
		"categories": plan.Categories,
	})

	categories, diags := utils.SetTerraformToGo(ctx, plan.Categories)
	diagnostics.Append(diags...)

	categoryUuids, err := category.GetCategoryUuids(client, categories)
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}

	tflog.Debug(ctx, "Successfully verified categories", map[string]any{"success": true})

	// Verify interface
	tflog.Debug(ctx, "Verifying interface", map[string]any{
		"interface": plan.Interface,
	})

	interfacesExist, err := overview.VerifyInterface(client, plan.Interface.ValueString())
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}
	if !interfacesExist {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), "Interface does not exist. Please verify that the specified interface exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interface", map[string]any{"success": true})

	// Create one-to-one NAT rule from plan
	tflog.Debug(ctx, fmt.Sprintf("Creating %s object from plan", resourceName), map[string]any{"plan": plan})

	// Check for default nat reflection
	natReflection := strings.ToLower(plan.NatReflection.ValueString())
	if natReflection == "default" {
		natReflection = ""
	}

	oneToOneNat := oneToOneNat{
		Enabled:        plan.Enabled.ValueBool(),
		Log:            plan.Log.ValueBool(),
		Sequence:       plan.Sequence.ValueInt32(),
		Interface:      plan.Interface.ValueString(),
		Type:           plan.Type.ValueString(),
		Source:         plan.Source.ValueString(),
		SourceNot:      plan.SourceNot.ValueBool(),
		Destination:    plan.Destination.ValueString(),
		DestinationNot: plan.DestinationNot.ValueBool(),
		External:       plan.External.ValueString(),
		NatRefection:   natReflection,
		Categories:     categoryUuids,
		Description:    plan.Description.ValueString(),
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return oneToOneNat, diagnostics
}
