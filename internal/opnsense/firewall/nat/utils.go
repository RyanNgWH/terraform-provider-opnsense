package nat

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	natController      string = "nat"
	oneToOneController string = "one_to_one"
)

type oneToOneNat struct {
	Enabled        bool
	Log            bool
	Sequence       int32
	Interface      string
	Type           string
	SourceNet      string
	SourceNot      bool
	DestinationNet string
	DestinationNot bool
	External       string
	NatRefection   string
	Categories     []string
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

	categories := utils.StringListTerraformToGo(plan.Categories)

	categoryUuids, err := category.GetCategoryUuids(client, categories)
	if err != nil {
		diagnostics.AddError("Create one-to-one NAT error", fmt.Sprintf("%s", err))
	}

	tflog.Debug(ctx, "Successfully verified categories", map[string]any{"success": true})

	// Verify interface
	tflog.Debug(ctx, "Verifying interface", map[string]any{
		"interface": plan.Interface,
	})

	interfacesExist, err := overview.VerifyInterfaces(client, []string{plan.Interface.ValueString()})
	if err != nil {
		diagnostics.AddError("Create one-to-one NAT error", fmt.Sprintf("%s", err))
	}
	if !interfacesExist {
		diagnostics.AddError("Create one-to-one NAT error", "Interface does not exist. Please verify that the specified interface exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interface", map[string]any{"success": true})

	// Create one-to-one NAT rule from plan
	tflog.Debug(ctx, "Creating one-to-one NAT object from plan", map[string]any{"plan": plan})

	// Sort lists for predictable output
	sort.Strings(categoryUuids)

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
		SourceNet:      plan.SourceNet.ValueString(),
		SourceNot:      plan.SourceNot.ValueBool(),
		DestinationNet: plan.DestinationNet.ValueString(),
		DestinationNot: plan.DestinationNot.ValueBool(),
		External:       plan.External.ValueString(),
		NatRefection:   natReflection,
		Categories:     categoryUuids,
		Description:    plan.Description.ValueString(),
	}

	tflog.Debug(ctx, "Successfully created one-to-one NAT object from plan", map[string]any{"success": true})

	return oneToOneNat, diagnostics
}
