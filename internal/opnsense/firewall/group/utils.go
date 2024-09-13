package group

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	controller string = "group"
)

type group struct {
	Name        string
	Members     []string
	NoGroup     bool
	Sequence    int64
	Description string
}

// Helper functions

// createGroup creates a group based on the specified plan.
func createGroup(ctx context.Context, client *opnsense.Client, plan groupResourceModel) (group, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify interfaces
	tflog.Debug(ctx, "Verifying interfaces", map[string]interface{}{
		"interfaces": plan.Members,
	})

	interfaces := utils.StringListTerraformToGo(plan.Members)

	interfacesExist, err := overview.VerifyInterfaces(client, interfaces)
	if err != nil {
		diagnostics.AddError("Create group error", fmt.Sprintf("Failed to verify interfaces: %s", err))
	}
	if !interfacesExist {
		diagnostics.AddError("Create group error", "One or more interfaces does not exist. Please verify that all specified interfaces exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interfaces", map[string]any{"success": true})

	// Create group from plan
	tflog.Debug(ctx, "Creating group object from plan", map[string]interface{}{"plan": plan})

	group := group{
		Name:        plan.Name.ValueString(),
		Members:     interfaces,
		NoGroup:     plan.NoGroup.ValueBool(),
		Sequence:    plan.Sequence.ValueInt64(),
		Description: plan.Description.ValueString(),
	}

	tflog.Debug(ctx, "Successfully created group object from plan", map[string]any{"success": true})

	return group, diagnostics
}
