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

	resourceName string = "group"
)

type group struct {
	Name        string
	Members     *utils.Set
	NoGroup     bool
	Sequence    int32
	Description string
}

// Helper functions

// createGroup creates a group based on the specified plan.
func createGroup(ctx context.Context, client *opnsense.Client, plan groupResourceModel) (group, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify interfaces
	tflog.Debug(ctx, "Verifying interfaces", map[string]any{
		"interfaces": plan.Members,
	})

	interfaces, diags := utils.SetTerraformToGo(ctx, plan.Members)
	diagnostics.Append(diags...)

	interfacesExist, err := overview.VerifyInterfaces(client, interfaces)
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}
	if !interfacesExist {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), "One or more interfaces does not exist. Please verify that all specified interfaces exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interfaces", map[string]any{"success": true})

	// Create group from plan
	tflog.Debug(ctx, fmt.Sprintf("Creating %s object from plan", resourceName), map[string]any{"plan": plan})

	group := group{
		Name:        plan.Name.ValueString(),
		Members:     interfaces,
		NoGroup:     plan.NoGroup.ValueBool(),
		Sequence:    plan.Sequence.ValueInt32(),
		Description: plan.Description.ValueString(),
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return group, diagnostics
}
