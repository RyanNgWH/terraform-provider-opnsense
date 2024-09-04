package category

import (
	"context"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	controller string = "category"
)

type category struct {
	Name  string
	Auto  bool
	Color string
}

// Helper functions
// createCategory creates a category based on the specified plan.
func createCategory(ctx context.Context, plan categoryResourceModel) category {
	// Create category from plan
	tflog.Debug(ctx, "Creating category object from plan", map[string]interface{}{"plan": plan})

	category := category{
		Name:  plan.Name.ValueString(),
		Auto:  plan.Auto.ValueBool(),
		Color: plan.Color.ValueString(),
	}

	tflog.Debug(ctx, "Successfully created category object from plan", map[string]any{"success": true})

	return category
}
