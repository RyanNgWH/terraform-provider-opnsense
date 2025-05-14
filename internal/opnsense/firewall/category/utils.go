package category

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"

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

// getCategoryUuids checks if the specified categories exist on the OPNsense firewall and returns their respective uuids.
func GetCategoryUuids(client *opnsense.Client, categoriesList []string) ([]string, error) {
	var categoryUuids []string
	for _, cat := range categoriesList {
		uuid, err := SearchCategory(client, cat)
		if err != nil {
			return nil, fmt.Errorf("failed to get category from OPNsense - %s", err)
		}

		categoryUuids = append(categoryUuids, uuid)
	}
	return categoryUuids, nil
}
