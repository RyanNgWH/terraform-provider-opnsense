package category

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	controller string = "category"

	resourceName string = "category"
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
	tflog.Debug(ctx, "Creating category object from plan", map[string]any{"plan": plan})

	category := category{
		Name:  plan.Name.ValueString(),
		Auto:  plan.Auto.ValueBool(),
		Color: plan.Color.ValueString(),
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return category
}

// getCategoryUuids checks if the specified categories exist on the OPNsense firewall and returns their respective uuids.
func GetCategoryUuids(client *opnsense.Client, categoriesList []string) ([]string, error) {
	var categoryUuids []string
	for _, cat := range categoriesList {
		uuid, err := searchCategory(client, cat)
		if err != nil {
			return nil, fmt.Errorf("%s", err)
		}

		if uuid == "" {
			return nil, fmt.Errorf("Get category UUID error: category `%s` does not exist", cat)
		}

		categoryUuids = append(categoryUuids, uuid)
	}
	return categoryUuids, nil
}
