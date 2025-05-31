package category

import (
	"context"
	"fmt"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &categoryDataSource{}
	_ datasource.DataSourceWithConfigure = &categoryDataSource{}
)

// NewCategoryDataSource is a helper function to simplify the provider implementation.
func NewCategoryDataSource() datasource.DataSource {
	return &categoryDataSource{}
}

// categoryDataSource defines the data source implementation.
type categoryDataSource struct {
	client *opnsense.Client
}

// categoryDataSourceModel describes the data source data model.
type categoryDataSourceModel struct {
	Id    types.String `tfsdk:"id"`
	Name  types.String `tfsdk:"name"`
	Auto  types.Bool   `tfsdk:"auto"`
	Color types.String `tfsdk:"color"`
}

// Metadata returns the data source type name.
func (d *categoryDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the datasource.
func (d *categoryDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves information about a firewall category.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: fmt.Sprintf("Identifier of the %s.", resourceName),
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The name of the category.",
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.Expressions{
						path.MatchRoot("id"),
					}...),
				},
			},
			"auto": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the category is automatically added (i.e will be removed when unused).",
			},
			"color": schema.StringAttribute{
				Computed:    true,
				Description: "The hex color code to be used for the category tag.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *categoryDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*opnsense.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *opnsense.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

// Read refreshes the Terraform state with the latest data.
func (d *categoryDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", resourceName))

	// Read Terraform configuration data into the model
	var data categoryDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get category UUID
	if data.Id.IsNull() {
		tflog.Debug(ctx, "Getting category UUID", map[string]any{"name": data.Name.ValueString()})

		uuid, err := searchCategory(d.client, data.Name.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(fmt.Sprintf("Get %s error", resourceName), fmt.Sprintf("%s", err))
		}
		if resp.Diagnostics.HasError() {
			return
		}

		data.Id = types.StringValue(uuid)

		tflog.Debug(ctx, "Successfully got category UUID", map[string]any{"success": true})
	}

	// Get category
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", resourceName))
	tflog.SetField(ctx, "category_name", data.Name.ValueString())

	category, err := GetCategory(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Get %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s information", resourceName), map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, fmt.Sprintf("Saving %s information to state", resourceName), map[string]any{
		"id":        data.Id.ValueString(),
		"name":      category.Name,
		"auto":      category.Auto,
		"interface": category.Color,
	})

	data.Name = types.StringValue(category.Name)
	data.Auto = types.BoolValue(category.Auto)
	data.Color = types.StringValue(category.Color)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Saved %s information to state", resourceName), map[string]any{"success": true})
	tflog.Info(ctx, fmt.Sprintf("Successfully read %s", resourceName), map[string]any{"success": true})
}
