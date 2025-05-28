package group

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/utils"

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
	_ datasource.DataSource              = &groupDataSource{}
	_ datasource.DataSourceWithConfigure = &groupDataSource{}
)

// NewGroupDataSource is a helper function to simplify the provider implementation.
func NewGroupDataSource() datasource.DataSource {
	return &groupDataSource{}
}

// groupDataSource defines the data source implementation.
type groupDataSource struct {
	client *opnsense.Client
}

// groupDataSourceModel describes the data source data model.
type groupDataSourceModel struct {
	Id          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Members     []types.String `tfsdk:"members"`
	NoGroup     types.Bool     `tfsdk:"no_group"`
	Sequence    types.Int32    `tfsdk:"sequence"`
	Description types.String   `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *groupDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the datasource.
func (d *groupDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves information about a firewall group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Identifier of the group.",
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The name of the group.",
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.Expressions{
						path.MatchRoot("id"),
					}...),
				},
			},
			"members": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Member interfaces of the group.",
			},
			"no_group": schema.BoolAttribute{
				Computed:    true,
				Description: "If grouping these members in the interfaces menu section should be prevented.",
			},
			"sequence": schema.Int32Attribute{
				Computed:    true,
				Description: "Priority sequence used in sorting the groups.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "The description of the group.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *groupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *groupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, "Reading firewall group")

	// Read Terraform configuration data into the model
	var data groupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get group UUID
	if data.Id.IsNull() {
		tflog.Debug(ctx, "Getting group UUID", map[string]any{"name": data.Name.ValueString()})

		uuid, err := searchGroup(d.client, data.Name.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Get group error", fmt.Sprintf("%s", err))
		}
		if resp.Diagnostics.HasError() {
			return
		}

		data.Id = types.StringValue(uuid)

		tflog.Debug(ctx, "Successfully got group UUID", map[string]any{"success": true})
	}

	// Get group
	tflog.Debug(ctx, "Getting group information")
	tflog.SetField(ctx, "group_name", data.Name.ValueString())

	group, err := getGroup(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Get group error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got group information", map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, "Saving group information to state", map[string]any{"group": data})

	data.Name = types.StringValue(group.Name)
	data.Members = utils.StringListGoToTerraform(group.Members)
	data.NoGroup = types.BoolValue(group.NoGroup)
	data.Sequence = types.Int32Value(group.Sequence)
	data.Description = types.StringValue(group.Description)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Saved group information to state", map[string]any{"success": true})
	tflog.Info(ctx, "Successfully read firewall group", map[string]any{"success": true})
}
