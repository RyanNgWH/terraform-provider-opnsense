package onetoone

import (
	"context"
	"fmt"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/nat"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &oneToOneNatDataSource{}
	_ datasource.DataSourceWithConfigure = &oneToOneNatDataSource{}
)

// NewOneToOneNatDataSource is a helper function to simplify the provider implementation.
func NewOneToOneNatDataSource() datasource.DataSource {
	return &oneToOneNatDataSource{}
}

// oneToOneNatDataSource defines the data source implementation.
type oneToOneNatDataSource struct {
	client *opnsense.Client
}

// oneToOneNatDataSourceModel describes the data source data model.
type oneToOneNatDataSourceModel struct {
	Id             types.String `tfsdk:"id"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	Log            types.Bool   `tfsdk:"log"`
	Sequence       types.Int32  `tfsdk:"sequence"`
	Interface      types.String `tfsdk:"interface"`
	Type           types.String `tfsdk:"type"`
	Source         types.String `tfsdk:"source"`
	SourceNot      types.Bool   `tfsdk:"source_not"`
	Destination    types.String `tfsdk:"destination"`
	DestinationNot types.Bool   `tfsdk:"destination_not"`
	External       types.String `tfsdk:"external"`
	NatReflection  types.String `tfsdk:"nat_reflection"`
	Categories     types.Set    `tfsdk:"categories"`
	Description    types.String `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *oneToOneNatDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, nat.NatController, oneToOneController)
}

// Schema defines the schema for the datasource.
func (d *oneToOneNatDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf("Retrieves information about a %s.", resourceName),

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: fmt.Sprintf("Identifier of the %s.", resourceName),
			},
			"enabled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the one-to-one nat entry is enabled.",
			},
			"log": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether packets that are handled by this rule should be logged.",
			},
			"sequence": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: "Order in which multiple matching rules are evaluated and applied.",
			},
			"interface": schema.StringAttribute{
				Computed:    true,
				Description: "The interface this rule applies to.",
			},
			"type": schema.StringAttribute{
				Computed:    true,
				Description: "The type of the nat rule.",
			},
			"source": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The internal subnet for this 1:1 mapping.",
			},
			"source_not": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the source matching should be inverted.",
			},
			"destination": schema.StringAttribute{
				Computed:    true,
				Description: "The 1:1 mapping will only be used for connections to or from the specified destination.",
			},
			"destination_not": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the destination matching should be inverted.",
			},
			"external": schema.StringAttribute{
				Computed:    true,
				Description: "The external subnet's starting address for the 1:1 mapping or network. This is the address or network the traffic will translate to/from.",
			},
			"nat_reflection": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Whether nat reflection should be enabled.",
			},
			"categories": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "The categories of the rule.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "The description of the rule.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *oneToOneNatDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *oneToOneNatDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", resourceName))

	// Read Terraform configuration data into the model
	var data oneToOneNatDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get one-to-one NAT rule
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", resourceName))
	tflog.SetField(ctx, "uuid", data.Id.ValueString())

	rule, err := getOneToOneNat(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s information", resourceName), map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, fmt.Sprintf("Saving %s information to state", resourceName), map[string]any{"rule": rule})

	data.Enabled = types.BoolValue(rule.Enabled)
	data.Log = types.BoolValue(rule.Log)
	data.Sequence = types.Int32Value(rule.Sequence)
	data.Interface = types.StringValue(rule.Interface)
	data.Type = types.StringValue(rule.Type)
	data.Source = types.StringValue(rule.Source)
	data.SourceNot = types.BoolValue(rule.SourceNot)
	data.Destination = types.StringValue(rule.Destination)
	data.DestinationNot = types.BoolValue(rule.DestinationNot)
	data.External = types.StringValue(rule.External)
	data.NatReflection = types.StringValue(rule.NatRefection)
	data.Description = types.StringValue(rule.Description)

	categories, diags := utils.SetGoToTerraform(ctx, rule.Categories)
	resp.Diagnostics.Append(diags...)
	data.Categories = categories

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
