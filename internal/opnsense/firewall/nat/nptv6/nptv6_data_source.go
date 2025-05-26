package nptv6

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
	_ datasource.DataSource              = &natNptv6DataSource{}
	_ datasource.DataSourceWithConfigure = &natNptv6DataSource{}
)

// nptv6DataSource is a helper function to simplify the provider implementation.
func NewOneToOneNatDataSource() datasource.DataSource {
	return &natNptv6DataSource{}
}

// oneToOneNatDataSource defines the data source implementation.
type natNptv6DataSource struct {
	client *opnsense.Client
}

// natNptv6DataSourceModel describes the resource data model.
type natNptv6DataSourceModel struct {
	Id             types.String   `tfsdk:"id"`
	LastUpdated    types.String   `tfsdk:"last_updated"`
	Enabled        types.Bool     `tfsdk:"enabled"`
	Log            types.Bool     `tfsdk:"log"`
	Sequence       types.Int32    `tfsdk:"sequence"`
	Interface      types.String   `tfsdk:"interface"`
	InternalPrefix types.String   `tfsdk:"internal_prefix"`
	ExternalPrefix types.String   `tfsdk:"external_prefix"`
	TrackInterface types.String   `tfsdk:"track_interface"`
	Categories     []types.String `tfsdk:"categories"`
	Description    types.String   `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *natNptv6DataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, nat.NatController, nptv6Controller)
}

// Schema defines the schema for the datasource.
func (d *natNptv6DataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about a NPTv6 NAT rule.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier of the NPTv6 rule entry.",
			},
			"enabled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the NPTv6 rule entry is enabled.",
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
			"internal_prefix": schema.StringAttribute{
				Computed:    true,
				Description: "The internal IPv6 prefix used in the LAN(s). This will replace the prefix of the destination address in inbound packets. The prefix size specified here will also be applied to the external prefix.",
			},
			"external_prefix": schema.StringAttribute{
				Computed:    true,
				Description: "The external IPv6 prefix. This will replace the prefix of the source address in outbound packets. Leave empty to auto-detect the prefix address using the specified tracking interface instead. The prefix size specified for the internal prefix will also be applied to the external prefix.",
			},
			"track_interface": schema.StringAttribute{
				Computed:    true,
				Description: "Use prefix defined on the selected interface instead of the interface this rule applies to when target prefix is not provided.",
			},
			"categories": schema.ListAttribute{
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
func (d *natNptv6DataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *natNptv6DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, "Reading NPTv6 NAT rule")

	// Read Terraform configuration data into the model
	var data natNptv6DataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get alias
	tflog.Debug(ctx, "Getting NPTv6 NAT rule information")
	tflog.SetField(ctx, "uuid", data.Id.ValueString())

	rule, err := getNptv6Nat(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read NPTv6 NAT rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got NPTv6 NAT rule information", map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, "Saving NPTv6 NAT rule information to state", map[string]any{"rule": rule})

	data.Enabled = types.BoolValue(rule.Enabled)
	data.Log = types.BoolValue(rule.Log)
	data.Sequence = types.Int32Value(rule.Sequence)
	data.Interface = types.StringValue(rule.Interface)
	data.InternalPrefix = types.StringValue(rule.InternalPrefix)
	data.ExternalPrefix = types.StringValue(rule.ExternalPrefix)
	data.TrackInterface = types.StringValue(rule.TrackInterface)
	data.Description = types.StringValue(rule.Description)
	data.Categories = utils.StringListGoToTerraform(rule.Categories)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Saved NPTv6 NAT rule information to state", map[string]any{"success": true})
	tflog.Info(ctx, "Successfully read NPTv6 NAT rule", map[string]any{"success": true})
}
