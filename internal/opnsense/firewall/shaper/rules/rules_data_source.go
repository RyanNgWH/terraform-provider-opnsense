package rules

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &shaperRulesDataSource{}
	_ datasource.DataSourceWithConfigure = &shaperRulesDataSource{}
)

// NewShaperRulesDataSource is a helper function to simplify the provider implementation.
func NewShaperRulesDataSource() datasource.DataSource {
	return &shaperRulesDataSource{}
}

// shaperRulesDataSource defines the data source implementation.
type shaperRulesDataSource struct {
	client *opnsense.Client
}

// shaperRulesDataSourceModel describes the resource data model.
type shaperRulesDataSourceModel struct {
	Id              types.String   `tfsdk:"id"`
	Enabled         types.Bool     `tfsdk:"enabled"`
	Sequence        types.Int32    `tfsdk:"sequence"`
	Interface       types.String   `tfsdk:"interface"`
	Interface2      types.String   `tfsdk:"interface2"`
	Protocol        types.String   `tfsdk:"protocol"`
	MaxPacketLength types.Int32    `tfsdk:"max_packet_length"`
	Sources         []types.String `tfsdk:"sources"`
	SourceNot       types.Bool     `tfsdk:"source_not"`
	SourcePort      types.String   `tfsdk:"source_port"`
	Destinations    []types.String `tfsdk:"destinations"`
	DestinationNot  types.Bool     `tfsdk:"destination_not"`
	DestinationPort types.String   `tfsdk:"destination_port"`
	Dscp            []types.String `tfsdk:"dscp"`
	Direction       types.String   `tfsdk:"direction"`
	Target          types.String   `tfsdk:"target"`
	Description     types.String   `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *shaperRulesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, shaper.ShaperController, rulesController)
}

// Schema defines the schema for the datasource.
func (d *shaperRulesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about a traffic shaper rule.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier of the traffic shaper rule.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the traffic shaper rule is enabled.",
			},
			"sequence": schema.Int32Attribute{
				Computed:    true,
				Description: "Order in which the rule will be evaluated (lowest first).",
			},
			"interface": schema.StringAttribute{
				Computed:    true,
				Description: "The interface this rule applies to.",
			},
			"interface2": schema.StringAttribute{
				Computed:    true,
				Description: "The secondary interface, matches packets traveling to/from interface (1) to/from interface (2). Can be combined with direction.",
			},
			"protocol": schema.StringAttribute{
				Computed:    true,
				Description: "The applicable protocol for this rule.",
			},
			"max_packet_length": schema.Int32Attribute{
				Computed:    true,
				Description: "Specifies the maximum size of packets to match in bytes. Negative values are treated as default (i.e empty)",
			},
			"sources": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Source IPs or networks, examples `10.0.0.0/24`, `10.0.0.1`.",
			},
			"source_not": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the source matching should be inverted.",
			},
			"source_port": schema.StringAttribute{
				Computed:    true,
				Description: "Source port number or well known name.",
			},
			"destinations": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Destination ips or networks, examples `10.0.0.0/24`, `10.0.0.1`.",
			},
			"destination_not": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the destination matching should be inverted.",
			},
			"destination_port": schema.StringAttribute{
				Computed:    true,
				Description: "Destination port number or well known name.",
			},
			"dscp": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Match against one or multiple DSCP values.",
			},
			"direction": schema.StringAttribute{
				Computed:    true,
				Description: "Direction of packet matching.",
			},
			"target": schema.StringAttribute{
				Computed:    true,
				Description: "Target pipe or queue.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description to identify this rule.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *shaperRulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *shaperRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, "Reading traffic shaper rule")

	// Read Terraform configuration data into the model
	var data shaperRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get traffic shaper rule
	tflog.Debug(ctx, "Getting traffic shaper rule information")
	tflog.SetField(ctx, "uuid", data.Id.ValueString())

	rule, err := getShaperRule(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read traffic shaper rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got traffic shaper rule information", map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, "Saving traffic shaper rule information to state", map[string]any{"rule": rule})

	data.Enabled = types.BoolValue(rule.Enabled)
	data.Sequence = types.Int32Value(rule.Sequence)
	data.Interface = types.StringValue(rule.Interface)
	data.Interface2 = types.StringValue(rule.Interface2)
	data.Protocol = types.StringValue(rule.Protocol)
	data.MaxPacketLength = types.Int32Value(rule.MaxPacketLength)
	data.Sources = utils.StringListGoToTerraform(rule.Sources)
	data.SourceNot = types.BoolValue(rule.SourceNot)
	data.SourcePort = types.StringValue(rule.SourcePort)
	data.Destinations = utils.StringListGoToTerraform(rule.Destinations)
	data.DestinationNot = types.BoolValue(rule.DestinationNot)
	data.DestinationPort = types.StringValue(rule.DestinationPort)
	data.Dscp = utils.StringListGoToTerraform(rule.Dscp)
	data.Direction = types.StringValue(rule.Direction)
	data.Target = types.StringValue(rule.Target)
	data.Description = types.StringValue(rule.Description)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Saved traffic shaper rule information to state", map[string]any{"success": true})
	tflog.Info(ctx, "Successfully read traffic shaper rule", map[string]any{"success": true})
}
