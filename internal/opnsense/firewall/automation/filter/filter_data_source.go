package filter

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/automation"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &automationFilterDataSource{}
	_ datasource.DataSourceWithConfigure = &automationFilterDataSource{}
)

// NewAutomationFilterDataSource is a helper function to simplify the provider implementation.
func NewAutomationFilterDataSource() datasource.DataSource {
	return &automationFilterDataSource{}
}

// automationFilterDataSource defines the data source implementation.
type automationFilterDataSource struct {
	client *opnsense.Client
}

// automationFilterDataSourceModel describes the resource data model.
type automationFilterDataSourceModel struct {
	Id              types.String   `tfsdk:"id"`
	Enabled         types.Bool     `tfsdk:"enabled"`
	Sequence        types.Int32    `tfsdk:"sequence"`
	Action          types.String   `tfsdk:"action"`
	Quick           types.Bool     `tfsdk:"quick"`
	Interfaces      []types.String `tfsdk:"interfaces"`
	Direction       types.String   `tfsdk:"direction"`
	IpVersion       types.String   `tfsdk:"ip_version"`
	Protocol        types.String   `tfsdk:"protocol"`
	Source          types.String   `tfsdk:"source"`
	SourceNot       types.Bool     `tfsdk:"source_not"`
	SourcePort      types.String   `tfsdk:"source_port"`
	Destination     types.String   `tfsdk:"destination"`
	DestinationNot  types.Bool     `tfsdk:"destination_not"`
	DestinationPort types.String   `tfsdk:"destination_port"`
	Gateway         types.String   `tfsdk:"gateway"`
	Log             types.Bool     `tfsdk:"log"`
	Categories      []types.String `tfsdk:"categories"`
	Description     types.String   `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *automationFilterDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, automation.AutomationController, filterController)
}

// Schema defines the schema for the datasource.
func (d *automationFilterDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about a firewall automation filter rule.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: fmt.Sprintf("Identifier of the %s.", resourceName),
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the rule is enabled.",
			},
			"sequence": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: "Order in which multiple matching rules are evaluated and applied (lowest first).",
			},
			"action": schema.StringAttribute{
				Computed:    true,
				Description: "Action taken with packets that match the criteria specified. The difference between block and reject is that with reject, a packet (TCP RST or ICMP port unreachable for UDP) is returned to the sender, whereas with block the packet is dropped silently. In either case, the original packet is discarded.",
			},
			"quick": schema.BoolAttribute{
				Computed:    true,
				Description: "If a packet matches a rule specifying quick, then that rule is considered the last matching rule and the specified action is taken. When a rule does not have quick enabled, the last matching rule wins.",
			},
			"interfaces": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Interfaces this rule applies to.",
			},
			"direction": schema.StringAttribute{
				Computed:    true,
				Description: "Direction of packet matching.",
			},
			"ip_version": schema.StringAttribute{
				Computed:    true,
				Description: "The applicable ip version this for this rule.",
			},
			"protocol": schema.StringAttribute{
				Computed:    true,
				Description: "The applicable protocol for this rule.",
			},
			"source": schema.StringAttribute{
				Computed:    true,
				Description: "Source IP or network.",
			},
			"source_not": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the source matching should be inverted.",
			},
			"source_port": schema.StringAttribute{
				Computed:    true,
				Description: "Source port number or well known name.",
			},
			"destination": schema.StringAttribute{
				Computed:    true,
				Description: "Destination IP or network.",
			},
			"destination_not": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the destination matching should be inverted.",
			},
			"destination_port": schema.StringAttribute{
				Computed:    true,
				Description: "Destination port number or well known name .",
			},
			"gateway": schema.StringAttribute{
				Computed:    true,
				Description: "Gateway utilized in policy based routing. An empty value uses the system routing table.",
			},
			"log": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether packets that are handled by this rule should be logged.",
			},
			"categories": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "The categories of the rule.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description to identify this rule.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *automationFilterDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *automationFilterDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", resourceName))

	// Read Terraform configuration data into the model
	var data automationFilterDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get automation filter rule
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", resourceName))
	tflog.SetField(ctx, "uuid", data.Id.ValueString())

	rule, err := getAutomationFilterRule(d.client, data.Id.ValueString())
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
	data.Sequence = types.Int32Value(rule.Sequence)
	data.Action = types.StringValue(rule.Action)
	data.Quick = types.BoolValue(rule.Quick)
	data.Interfaces = utils.StringListGoToTerraform(rule.Interfaces)
	data.Direction = types.StringValue(rule.Direction)
	data.IpVersion = types.StringValue(rule.IpVersion)
	data.Protocol = types.StringValue(rule.Protocol)
	data.Source = types.StringValue(rule.Source)
	data.SourceNot = types.BoolValue(rule.SourceNot)
	data.SourcePort = types.StringValue(rule.SourcePort)
	data.Destination = types.StringValue(rule.Destination)
	data.DestinationNot = types.BoolValue(rule.DestinationNot)
	data.DestinationPort = types.StringValue(rule.DestinationPort)
	data.Gateway = types.StringValue(rule.Gateway)
	data.Log = types.BoolValue(rule.Log)
	data.Categories = utils.StringListGoToTerraform(rule.Categories)
	data.Description = types.StringValue(rule.Description)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Saved traffic %s information to state", resourceName), map[string]any{"success": true})
	tflog.Info(ctx, fmt.Sprintf("Successfully read %s", resourceName), map[string]any{"success": true})
}
