package queues

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &shaperQueuesDataSource{}
	_ datasource.DataSourceWithConfigure = &shaperQueuesDataSource{}
)

// NewShaperQueuesDataSource is a helper function to simplify the provider implementation.
func NewShaperQueuesDataSource() datasource.DataSource {
	return &shaperQueuesDataSource{}
}

// shaperQueuesDataSource defines the data source implementation.
type shaperQueuesDataSource struct {
	client *opnsense.Client
}

// shaperQueuesDataSourceModel describes the resource data model.
type shaperQueuesDataSourceModel struct {
	Id          types.String `tfsdk:"id"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Pipe        types.String `tfsdk:"pipe"`
	Weight      types.Int32  `tfsdk:"weight"`
	Mask        types.String `tfsdk:"mask"`
	Buckets     types.Int32  `tfsdk:"buckets"`
	Codel       types.Object `tfsdk:"codel"`
	Pie         types.Bool   `tfsdk:"pie"`
	Description types.String `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *shaperQueuesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, shaper.ShaperController, queuesController)
}

// Schema defines the schema for the datasource.
func (d *shaperQueuesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about a traffic shaper queue.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier of the traffic shaper queue.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the traffic shaper queue is enabled.",
			},
			"pipe": schema.StringAttribute{
				Computed:    true,
				Description: "Connected pipe for this queue.",
			},
			"weight": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: " Weight of this queue (`1..100`), used to prioritize within a pipe. (1 is low, 100 is high).",
			},
			"mask": schema.StringAttribute{
				Computed:    true,
				Description: "Dynamic queue creation by source or destination address.",
			},
			"buckets": schema.Int32Attribute{
				Computed:    true,
				Description: "Specifies the size of the hash table used for storing the various dynamic queues configured with the mask setting. Negative values are treated as default (i.e empty)",
			},
			"codel": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "CoDel active queue management.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether CoDel active queue management is enabled.",
					},
					"target": schema.Int32Attribute{
						Computed:    true,
						Description: "Minimum acceptable persistent queue delay (in ms), negative values are treated as default (i.e empty).",
					},
					"interval": schema.Int32Attribute{
						Computed:    true,
						Description: "Interval before dropping packets (in ms), negative values are treated as default (i.e empty).",
					},
					"ecn": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether explicit congestion notification is enabled.",
					},
				},
			},
			"pie": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether PIE active queue management should be enabled.",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description to identify this pipe.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *shaperQueuesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *shaperQueuesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, "Reading traffic shaper queue")

	// Read Terraform configuration data into the model
	var data shaperQueuesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get traffic shaper queue
	tflog.Debug(ctx, "Getting traffic shaper queue information")
	tflog.SetField(ctx, "uuid", data.Id.ValueString())

	queue, err := getShaperQueue(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read traffic shaper queue error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got traffic shaper queue information", map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, "Saving traffic shaper queue information to state", map[string]any{"queue": queue})

	data.Enabled = types.BoolValue(queue.Enabled)
	data.Pipe = types.StringValue(queue.Pipe)
	data.Weight = types.Int32Value(queue.Weight)
	data.Mask = types.StringValue(queue.Mask)
	data.Buckets = types.Int32Value(queue.Buckets)
	data.Pie = types.BoolValue(queue.Pie)
	data.Description = types.StringValue(queue.Description)

	codel, diags := types.ObjectValue(
		map[string]attr.Type{
			"enabled":  types.BoolType,
			"target":   types.Int32Type,
			"interval": types.Int32Type,
			"ecn":      types.BoolType,
		},
		map[string]attr.Value{
			"enabled":  types.BoolValue(queue.Codel.Enabled),
			"target":   types.Int32Value(queue.Codel.Target),
			"interval": types.Int32Value(queue.Codel.Interval),
			"ecn":      types.BoolValue(queue.Codel.Ecn),
		},
	)
	resp.Diagnostics.Append(diags...)
	data.Codel = codel

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Saved traffic shaper queue information to state", map[string]any{"success": true})
	tflog.Info(ctx, "Successfully read traffic shaper queue", map[string]any{"success": true})
}
