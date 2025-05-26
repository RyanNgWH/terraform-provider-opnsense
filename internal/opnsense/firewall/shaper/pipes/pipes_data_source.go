package pipes

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &shaperPipesDataSource{}
	_ datasource.DataSourceWithConfigure = &shaperPipesDataSource{}
)

// NewShaperPipesDataSource is a helper function to simplify the provider implementation.
func NewShaperPipesDataSource() datasource.DataSource {
	return &shaperPipesDataSource{}
}

// shaperPipesDataSource defines the data source implementation.
type shaperPipesDataSource struct {
	client *opnsense.Client
}

// shaperPipesDataSourceModel describes the resource data model.
type shaperPipesDataSourceModel struct {
	Id          types.String `tfsdk:"id"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Bandwidth   types.Object `tfsdk:"bandwidth"`
	Queue       types.Int32  `tfsdk:"queue"`
	Mask        types.String `tfsdk:"mask"`
	Buckets     types.Int32  `tfsdk:"buckets"`
	Scheduler   types.String `tfsdk:"scheduler"`
	Codel       types.Object `tfsdk:"codel"`
	Pie         types.Bool   `tfsdk:"pie"`
	Delay       types.Int32  `tfsdk:"delay"`
	Description types.String `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *shaperPipesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s", req.ProviderTypeName, firewall.TypeName, pipesController)
}

// Schema defines the schema for the datasource.
func (d *shaperPipesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about a traffic shaper pipe.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Identifier of the traffic shaper pipe.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the traffic shaper pipe is enabled.",
			},
			"bandwidth": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Bandwidth for this pipe.",
				Attributes: map[string]schema.Attribute{
					"value": schema.Int64Attribute{
						Computed:    true,
						Description: "Total bandwidth for this pipe.",
					},
					"metric": schema.StringAttribute{
						Computed:    true,
						Description: "Metric used for the bandwidth specified. Values are per second (e.g `bit/s`).",
					},
				},
			},
			"queue": schema.Int32Attribute{
				Computed:    true,
				Description: "Number of dynamic queues, negative values are treated as default (i.e empty).",
			},
			"mask": schema.StringAttribute{
				Computed:    true,
				Description: "Dynamic pipe creation by source or destination address.",
			},
			"buckets": schema.Int32Attribute{
				Computed:    true,
				Description: "Specifies the size of the hash table used for storing the various dynamic pipes configured with the mask setting. Negative values are treated as default (i.e empty)",
			},
			"scheduler": schema.StringAttribute{
				Computed:    true,
				Description: "Specifies the scheduling algorithm to use.",
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
					"quantum": schema.Int32Attribute{
						Computed:    true,
						Description: "The number of bytes a queue can serve before being moved to the tail of old queues list (bytes), negative values are treated as default (i.e empty).",
					},
					"limit": schema.Int32Attribute{
						Computed:    true,
						Description: "The hard size limit of all queues managed by this instance, negative values are treated as default (i.e empty).",
					},
					"flows": schema.Int32Attribute{
						Computed:    true,
						Description: "The number of flow queues that are created and managed, negative values are treated as default (i.e empty).",
					},
				},
			},
			"pie": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether PIE active queue management should be enabled.",
			},
			"delay": schema.Int32Attribute{
				Computed:    true,
				Description: "Add delay in ms to this pipe. Negative values are treated as default (i.e empty)",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description to identify this pipe.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *shaperPipesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *shaperPipesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, "Reading traffic shaper pipe")

	// Read Terraform configuration data into the model
	var data shaperPipesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get traffic shaper pipe
	tflog.Debug(ctx, "Getting traffic shaper pipe information")
	tflog.SetField(ctx, "uuid", data.Id.ValueString())

	pipe, err := getShaperPipe(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read traffic shaper pipe error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got traffic shaper pipe information", map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, "Saving traffic shaper pipe information to state", map[string]any{"pipe": pipe})

	data.Enabled = types.BoolValue(pipe.Enabled)
	data.Queue = types.Int32Value(pipe.Queue)
	data.Mask = types.StringValue(pipe.Mask)
	data.Buckets = types.Int32Value(pipe.Buckets)
	data.Scheduler = types.StringValue(pipe.Scheduler)
	data.Pie = types.BoolValue(pipe.Pie)
	data.Delay = types.Int32Value(pipe.Delay)
	data.Description = types.StringValue(pipe.Description)

	bandwidth, diags := types.ObjectValue(
		map[string]attr.Type{
			"value":  types.Int64Type,
			"metric": types.StringType,
		},
		map[string]attr.Value{
			"value":  types.Int64Value(pipe.Bandwidth.Value),
			"metric": types.StringValue(pipe.Bandwidth.Metric),
		},
	)
	resp.Diagnostics.Append(diags...)
	data.Bandwidth = bandwidth

	codel, diags := types.ObjectValue(
		map[string]attr.Type{
			"enabled":  types.BoolType,
			"target":   types.Int32Type,
			"interval": types.Int32Type,
			"ecn":      types.BoolType,
			"quantum":  types.Int32Type,
			"limit":    types.Int32Type,
			"flows":    types.Int32Type,
		},
		map[string]attr.Value{
			"enabled":  types.BoolValue(pipe.Codel.Enabled),
			"target":   types.Int32Value(pipe.Codel.Target),
			"interval": types.Int32Value(pipe.Codel.Interval),
			"ecn":      types.BoolValue(pipe.Codel.Ecn),
			"quantum":  types.Int32Value(pipe.Codel.Quantum),
			"limit":    types.Int32Value(pipe.Codel.Limit),
			"flows":    types.Int32Value(pipe.Codel.Flows),
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

	tflog.Debug(ctx, "Saved traffic shaper pipe information to state", map[string]any{"success": true})
	tflog.Info(ctx, "Successfully read traffic shaper pipe", map[string]any{"success": true})
}
