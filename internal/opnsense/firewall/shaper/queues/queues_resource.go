package queues

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper"
	"terraform-provider-opnsense/internal/utils"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &shaperQueuesResource{}
	_ resource.ResourceWithConfigure   = &shaperQueuesResource{}
	_ resource.ResourceWithImportState = &shaperQueuesResource{}
)

// NewShaperQueuesResource is a helper function to simplify the provider implementation.
func NewShaperQueuesResource() resource.Resource {
	return &shaperQueuesResource{}
}

// shaperQueuesResource defines the resource implementation.
type shaperQueuesResource struct {
	client *opnsense.Client
}

// shaperQueuesResourceModel describes the resource data model.
type shaperQueuesResourceModel struct {
	Id          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Pipe        types.String `tfsdk:"pipe"`
	Weight      types.Int32  `tfsdk:"weight"`
	Mask        types.String `tfsdk:"mask"`
	Buckets     types.Int32  `tfsdk:"buckets"`
	Codel       types.Object `tfsdk:"codel"`
	Pie         types.Bool   `tfsdk:"pie"`
	Description types.String `tfsdk:"description"`
}

type codelModel struct {
	Enabled  types.Bool  `tfsdk:"enabled"`
	Target   types.Int32 `tfsdk:"target"`
	Interval types.Int32 `tfsdk:"interval"`
	Ecn      types.Bool  `tfsdk:"ecn"`
}

// Metadata returns the resource type name.
func (r *shaperQueuesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, shaper.ShaperController, queuesController)
}

// Schema defines the schema for the resource.
func (r *shaperQueuesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A queue is an abstraction used to implement the WF2Q+ (Worstcase Fair Weighted Fair Queueing) policy, which is an efficient variant of the WFQ policy. The queue associates a weight and a reference pipe to each flow, and then all backlogged (i.e., with packets queued) flows linked to the same pipe share the pipe’s bandwidth proportionally to their weights. Note that weights are not priorities; a flow with a lower weight is still guaranteed to get its fraction of the bandwidth even if a flow with a higher weight is permanently backlogged.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of the traffic shaper queue.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "DateTime when traffic shaper queue was last updated.",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the traffic shaper queue is enabled. Defaults to `true`.",
				Default:             booldefault.StaticBool(true),
			},
			"pipe": schema.StringAttribute{
				Required:    true,
				Description: "Connected pipe for this queue.",
			},
			"weight": schema.Int32Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: " Weight of this queue (`1..100`), used to prioritize within a pipe. (1 is low, 100 is high). Defaults to `100`",
				Validators:          []validator.Int32{int32validator.Between(1, 100)},
				Default:             int32default.StaticInt32(100),
			},
			"mask": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"Dynamic queue creation by source or destination address. Leave this value empty if you want to specify multiple queues with different weights. Must be one of: %s. Defaults to `none`", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getMaskTypes(), func(mask string) string {
							return fmt.Sprintf("`%s`", mask)
						}),
						", ",
					),
				),
				Default: stringdefault.StaticString("none"),
			},
			"buckets": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Specifies the size of the hash table used for storing the various dynamic pipes configured with the mask setting.",
				Validators:  []validator.Int32{int32validator.Between(1, 65535)},
				Default:     int32default.StaticInt32(-1),
			},
			"codel": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "CoDel active queue management.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Whether CoDel active queue management is enabled.",
						Default:     booldefault.StaticBool(false),
					},
					"target": schema.Int32Attribute{
						Optional:    true,
						Computed:    true,
						Description: "Minimum acceptable persistent queue delay (in ms), leave empty for default.",
						Validators:  []validator.Int32{int32validator.AtLeast(1)},
						Default:     int32default.StaticInt32(-1),
					},
					"interval": schema.Int32Attribute{
						Optional:    true,
						Computed:    true,
						Description: "Interval before dropping packets (in ms), leave empty for default.",
						Validators:  []validator.Int32{int32validator.AtLeast(1)},
						Default:     int32default.StaticInt32(-1),
					},
					"ecn": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						MarkdownDescription: "Whether explicit congestion notification is enabled. Defaults to 'false`",
						Default:             booldefault.StaticBool(false),
					},
				},
				Default: objectdefault.StaticValue(types.ObjectValueMust(
					map[string]attr.Type{
						"enabled":  types.BoolType,
						"target":   types.Int32Type,
						"interval": types.Int32Type,
						"ecn":      types.BoolType,
					},
					map[string]attr.Value{
						"enabled":  types.BoolValue(false),
						"target":   types.Int32Value(-1),
						"interval": types.Int32Value(-1),
						"ecn":      types.BoolValue(false),
					},
				)),
			},
			"pie": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether PIE active queue management should be enabled. Defaults to `false`",
				Default:             booldefault.StaticBool(false),
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description to identify this queue.",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *shaperQueuesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*opnsense.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *opnsense.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *shaperQueuesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating traffic shaper queue")

	// Read Terraform plan data into the model
	var plan shaperQueuesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper queue object
	shaperQueue, diags := createShaperQueue(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper queue on OPNsense
	tflog.Debug(ctx, "Creating traffic shaper queue on OPNsense", map[string]any{"traffic shaper queue": shaperQueue})

	uuid, err := addShaperQueue(r.client, shaperQueue)
	if err != nil {
		resp.Diagnostics.AddError("Create traffic shaper queue entry error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = shaper.ApplyShaperConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Create traffic shaper queue entry error", fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	// Update plan ID & last_updated fields
	plan.Id = types.StringValue(uuid)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC3339))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Successfully created traffic shaper queue entry")
}

// Read resource information.
func (r *shaperQueuesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state shaperQueuesResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get traffic shaper queue
	tflog.Debug(ctx, "Getting traffic shaper queue information")
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	queue, err := getShaperQueue(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read traffic shaper queue error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got traffic shaper queue information", map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(queue.Enabled)
	state.Pipe = types.StringValue(queue.Pipe)
	state.Weight = types.Int32Value(queue.Weight)
	state.Mask = types.StringValue(queue.Mask)
	state.Buckets = types.Int32Value(queue.Buckets)
	state.Pie = types.BoolValue(queue.Pie)
	state.Description = types.StringValue(queue.Description)

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
	state.Codel = codel

	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource on OPNsense and the Terraform state.
func (r *shaperQueuesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating traffic shaper queue")

	// Read Terraform plan data into the model
	var plan shaperQueuesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state shaperQueuesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper queue object
	queue, diags := createShaperQueue(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update traffic shaper queue on OPNsense
	tflog.Debug(ctx, "Updating traffic shaper queue on OPNsense", map[string]any{"traffic shaper queue": queue})

	err := setShaperQueue(r.client, queue, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Update traffic shaper queue error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = shaper.ApplyShaperConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Update traffic shaper queue error", fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	// Update last_updated field (if change detected)
	if !(reflect.DeepEqual(plan, state)) {
		plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC3339))
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Successfully updated ftraffic shaper queue")
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *shaperQueuesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Deleting traffic shaper queue")

	// Read Terraform prior state data into the model
	var state shaperQueuesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete traffic shaper queue on OPNsense
	tflog.Debug(ctx, "Deleting traffic shaper queue on OPNsense", map[string]any{"uuid": state.Id.ValueString()})

	err := deleteShaperQueue(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete traffic shaper queue error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = shaper.ApplyShaperConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Delete traffic shaper queue error", fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	if resp.Diagnostics.HasError() {
		return
	}
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *shaperQueuesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, "Importing traffic shaper queue")

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}
}
