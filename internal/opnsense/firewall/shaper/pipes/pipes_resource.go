package pipes

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
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	_ resource.Resource                = &shaperPipesResource{}
	_ resource.ResourceWithConfigure   = &shaperPipesResource{}
	_ resource.ResourceWithImportState = &shaperPipesResource{}
)

// NewShaperPipesResource is a helper function to simplify the provider implementation.
func NewShaperPipesResource() resource.Resource {
	return &shaperPipesResource{}
}

// shaperPipesResource defines the resource implementation.
type shaperPipesResource struct {
	client *opnsense.Client
}

// shaperPipesResourceModel describes the resource data model.
type shaperPipesResourceModel struct {
	Id          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
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

type bandwidthModel struct {
	Value  types.Int64  `tfsdk:"value"`
	Metric types.String `tfsdk:"metric"`
}

type codelModel struct {
	Enabled  types.Bool  `tfsdk:"enabled"`
	Target   types.Int32 `tfsdk:"target"`
	Interval types.Int32 `tfsdk:"interval"`
	Ecn      types.Bool  `tfsdk:"ecn"`
	Quantum  types.Int32 `tfsdk:"quantum"`
	Limit    types.Int32 `tfsdk:"limit"`
	Flows    types.Int32 `tfsdk:"flows"`
}

// Metadata returns the resource type name.
func (r *shaperPipesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, shaper.ShaperController, pipesController)
}

// Schema defines the schema for the resource.
func (r *shaperPipesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A pipe emulates a link with given bandwidth, propagation delay, queue size and packet loss rate. Packets are queued in front of the pipe as they come out from the classifier, and then transferred to the pipe according to the pipe’s parameters.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: fmt.Sprintf("Identifier of the %s.", resourceName),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: fmt.Sprintf("DateTime when the %s was last updated.", resourceName),
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the traffic shaper pipe is enabled. Defaults to `true`.",
				Default:             booldefault.StaticBool(true),
			},
			"bandwidth": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Bandwidth for this pipe.",
				Attributes: map[string]schema.Attribute{
					"value": schema.Int64Attribute{
						Required:    true,
						Description: "Total bandwidth for this pipe.",
						Validators:  []validator.Int64{int64validator.AtLeast(0)},
					},
					"metric": schema.StringAttribute{
						Optional: true,
						Computed: true,
						MarkdownDescription: fmt.Sprintf(
							"Metric used for the bandwidth specified. Must be one of: %s. Values are per second (e.g `bit/s`). Defaults to `bit`.", strings.Join(
								// Surround each type with backticks (`)
								utils.SliceMap(getMetricValues(), func(metric string) string {
									return fmt.Sprintf("`%s`", metric)
								}),
								", ",
							),
						),
						Validators: []validator.String{
							// Type must be one of the listed values
							stringvalidator.OneOf(getMetricValues()...),
						},
						Default: stringdefault.StaticString("bit"),
					},
				},
			},
			"queue": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Number of dynamic queues, leave empty for default.",
				Validators:  []validator.Int32{int32validator.Between(2, 100)},
				Default:     int32default.StaticInt32(-1),
			},
			"mask": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"Dynamic pipe creation by source or destination address. Leave this value empty if you want to create a pipe with a fixed bandwidth. Must be one of: %s. Defaults to `none`", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getMaskTypes(), func(mask string) string {
							return fmt.Sprintf("`%s`", mask)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getMaskTypes()...),
				},
				Default: stringdefault.StaticString("none"),
			},
			"buckets": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Specifies the size of the hash table used for storing the various dynamic pipes configured with the mask setting.",
				Validators:  []validator.Int32{int32validator.Between(1, 65535)},
				Default:     int32default.StaticInt32(-1),
			},
			"scheduler": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"Specifies the scheduling algorithm to use. Must be one of: %s. Defaults to `%s`", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getSchedulers(), func(scheduler string) string {
							return fmt.Sprintf("`%s`", scheduler)
						}),
						", ",
					),
					weightedFairQueueing,
				),
				Default: stringdefault.StaticString(weightedFairQueueing),
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
					"quantum": schema.Int32Attribute{
						Optional:    true,
						Computed:    true,
						Description: "The number of bytes a queue can serve before being moved to the tail of old queues list (bytes), leave empty for defaults.",
						Validators:  []validator.Int32{int32validator.AtLeast(1)},
						Default:     int32default.StaticInt32(-1),
					},
					"limit": schema.Int32Attribute{
						Optional:    true,
						Computed:    true,
						Description: "The hard size limit of all queues managed by this instance, leave empty for defaults.",
						Validators:  []validator.Int32{int32validator.AtLeast(1)},
						Default:     int32default.StaticInt32(-1),
					},
					"flows": schema.Int32Attribute{
						Optional:    true,
						Computed:    true,
						Description: "The number of flow queues that are created and managed, leave empty for defaults.",
						Validators:  []validator.Int32{int32validator.AtLeast(1)},
						Default:     int32default.StaticInt32(-1),
					},
				},
				Default: objectdefault.StaticValue(types.ObjectValueMust(
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
						"enabled":  types.BoolValue(false),
						"target":   types.Int32Value(-1),
						"interval": types.Int32Value(-1),
						"ecn":      types.BoolValue(false),
						"quantum":  types.Int32Value(-1),
						"limit":    types.Int32Value(-1),
						"flows":    types.Int32Value(-1),
					},
				)),
			},
			"pie": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether PIE active queue management should be enabled. Defaults to `false`",
				Default:             booldefault.StaticBool(false),
			},
			"delay": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Add delay in ms to this pipe.",
				Validators:  []validator.Int32{int32validator.Between(1, 3000)},
				Default:     int32default.StaticInt32(-1),
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description to identify this pipe.",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *shaperPipesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *shaperPipesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Creating %s", resourceName))

	// Read Terraform plan data into the model
	var plan shaperPipesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper pipe object
	shaperPipe, diags := createShaperPipe(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper pipe on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Creating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): shaperPipe})

	uuid, err := addShaperPipe(r.client, shaperPipe)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Create %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = shaper.ApplyShaperConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Create %s error", resourceName), fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, fmt.Sprintf("Successfully created %s", resourceName))
}

// Read resource information.
func (r *shaperPipesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", resourceName))

	var state shaperPipesResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get traffic shaper pipe
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", resourceName))
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	pipe, err := getShaperPipe(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s information", resourceName), map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(pipe.Enabled)
	state.Queue = types.Int32Value(pipe.Queue)
	state.Mask = types.StringValue(pipe.Mask)
	state.Buckets = types.Int32Value(pipe.Buckets)
	state.Scheduler = types.StringValue(pipe.Scheduler)
	state.Pie = types.BoolValue(pipe.Pie)
	state.Delay = types.Int32Value(pipe.Delay)
	state.Description = types.StringValue(pipe.Description)

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
	state.Bandwidth = bandwidth

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
	state.Codel = codel

	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully read %s", resourceName))
}

// Update updates the resource on OPNsense and the Terraform state.
func (r *shaperPipesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Updating %s", resourceName))

	// Read Terraform plan data into the model
	var plan shaperPipesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state shaperPipesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper pipe object
	rule, diags := createShaperPipe(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update traffic shaper pipe on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Updating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): rule})

	err := setShaperPipe(r.client, rule, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Update %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = shaper.ApplyShaperConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Update %s error", resourceName), fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, fmt.Sprintf("Successfully updated %s", resourceName))
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *shaperPipesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, fmt.Sprintf("Deleting %s", resourceName))

	// Read Terraform prior state data into the model
	var state shaperPipesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete traffic shaper pipe on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Deleting %s on OPNsense", resourceName), map[string]any{"uuid": state.Id.ValueString()})

	err := deleteShaperPipe(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Delete %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = shaper.ApplyShaperConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Delete %s error", resourceName), fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully deleted %s", resourceName))
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *shaperPipesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Importing %s", resourceName))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully imported %s", resourceName))
}
