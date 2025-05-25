package nptv6

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/nat"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &natNptv6Resource{}
	_ resource.ResourceWithConfigure   = &natNptv6Resource{}
	_ resource.ResourceWithImportState = &natNptv6Resource{}
)

// NewNatNptv6Resource is a helper function to simplify the provider implementation.
func NewNatNptv6Resource() resource.Resource {
	return &natNptv6Resource{}
}

// natNptv6Resource defines the resource implementation.
type natNptv6Resource struct {
	client *opnsense.Client
}

// natNptv6ResourceModel describes the resource data model.
type natNptv6ResourceModel struct {
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

// Metadata returns the resource type name.
func (r *natNptv6Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, nat.NatController, nptv6Controller)
}

// Schema defines the schema for the resource.
func (r *natNptv6Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	defaultCategories, _ := basetypes.NewListValue(types.StringType, []attr.Value{})

	resp.Schema = schema.Schema{
		MarkdownDescription: "Network Prefix Translation, shortened to NPTv6, is used to translate IPv6 addresses.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of the nptv6 nat entry.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "DateTime when nptv6 entry was last updated.",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the nptv6 nat entry is enabled. Defaults to `true`.",
				Default:             booldefault.StaticBool(true),
			},
			"log": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether packets that are handled by this rule should be logged. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"sequence": schema.Int32Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Order in which multiple matching rules are evaluated and applied. Defaults to `1`.",
				Default:             int32default.StaticInt32(1),
			},
			"interface": schema.StringAttribute{
				Required:    true,
				Description: "The interface this rule applies to.",
			},
			"internal_prefix": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The internal IPv6 prefix used in the LAN(s). This will replace the prefix of the destination address in inbound packets. The prefix size specified here will also be applied to the external prefix.",
			},
			"external_prefix": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The external IPv6 prefix. This will replace the prefix of the source address in outbound packets. Leave empty to auto-detect the prefix address using the specified tracking interface instead. The prefix size specified for the internal prefix will also be applied to the external prefix.",
				Default:     stringdefault.StaticString(""),
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.Expressions{
						path.MatchRoot("track_interface"),
					}...),
				},
			},
			"track_interface": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Use prefix defined on the selected interface instead of the interface this rule applies to when target prefix is not provided.",
				Default:     stringdefault.StaticString(""),
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.Expressions{
						path.MatchRoot("external_prefix"),
					}...),
				},
			},
			"categories": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "The categories of the rule. Ensure that the categories are in lexicographical order, else the provider will detect a change on every execution.",
				Default:     listdefault.StaticValue(defaultCategories),
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The description of the rule.",
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *natNptv6Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *natNptv6Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating NPTv6 NAT rule")

	// Read Terraform plan data into the model
	var plan natNptv6ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create NPTv6 NAT object
	nptv6, diags := createNptv6Nat(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create NPTv6 NAT on OPNsense
	tflog.Debug(ctx, "Creating NPTv6 NAT rule on OPNsense", map[string]any{"NPTv6 NAT": nptv6})

	uuid, err := addNptv6Nat(r.client, nptv6)
	if err != nil {
		resp.Diagnostics.AddError("Create NPTv6 NAT entry error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyNptv6NatConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Create NPTv6 NAT entry error", fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, "Successfully created NPTv6 NAT entry")
}

// Read resource information.
func (r *natNptv6Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state natNptv6ResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get NPTv6 NAT rule
	tflog.Debug(ctx, "Getting NPTv6 NAT rule information")
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	rule, err := getNptv6Nat(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read NPTv6 NAT rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got NPTv6 NAT rule information", map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(rule.Enabled)
	state.Log = types.BoolValue(rule.Log)
	state.Sequence = types.Int32Value(rule.Sequence)
	state.Interface = types.StringValue(rule.Interface)
	state.InternalPrefix = types.StringValue(rule.InternalPrefix)
	state.ExternalPrefix = types.StringValue(rule.ExternalPrefix)
	state.TrackInterface = types.StringValue(rule.TrackInterface)
	state.Description = types.StringValue(rule.Description)

	state.Categories = utils.StringListGoToTerraform(rule.Categories)

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
func (r *natNptv6Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating firewall NPTv6 NAT rule")

	// Read Terraform plan data into the model
	var plan natNptv6ResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state natNptv6ResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create NPTv6 NAT object
	rule, diags := createNptv6Nat(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update NPTv6 NAT rule on OPNsense
	tflog.Debug(ctx, "Updating NPTv6 NAT rule on OPNsense", map[string]any{"NPTv6 NAT rule": rule})

	err := setNptv6Nat(r.client, rule, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Update NPTv6 NAT rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyNptv6NatConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Update NPTv6 NAT rule error", fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, "Successfully updated firewall NPTv6 NAT rule")
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *natNptv6Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Deleting firewall NPTv6 NAT rule")

	// Read Terraform prior state data into the model
	var state natNptv6ResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete NPTv6 NAT rule on OPNsense
	tflog.Debug(ctx, "Deleting NPTv6 NAT rule on OPNsense", map[string]any{"uuid": state.Id.ValueString()})

	err := deleteNptv6Nat(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete NPTv6 NAT rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyNptv6NatConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Delete NPTv6 NAT rule error", fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	if resp.Diagnostics.HasError() {
		return
	}
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *natNptv6Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, "Importing firewall NPTv6 NAT rule")

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}
}
