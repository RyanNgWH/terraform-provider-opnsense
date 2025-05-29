package filter

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/automation"
	"terraform-provider-opnsense/internal/utils"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
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
	_ resource.Resource                = &automationFilterResource{}
	_ resource.ResourceWithConfigure   = &automationFilterResource{}
	_ resource.ResourceWithImportState = &automationFilterResource{}
)

// NewAutomationFilterResource is a helper function to simplify the provider implementation.
func NewAutomationFilterResource() resource.Resource {
	return &automationFilterResource{}
}

// automationFilterResource defines the resource implementation.
type automationFilterResource struct {
	client *opnsense.Client
}

// automationFilterResourceModel describes the resource data model.
type automationFilterResourceModel struct {
	Id              types.String   `tfsdk:"id"`
	LastUpdated     types.String   `tfsdk:"last_updated"`
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

// Metadata returns the resource type name.
func (r *automationFilterResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, automation.AutomationController, filterController)
}

// Schema defines the schema for the resource.
func (r *automationFilterResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	emptyList, _ := basetypes.NewListValue(types.StringType, []attr.Value{})

	resp.Schema = schema.Schema{
		Description: "Controls the stateful packet filter, which can be used to restrict or allow traffic from and/or to specific networks as well as influence how traffic should be forwarded.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of the automation filter rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "DateTime when automation filter rule was last updated.",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the rule is enabled. Defaults to `true`.",
				Default:             booldefault.StaticBool(true),
			},
			"sequence": schema.Int32Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Order in which multiple matching rules are evaluated and applied (lowest first). Defaults to `1`.",
				Validators:          []validator.Int32{int32validator.Between(1, 999999)},
				Default:             int32default.StaticInt32(1),
			},
			"action": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"Choose what to do with packets that match the criteria specified. The difference between block and reject is that with reject, a packet (TCP RST or ICMP port unreachable for UDP) is returned to the sender, whereas with block the packet is dropped silently. In either case, the original packet is discarded. Must be one of: %s. Defaults to `pass`", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getActions(), func(action string) string {
							return fmt.Sprintf("`%s`", action)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getActions()...),
				},
				Default: stringdefault.StaticString("pass"),
			},
			"quick": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "If a packet matches a rule specifying quick, then that rule is considered the last matching rule and the specified action is taken. When a rule does not have quick enabled, the last matching rule wins. Defaults to `true`",
				Default:             booldefault.StaticBool(true),
			},
			"interfaces": schema.ListAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Interfaces this rule applies to. Use the interface identifiers (e.g `lan`, `opt1`) Ensure that the interfaces are in lexicographical order, else the provider will detect a change on every execution.",
				Default:             listdefault.StaticValue(emptyList),
			},
			"direction": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"Direction of packet matching. Must be one of: %s. Defaults to `in`.", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getDirections(), func(direction string) string {
							return fmt.Sprintf("`%s`", direction)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getDirections()...),
				},
				Default: stringdefault.StaticString("in"),
			},
			"ip_version": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"The applicable ip version this for this rule. Must be one of: %s. Defaults to `ipv4`.", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getIpVersions(), func(proto string) string {
							return fmt.Sprintf("`%s`", proto)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getIpVersions()...),
				},
				Default: stringdefault.StaticString("ipv4"),
			},
			"protocol": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"The applicable protocol for this rule. Must be one of: %s. Defaults to `any`.", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getProtocols(), func(proto string) string {
							return fmt.Sprintf("`%s`", proto)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getProtocols()...),
				},
				Default: stringdefault.StaticString("any"),
			},
			"source": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Source IP or network. Can be a single network/host, alias or predefined network. For interface addresses, add `ip` to the end of the interface name (e.g `opt1ip`). Defaults to `any`",
				Default:             stringdefault.StaticString("any"),
			},
			"source_not": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the source matching should be inverted. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"source_port": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Source port number or well known name (`imap`, `imaps`, `http`, `https`, ...), for ranges use a dash.",
				Default:             stringdefault.StaticString(""),
			},
			"destination": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Destination IP or network. Can be a single network/host, alias or predefined network. For interface addresses, add `ip` to the end of the interface name (e.g `opt1ip`). Defaults to `any`",
				Default:             stringdefault.StaticString("any"),
			},
			"destination_not": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the destination matching should be inverted. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"destination_port": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Destination port number or well known name (`imap`, `imaps`, `http`, `https`, ...), for ranges use a dash.",
				Default:             stringdefault.StaticString(""),
			},
			"gateway": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Choose a gateway to utilize policy based routing. Leave empty to use the system routing table.",
				Default:     stringdefault.StaticString(""),
			},
			"log": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether packets that are handled by this rule should be logged. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"categories": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "The categories of the rule. Ensure that the categories are in lexicographical order, else the provider will detect a change on every execution.",
				Default:     listdefault.StaticValue(emptyList),
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description to identify this rule.",
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *automationFilterResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *automationFilterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating automation filter rule")

	// Read Terraform plan data into the model
	var plan automationFilterResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create automation filter rule object
	automationFilter, diags := createAutomationFilter(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create automation filter rule on OPNsense
	tflog.Debug(ctx, "Creating automation filter rule on OPNsense", map[string]any{"automation filter rule": automationFilter})

	uuid, err := addAutomationFilterRule(r.client, automationFilter)
	if err != nil {
		resp.Diagnostics.AddError("Create automation filter rule entry error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyAutomationFilterConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Create automation filter rule entry error", fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, "Successfully created automation filter rule entry")
}

// Read resource information.
func (r *automationFilterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state automationFilterResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get automation filter rule
	tflog.Debug(ctx, "Getting automation filter rule information")
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	rule, err := getAutomationFilterRule(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read automation filter rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got automation filter rule information", map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(rule.Enabled)
	state.Sequence = types.Int32Value(rule.Sequence)
	state.Action = types.StringValue(rule.Action)
	state.Quick = types.BoolValue(rule.Quick)
	state.Interfaces = utils.StringListGoToTerraform(rule.Interfaces)
	state.Direction = types.StringValue(rule.Direction)
	state.IpVersion = types.StringValue(rule.IpVersion)
	state.Source = types.StringValue(rule.Source)
	state.SourceNot = types.BoolValue(rule.SourceNot)
	state.SourcePort = types.StringValue(rule.SourcePort)
	state.Destination = types.StringValue(rule.Destination)
	state.DestinationNot = types.BoolValue(rule.DestinationNot)
	state.DestinationPort = types.StringValue(rule.DestinationPort)
	state.Gateway = types.StringValue(rule.Gateway)
	state.Log = types.BoolValue(rule.Log)
	state.Categories = utils.StringListGoToTerraform(rule.Categories)
	state.Description = types.StringValue(rule.Description)

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
func (r *automationFilterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating automation filter rule")

	// Read Terraform plan data into the model
	var plan automationFilterResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state automationFilterResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create automation filter rule object
	rule, diags := createAutomationFilter(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update automation filter rule on OPNsense
	tflog.Debug(ctx, "Updating automation filter rule on OPNsense", map[string]any{"automation filter rule": rule})

	err := setAutomationFilterRule(r.client, rule, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Update automation filter rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyAutomationFilterConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Update automation filter rule error", fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, "Successfully updated automation filter rule")
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *automationFilterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Deleting automation filter rule")

	// Read Terraform prior state data into the model
	var state automationFilterResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete automation filter rule on OPNsense
	tflog.Debug(ctx, "Deleting automation filter rule on OPNsense", map[string]any{"uuid": state.Id.ValueString()})

	err := deleteAutomationFilterRule(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete automation filter rule error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyAutomationFilterConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Delete automation filter rule error", fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	if resp.Diagnostics.HasError() {
		return
	}
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *automationFilterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, "Importing automation filter queue")

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}
}
