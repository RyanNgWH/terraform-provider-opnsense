package rules

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &shaperRulesResource{}
	_ resource.ResourceWithConfigure   = &shaperRulesResource{}
	_ resource.ResourceWithImportState = &shaperRulesResource{}
)

// NewShaperRulesResource is a helper function to simplify the provider implementation.
func NewShaperRulesResource() resource.Resource {
	return &shaperRulesResource{}
}

// shaperRulesResource defines the resource implementation.
type shaperRulesResource struct {
	client *opnsense.Client
}

// shaperRulesResourceModel describes the resource data model.
type shaperRulesResourceModel struct {
	Id              types.String `tfsdk:"id"`
	LastUpdated     types.String `tfsdk:"last_updated"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	Sequence        types.Int32  `tfsdk:"sequence"`
	Interface       types.String `tfsdk:"interface"`
	Interface2      types.String `tfsdk:"interface2"`
	Protocol        types.String `tfsdk:"protocol"`
	MaxPacketLength types.Int32  `tfsdk:"max_packet_length"`
	Sources         types.Set    `tfsdk:"sources"`
	SourceNot       types.Bool   `tfsdk:"source_not"`
	SourcePort      types.String `tfsdk:"source_port"`
	Destinations    types.Set    `tfsdk:"destinations"`
	DestinationNot  types.Bool   `tfsdk:"destination_not"`
	DestinationPort types.String `tfsdk:"destination_port"`
	Dscp            types.Set    `tfsdk:"dscp"`
	Direction       types.String `tfsdk:"direction"`
	Target          types.String `tfsdk:"target"`
	Description     types.String `tfsdk:"description"`
}

// Metadata returns the resource type name.
func (r *shaperRulesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, shaper.ShaperController, rulesController)
}

// Schema defines the schema for the resource.
func (r *shaperRulesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	defaultSourcesAndDestinations, _ := basetypes.NewSetValue(types.StringType, []attr.Value{basetypes.NewStringValue("any")})
	emptySet, _ := basetypes.NewSetValue(types.StringType, []attr.Value{})

	resp.Schema = schema.Schema{
		Description: "Traffic shaping rules are used to apply the shaping to a certain package flow. The shaping rules are handled independently from the firewall rules and other settings.",

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
				MarkdownDescription: "Whether the traffic shaper rule is enabled. Defaults to `true`.",
				Default:             booldefault.StaticBool(true),
			},
			"sequence": schema.Int32Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Order in which the rule will be evaluated (lowest first). Defaults to `1`.",
				Validators:          []validator.Int32{int32validator.AtLeast(1)},
				Default:             int32default.StaticInt32(1),
			},
			"interface": schema.StringAttribute{
				Required:    true,
				Description: "The interface this rule applies to.",
			},
			"interface2": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The secondary interface, matches packets traveling to/from interface (1) to/from interface (2). Can be combined with direction.",
				Default:     stringdefault.StaticString(""),
			},
			"protocol": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"The applicable protocol for this rule. Must be one of: %s. Defaults to `ip`.", strings.Join(
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
				Default: stringdefault.StaticString("ip"),
			},
			"max_packet_length": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Specifies the maximum size of packets to match in bytes.",
				Validators:  []validator.Int32{int32validator.Between(1, 65535)},
				Default:     int32default.StaticInt32(-1),
			},
			"sources": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Source IPs or networks, examples `10.0.0.0/24`, `10.0.0.1`. Defaults to be `any`.",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1)},
				Default:             setdefault.StaticValue(defaultSourcesAndDestinations),
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
				MarkdownDescription: "Source port number or well known name (`imap`, `imaps`, `http`, `https`, ...), for ranges use a dash. Defaults to `any`",
				Default:             stringdefault.StaticString("any"),
			},
			"destinations": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Destination ips or networks, examples `10.0.0.0/24`, `10.0.0.1`. Defaults to be `any`.",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1)},
				Default:             setdefault.StaticValue(defaultSourcesAndDestinations),
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
				MarkdownDescription: "Destination port number or well known name (`imap`, `imaps`, `http`, `https`, ...), for ranges use a dash. Defaults to `any`",
				Default:             stringdefault.StaticString("any"),
			},
			"dscp": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				MarkdownDescription: fmt.Sprintf(
					"Match against one or multiple DSCP values. Allowed values: %s.", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getDscp(), func(dscp string) string {
							return fmt.Sprintf("`%s`", dscp)
						}),
						", ",
					),
				),
				Validators: []validator.Set{
					// Must be one of the listed values
					setvalidator.ValueStringsAre(stringvalidator.OneOf(getDscp()...)),
				},
				Default: setdefault.StaticValue(emptySet),
			},
			"direction": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"Direction of packet matching. Must be one of: %s. Defaults to `both`.", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getDirection(), func(direction string) string {
							return fmt.Sprintf("`%s`", direction)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getDirection()...),
				},
				Default: stringdefault.StaticString("both"),
			},
			"target": schema.StringAttribute{
				Required:    true,
				Description: "Target pipe or queue.",
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
func (r *shaperRulesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *shaperRulesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Creating %s", resourceName))

	// Read Terraform plan data into the model
	var plan shaperRulesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper rule object
	shaperRule, diags := createShaperRule(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Creating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): shaperRule})

	uuid, err := addShaperRule(r.client, shaperRule)
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
func (r *shaperRulesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", resourceName))

	var state shaperRulesResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get traffic shaper rule
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", resourceName))
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	rule, err := getShaperRule(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s information", resourceName), map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(rule.Enabled)
	state.Sequence = types.Int32Value(rule.Sequence)
	state.Interface = types.StringValue(rule.Interface)
	state.Interface2 = types.StringValue(rule.Interface2)
	state.Protocol = types.StringValue(rule.Protocol)
	state.MaxPacketLength = types.Int32Value(rule.MaxPacketLength)

	sources, diags := utils.SetGoToTerraform(ctx, rule.Sources)
	resp.Diagnostics.Append(diags...)
	state.Sources = sources

	state.SourceNot = types.BoolValue(rule.SourceNot)
	state.SourcePort = types.StringValue(rule.SourcePort)

	destinations, diags := utils.SetGoToTerraform(ctx, rule.Destinations)
	resp.Diagnostics.Append(diags...)
	state.Destinations = destinations

	state.DestinationNot = types.BoolValue(rule.DestinationNot)
	state.DestinationPort = types.StringValue(rule.DestinationPort)

	dscp, diags := utils.SetGoToTerraform(ctx, rule.Dscp)
	resp.Diagnostics.Append(diags...)
	state.Dscp = dscp

	state.Direction = types.StringValue(rule.Direction)
	state.Target = types.StringValue(rule.Target)
	state.Description = types.StringValue(rule.Description)

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
func (r *shaperRulesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Updating %s", resourceName))

	// Read Terraform plan data into the model
	var plan shaperRulesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state shaperRulesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create traffic shaper rule object
	rule, diags := createShaperRule(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update traffic shaper rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Updating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): rule})

	err := setShaperRule(r.client, rule, state.Id.ValueString())
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
func (r *shaperRulesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, fmt.Sprintf("Deleting %s", resourceName))

	// Read Terraform prior state data into the model
	var state shaperRulesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete traffic shaper rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Deleting %s on OPNsense", resourceName), map[string]any{"uuid": state.Id.ValueString()})

	err := deleteShaperRule(r.client, state.Id.ValueString())
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
func (r *shaperRulesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Importing %s", resourceName))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully imported %s", resourceName))
}
