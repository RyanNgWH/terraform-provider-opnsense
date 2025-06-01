package sourcenat

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/opnsense/firewall/automation"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
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
	_ resource.Resource                = &automationSourceNatResource{}
	_ resource.ResourceWithConfigure   = &automationSourceNatResource{}
	_ resource.ResourceWithImportState = &automationSourceNatResource{}
)

// NewAutomationSourceNatResource is a helper function to simplify the provider implementation.
func NewAutomationSourceNatResource() resource.Resource {
	return &automationSourceNatResource{}
}

// automationSourceNatResource defines the resource implementation.
type automationSourceNatResource struct {
	client *opnsense.Client
}

// automationSourceNatResourceModel describes the resource data model.
type automationSourceNatResourceModel struct {
	Id              types.String `tfsdk:"id"`
	LastUpdated     types.String `tfsdk:"last_updated"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	NoNat           types.Bool   `tfsdk:"no_nat"`
	Sequence        types.Int32  `tfsdk:"sequence"`
	Interface       types.String `tfsdk:"interface"`
	IpVersion       types.String `tfsdk:"ip_version"`
	Protocol        types.String `tfsdk:"protocol"`
	Source          types.String `tfsdk:"source"`
	SourceNot       types.Bool   `tfsdk:"source_not"`
	SourcePort      types.String `tfsdk:"source_port"`
	Destination     types.String `tfsdk:"destination"`
	DestinationNot  types.Bool   `tfsdk:"destination_not"`
	DestinationPort types.String `tfsdk:"destination_port"`
	Target          types.String `tfsdk:"target"`
	TargetPort      types.String `tfsdk:"target_port"`
	Log             types.Bool   `tfsdk:"log"`
	Categories      types.Set    `tfsdk:"categories"`
	Description     types.String `tfsdk:"description"`
}

// Metadata returns the resource type name.
func (r *automationSourceNatResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, automation.AutomationController, sourceNatController)
}

// Schema defines the schema for the resource.
func (r *automationSourceNatResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	emptySet, _ := basetypes.NewSetValue(types.StringType, []attr.Value{})

	resp.Schema = schema.Schema{
		Description: "When a client on an internal network makes an outbound request, the gateway will have to change the source IP to the external IP of the gateway, since the outside server will not be able to send an answer back otherwise. Source NAT is also known as Outbound NAT or Masquerading.",

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
				MarkdownDescription: "Whether the rule is enabled. Defaults to `true`.",
				Default:             booldefault.StaticBool(true),
			},
			"no_nat": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Disable NAT for all traffic matching this rule and stop processing source nat rules. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"sequence": schema.Int32Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Order in which multiple matching rules are evaluated and applied (lowest first). Defaults to `1`.",
				Validators:          []validator.Int32{int32validator.Between(1, 999999)},
				Default:             int32default.StaticInt32(1),
			},
			"interface": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Interface this rule applies to. Use the interface identifiers (e.g `lan`, `opt1`).",
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
			"target": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: " Packets matching this rule will be mapped to this IP address or network. Can be a single network/host, alias or predefined network. For interface addresses, add `ip` to the end of the interface name (e.g `opt1ip`). Defaults to `any`",
			},
			"target_port": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Target port number or well known name (`imap`, `imaps`, `http`, `https`, ...), for ranges use a dash.",
				Default:     stringdefault.StaticString(""),
			},
			"log": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether packets that are handled by this rule should be logged. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"categories": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "The categories of the rule.",
				Default:     setdefault.StaticValue(emptySet),
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
func (r *automationSourceNatResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *automationSourceNatResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Creating %s", resourceName))

	// Read Terraform plan data into the model
	var plan automationSourceNatResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create automation source nat rule object
	automationSourceNat, diags := createAutomationSourceNat(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create automation source nat rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Creating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): automationSourceNat})

	uuid, err := addAutomationSourceNatRule(r.client, automationSourceNat)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Create %s entry error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyAutomationSourceNatConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Create %s entry error", resourceName), fmt.Sprintf("%s", err))
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
func (r *automationSourceNatResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", resourceName))

	var state automationSourceNatResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get automation source nat rule
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", resourceName))
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	rule, err := getAutomationSourceNatRule(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s rule information", resourceName), map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(rule.Enabled)
	state.NoNat = types.BoolValue(rule.NoNat)
	state.Sequence = types.Int32Value(rule.Sequence)
	state.Interface = types.StringValue(rule.Interface)
	state.IpVersion = types.StringValue(rule.IpVersion)
	state.Protocol = types.StringValue(rule.Protocol)
	state.Source = types.StringValue(rule.Source)
	state.SourceNot = types.BoolValue(rule.SourceNot)
	state.SourcePort = types.StringValue(rule.SourcePort)
	state.Destination = types.StringValue(rule.Destination)
	state.DestinationNot = types.BoolValue(rule.DestinationNot)
	state.DestinationPort = types.StringValue(rule.DestinationPort)
	state.Target = types.StringValue(rule.Target)
	state.TargetPort = types.StringValue(rule.TargetPort)
	state.Log = types.BoolValue(rule.Log)

	categories, diags := utils.SetGoToTerraform(ctx, rule.Categories)
	resp.Diagnostics.Append(diags...)
	state.Categories = categories

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
func (r *automationSourceNatResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Updating %s", resourceName))

	// Read Terraform plan data into the model
	var plan automationSourceNatResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state automationSourceNatResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create automation source nat rule object
	rule, diags := createAutomationSourceNat(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update automation source nat rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Updating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): rule})

	err := setAutomationSourceNatRule(r.client, rule, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Update %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyAutomationSourceNatConfig(r.client)
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
func (r *automationSourceNatResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, fmt.Sprintf("Deleting %s", resourceName))

	// Read Terraform prior state data into the model
	var state automationSourceNatResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete automation source nat rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Deleting %s on OPNsense", resourceName), map[string]any{"uuid": state.Id.ValueString()})

	err := deleteAutomationSourceNatRule(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Delete %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyAutomationSourceNatConfig(r.client)
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
func (r *automationSourceNatResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Importing %s", resourceName))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully imported %s", resourceName))
}
