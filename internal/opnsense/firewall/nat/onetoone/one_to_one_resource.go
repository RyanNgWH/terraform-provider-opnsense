package onetoone

import (
	"context"
	"fmt"
	"reflect"
	"strings"
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
	_ resource.Resource                = &natOneToOneResource{}
	_ resource.ResourceWithConfigure   = &natOneToOneResource{}
	_ resource.ResourceWithImportState = &natOneToOneResource{}
)

// NewNatOneToOneResource is a helper function to simplify the provider implementation.
func NewNatOneToOneResource() resource.Resource {
	return &natOneToOneResource{}
}

// natOneToOneResource defines the resource implementation.
type natOneToOneResource struct {
	client *opnsense.Client
}

// natOneToOneResourceModel describes the resource data model.
type natOneToOneResourceModel struct {
	Id             types.String `tfsdk:"id"`
	LastUpdated    types.String `tfsdk:"last_updated"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	Log            types.Bool   `tfsdk:"log"`
	Sequence       types.Int32  `tfsdk:"sequence"`
	Interface      types.String `tfsdk:"interface"`
	Type           types.String `tfsdk:"type"`
	Source         types.String `tfsdk:"source"`
	SourceNot      types.Bool   `tfsdk:"source_not"`
	Destination    types.String `tfsdk:"destination"`
	DestinationNot types.Bool   `tfsdk:"destination_not"`
	External       types.String `tfsdk:"external"`
	NatReflection  types.String `tfsdk:"nat_reflection"`
	Categories     types.Set    `tfsdk:"categories"`
	Description    types.String `tfsdk:"description"`
}

// Metadata returns the resource type name.
func (r *natOneToOneResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_%s", req.ProviderTypeName, firewall.TypeName, nat.NatController, oneToOneController)
}

// Schema defines the schema for the resource.
func (r *natOneToOneResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	emptySet, _ := basetypes.NewSetValue(types.StringType, []attr.Value{})

	resp.Schema = schema.Schema{
		MarkdownDescription: "One-to-one NAT will translate two IPs one-to-one, rather than one-to-many as is most common.",

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
				Description: fmt.Sprintf("DateTime when the %s entry was last updated.", resourceName),
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the one-to-one nat entry is enabled. Defaults to `true`.",
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
			"type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: fmt.Sprintf(
					"The type of the nat rule. Must be one of: %s", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getNatTypes(), func(natType string) string {
							return fmt.Sprintf("`%s`", natType)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getNatTypes()...),
				},
			},
			"source": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The internal subnet for this 1:1 mapping. Can be a single network/host, alias or predefined network. For interface addresses, add `ip` to the end of the interface name (e.g `opt1ip`).",
			},
			"source_not": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the source matching should be inverted. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"destination": schema.StringAttribute{
				Required:    true,
				Description: "The 1:1 mapping will only be used for connections to or from the specified destination. Can be a single network/host, alias or predefined network. For interface addresses, add `ip` to the end of the interface name (e.g `opt1ip`).",
			},
			"destination_not": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the destination matching should be inverted. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"external": schema.StringAttribute{
				Required:    true,
				Description: "The external subnet's starting address for the 1:1 mapping or network. This is the address or network the traffic will translate to/from.",
			},
			"nat_reflection": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: fmt.Sprintf(
					"Whether nat reflection should be enabled. Must be one of: %s. Defaults to `default`.", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getNatReflectionOptions(), func(option string) string {
							return fmt.Sprintf("`%s`", option)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getNatReflectionOptions()...),
				},
				Default: stringdefault.StaticString("default"),
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
				Description: "The description of the rule.",
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *natOneToOneResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *natOneToOneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Creating %s", resourceName))

	// Read Terraform plan data into the model
	var plan natOneToOneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create one-to-one NAT object
	oneToOneNat, diags := createOneToOneNat(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create one-to-one NAT on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Creating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): oneToOneNat})

	uuid, err := addOneToOneNat(r.client, oneToOneNat)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Create %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyOneToOneNatConfig(r.client)
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
func (r *natOneToOneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", resourceName))

	var state natOneToOneResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get one-to-one NAT rule
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", resourceName))
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	rule, err := getOneToOneNat(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s information", resourceName), map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(rule.Enabled)
	state.Log = types.BoolValue(rule.Log)
	state.Sequence = types.Int32Value(rule.Sequence)
	state.Interface = types.StringValue(rule.Interface)
	state.Type = types.StringValue(rule.Type)
	state.Source = types.StringValue(rule.Source)
	state.SourceNot = types.BoolValue(rule.SourceNot)
	state.Destination = types.StringValue(rule.Destination)
	state.DestinationNot = types.BoolValue(rule.DestinationNot)
	state.External = types.StringValue(rule.External)
	state.NatReflection = types.StringValue(rule.NatRefection)
	state.Description = types.StringValue(rule.Description)

	categories, diags := utils.SetGoToTerraform(ctx, rule.Categories)
	resp.Diagnostics.Append(diags...)
	state.Categories = categories

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
func (r *natOneToOneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Updating %s", resourceName))

	// Read Terraform plan data into the model
	var plan natOneToOneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state natOneToOneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create one-to-one NAT object
	rule, diags := createOneToOneNat(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update one-to-one NAT rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Updating %s on OPNsense", resourceName), map[string]any{fmt.Sprintf("%s", resourceName): rule})

	err := setOneToOneNat(r.client, rule, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Update %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyOneToOneNatConfig(r.client)
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
func (r *natOneToOneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, fmt.Sprintf("Deleting %s", resourceName))

	// Read Terraform prior state data into the model
	var state natOneToOneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete one-to-one NAT rule on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Deleting %s on OPNsense", resourceName), map[string]any{"uuid": state.Id.ValueString()})

	err := deleteOneToOneNat(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Delete %s error", resourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyOneToOneNatConfig(r.client)
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
func (r *natOneToOneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Importing %s", resourceName))

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully imported %s", resourceName))
}
