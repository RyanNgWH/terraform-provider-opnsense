package alias

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &aliasResource{}
	_ resource.ResourceWithConfigure   = &aliasResource{}
	_ resource.ResourceWithImportState = &aliasResource{}
)

// NewAliasResource is a helper function to simplify the provider implementation.
func NewAliasResource() resource.Resource {
	return &aliasResource{}
}

// aliasResource defines the resource implementation.
type aliasResource struct {
	client *opnsense.Client
}

// aliasResourceModel describes the resource data model.
type aliasResourceModel struct {
	Id          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Counters    types.Bool   `tfsdk:"counters"`
	UpdateFreq  types.Object `tfsdk:"updatefreq"`
	Description types.String `tfsdk:"description"`
	Proto       types.Object `tfsdk:"proto"`
	Categories  types.Set    `tfsdk:"categories"`
	Content     types.Set    `tfsdk:"content"`
	Interface   types.String `tfsdk:"interface"`
}

type updateFreqModel struct {
	Days  types.Int32   `tfsdk:"days"`
	Hours types.Float64 `tfsdk:"hours"`
}

type protoModel struct {
	Ipv4 types.Bool `tfsdk:"ipv4"`
	Ipv6 types.Bool `tfsdk:"ipv6"`
}

// Metadata returns the resource type name.
func (r *aliasResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the resource.
func (r *aliasResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	emptySet, _ := basetypes.NewSetValue(types.StringType, []attr.Value{})

	resp.Schema = schema.Schema{
		MarkdownDescription: "Aliases are named lists of networks, hosts or ports that can be used as one entity by referencing the alias name in the various supported sections of the firewall. These aliases are particularly useful to condense firewall rules and minimize changes.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: fmt.Sprintf("Identifier of the %s.", aliasResourceName),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: fmt.Sprintf("DateTime when the %s was last updated.", aliasResourceName),
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the alias is enabled. Defaults to `true`.",
				Default:             booldefault.StaticBool(true),
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the alias.",
			},
			"type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: fmt.Sprintf(
					"The type of the alias. Must be one of: %s", strings.Join(
						// Surround each type with backticks (`)
						utils.SliceMap(getAliasTypes(), func(aliasType string) string {
							return fmt.Sprintf("`%s`", aliasType)
						}),
						", ",
					),
				),
				Validators: []validator.String{
					// Type must be one of the listed values
					stringvalidator.OneOf(getAliasTypes()...),
				},
			},
			"counters": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the statistics of the alias is enabled. Defaults to `false`.",
				Default:             booldefault.StaticBool(false),
			},
			"updatefreq": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "[Only for `urltable` type] The update frequency of the alias. Days and hours will be added together the determine the final update frequency.",
				Attributes: map[string]schema.Attribute{
					"days": schema.Int32Attribute{
						Required:    true,
						Description: "The number of days between updates.",
					},
					"hours": schema.Float64Attribute{
						Required:    true,
						Description: "The number of hours between updates.",
					},
				},
				Default: objectdefault.StaticValue(types.ObjectValueMust(
					map[string]attr.Type{
						"days":  types.Int32Type,
						"hours": types.Float64Type,
					},
					map[string]attr.Value{
						"days":  types.Int32Value(0),
						"hours": types.Float64Value(0),
					},
				)),
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The description of the alias.",
				Default:     stringdefault.StaticString(""),
			},
			"proto": schema.SingleNestedAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "[Only for `asn` & `geoip` types] The alias protocols.",
				Attributes: map[string]schema.Attribute{
					"ipv4": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Whether the alias applies to the IPv4 protocol.",
						Default:     booldefault.StaticBool(false),
					},
					"ipv6": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Whether the alias applies to the IPv6 protocol.",
						Default:     booldefault.StaticBool(false),
					},
				},
				Default: objectdefault.StaticValue(types.ObjectValueMust(
					map[string]attr.Type{
						"ipv4": types.BoolType,
						"ipv6": types.BoolType,
					},
					map[string]attr.Value{
						"ipv4": types.BoolValue(false),
						"ipv6": types.BoolValue(false),
					},
				)),
			},
			"categories": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "The categories of the alias.",
				Default:     setdefault.StaticValue(emptySet),
			},
			"content": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "The content of the alias.",
				Default:     setdefault.StaticValue(emptySet),
			},
			"interface": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "[Only for `dynipv6` type] The interface for the v6 dynamic IP.",
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *aliasResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *aliasResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Creating %s", aliasResourceName))

	// Read Terraform plan data into the model
	var plan aliasResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create alias object
	alias, diags := createAlias(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create alias on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Creating %s on OPNsense", aliasResourceName), map[string]any{"alias": alias})

	uuid, err := addAlias(r.client, alias)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Create %s error", aliasResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Create %s error", aliasResourceName), fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, fmt.Sprintf("Successfully created %s", aliasResourceName))
}

// Read resource information.
func (r *aliasResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s", aliasResourceName))

	var state aliasResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get alias
	tflog.Debug(ctx, fmt.Sprintf("Getting %s information", aliasResourceName))
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	alias, err := getAlias(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", aliasResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s information", aliasResourceName), map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Enabled = types.BoolValue(alias.Enabled)
	state.Name = types.StringValue(alias.Name)
	state.Type = types.StringValue(alias.Type)
	state.Counters = types.BoolValue(alias.Counters)

	updateFreq, diags := types.ObjectValue(
		map[string]attr.Type{
			"days":  types.Int32Type,
			"hours": types.Float64Type,
		},
		freqFloatToObject(alias.UpdateFreq),
	)
	resp.Diagnostics.Append(diags...)
	state.UpdateFreq = updateFreq

	state.Description = types.StringValue(alias.Description)

	proto, diags := types.ObjectValue(
		map[string]attr.Type{
			"ipv4": types.BoolType,
			"ipv6": types.BoolType,
		},
		map[string]attr.Value{
			"ipv4": types.BoolValue(protoContains(alias.Proto, "ipv4")),
			"ipv6": types.BoolValue(protoContains(alias.Proto, "ipv6")),
		},
	)
	resp.Diagnostics.Append(diags...)
	state.Proto = proto

	categories, diags := utils.SetGoToTerraform(ctx, alias.Categories)
	resp.Diagnostics.Append(diags...)
	state.Categories = categories

	content, diags := utils.SetGoToTerraform(ctx, alias.Content)
	resp.Diagnostics.Append(diags...)
	state.Content = content

	state.Interface = types.StringValue(alias.Interface)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully read %s", aliasResourceName))
}

// Update updates the resource on OPNsense and the Terraform state.
func (r *aliasResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Updating %s", aliasResourceName))

	// Read Terraform plan data into the model
	var plan aliasResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state aliasResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create alias object
	alias, diags := createAlias(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update alias on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Updating %s on OPNsense", aliasResourceName), map[string]any{fmt.Sprintf("%s", aliasResourceName): alias})

	err := setAlias(r.client, alias, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Update %s error", aliasResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Update %s error", aliasResourceName), fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, fmt.Sprintf("Successfully updated %s", aliasResourceName))
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *aliasResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, fmt.Sprintf("Deleting %s", aliasResourceName))

	// Read Terraform prior state data into the model
	var state aliasResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete alias on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Deleting %s on OPNsense", aliasResourceName), map[string]any{"uuid": state.Id.ValueString()})

	err := deleteAlias(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Delete %s error", aliasResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Delete %s error", aliasResourceName), fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully deleted %s", aliasResourceName))
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *aliasResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Importing %s", aliasResourceName))

	// Get alias UUID from name
	tflog.Debug(ctx, "Getting alias UUID", map[string]any{"name": req.ID})

	uuid, err := getAliasUuid(r.client, req.ID)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Import %s error", aliasResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got alias UUID", map[string]any{"success": true})

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), uuid)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully imported %s", aliasResourceName))
}
