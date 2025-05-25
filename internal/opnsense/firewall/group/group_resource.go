package group

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &groupResource{}
	_ resource.ResourceWithConfigure   = &groupResource{}
	_ resource.ResourceWithImportState = &groupResource{}
)

// NewGroupResource is a helper function to simplify the provider implementation.
func NewGroupResource() resource.Resource {
	return &groupResource{}
}

// groupResource defines the resource implementation.
type groupResource struct {
	client *opnsense.Client
}

// groupResourceModel describes the resource data model.
type groupResourceModel struct {
	Id          types.String   `tfsdk:"id"`
	LastUpdated types.String   `tfsdk:"last_updated"`
	Name        types.String   `tfsdk:"name"`
	Members     []types.String `tfsdk:"members"`
	NoGroup     types.Bool     `tfsdk:"no_group"`
	Sequence    types.Int64    `tfsdk:"sequence"`
	Description types.String   `tfsdk:"description"`
}

// Metadata returns the resource type name.
func (r *groupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the resource.
func (r *groupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "To simplify rulesets, you can combine interfaces into Interface Groups and add policies which will be applied to all interfaces in the group.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of the group",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "DateTime when group was last updated",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the group",
			},
			"members": schema.ListAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Member interfaces of the group. Use the interface identifiers (e.g `lan`, `opt1`) Ensure that the interfaces are in lexicographical order, else the provider will detect a change on every execution.",
			},
			"no_group": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "If grouping these members in the interfaces menu section should be prevented. Defaults to `false`.",
				Default:     booldefault.StaticBool(false),
			},
			"sequence": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Priority sequence used in sorting the groups. Defaults to `0`.",
				Default:     int64default.StaticInt64(0),
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The description of the group",
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *groupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating firewall group")

	// Read Terraform plan data into the model
	var plan groupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create group object
	group, diags := createGroup(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create group on OPNsense
	tflog.Debug(ctx, "Creating group on OPNsense", map[string]any{"group": group})

	uuid, err := addGroup(r.client, group)
	if err != nil {
		resp.Diagnostics.AddError("Create group error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Create group error", fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, "Successfully created firewall group")
}

// Read resource information.
func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Read Terraform prior state data into the model
	var state groupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get group
	tflog.Debug(ctx, "Getting group information")
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	group, err := getGroup(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read group error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got group information", map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Name = types.StringValue(group.Name)
	state.Members = utils.StringListGoToTerraform(group.Members)
	state.NoGroup = types.BoolValue(group.NoGroup)
	state.Sequence = types.Int64Value(group.Sequence)
	state.Description = types.StringValue(group.Description)

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
func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating firewall group")

	// Read Terraform plan data into the model
	var plan groupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state groupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create group object
	group, diags := createGroup(ctx, r.client, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update group on OPNsense
	tflog.Debug(ctx, "Updating group on OPNsense", map[string]any{"group": group})

	err := setGroup(r.client, group, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Update group error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Update group error", fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, "Successfully updated firewall group")
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Deleting firewall group")

	// Read Terraform prior state data into the model
	var state groupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete group on OPNsense
	tflog.Debug(ctx, "Deleting group on OPNsense", map[string]any{"uuid": state.Id.ValueString()})

	err := deleteGroup(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete group error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning("Delete group error", fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	if resp.Diagnostics.HasError() {
		return
	}
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *groupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, "Importing firewall group")

	// Get group UUID from name
	tflog.Debug(ctx, "Getting group UUID", map[string]any{"name": req.ID})

	uuid, err := searchGroup(r.client, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import group error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got group UUID", map[string]any{"success": true})

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), uuid)...)
	if resp.Diagnostics.HasError() {
		return
	}
}
