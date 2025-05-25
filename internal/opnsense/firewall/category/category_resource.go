package category

import (
	"context"
	"fmt"
	"reflect"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &categoryResource{}
	_ resource.ResourceWithConfigure   = &categoryResource{}
	_ resource.ResourceWithImportState = &categoryResource{}
)

// NewCategoryResource is a helper function to simplify the provider implementation.
func NewCategoryResource() resource.Resource {
	return &categoryResource{}
}

// categoryResource defines the resource implementation.
type categoryResource struct {
	client *opnsense.Client
}

// categoryResourceModel describes the resource data model.
type categoryResourceModel struct {
	Id          types.String `tfsdk:"id"`
	LastUpdated types.String `tfsdk:"last_updated"`
	Name        types.String `tfsdk:"name"`
	Auto        types.Bool   `tfsdk:"auto"`
	Color       types.String `tfsdk:"color"`
}

// Metadata returns the resource type name.
func (r *categoryResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the resource.
func (r *categoryResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "To ease maintenance of larger rulesets, OPNsense includes categories for the firewall. Each rule can contain one or more categories, which can be filtered on top of each firewall rule page.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of the category",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "DateTime when alias was last updated",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the category",
			},
			"auto": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the category is automatically added (i.e will be removed when unused)",
				Default:     booldefault.StaticBool(false),
			},
			"color": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The hex color code to be used for the category tag",
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (r *categoryResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *categoryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating category alias")

	// Read Terraform plan data into the model
	var plan categoryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create alias object
	category := createCategory(ctx, plan)

	// Create alias on OPNsense
	tflog.Debug(ctx, "Creating category on OPNsense", map[string]any{"category": category})

	uuid, err := addCategory(r.client, category)
	if err != nil {
		resp.Diagnostics.AddError("Create category error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Update plan ID & last_updated fields
	plan.Id = types.StringValue(uuid)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC3339))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Successfully created firewall category")
}

// Read resource information.
func (r *categoryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Read Terraform prior state data into the model
	var state categoryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get category
	tflog.Debug(ctx, "Getting category information")
	tflog.SetField(ctx, "uuid", state.Id.ValueString())

	category, err := GetCategory(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read category error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got category information", map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Name = types.StringValue(category.Name)
	state.Auto = types.BoolValue(category.Auto)
	state.Color = types.StringValue(category.Color)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource on OPNsense and the Terraform state.
func (r *categoryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating firewall category")

	// Read Terraform plan data into the model
	var plan categoryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state categoryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create category object
	category := createCategory(ctx, plan)

	// Update alias on OPNsense
	tflog.Debug(ctx, "Updating category on OPNsense", map[string]any{"category": category})

	err := setCategory(r.client, category, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Update alias error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
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

	tflog.Info(ctx, "Successfully updated firewall category")
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *categoryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Deleting firewall alias")

	// Read Terraform prior state data into the model
	var state categoryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete alias on OPNsense
	tflog.Debug(ctx, "Deleting category on OPNsense", map[string]any{"uuid": state.Id.ValueString()})

	err := deleteCategory(r.client, state.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Delete alias error", fmt.Sprintf("%s", err))
	}
	tflog.Info(ctx, "Successfully deleted firewall alias")
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *categoryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, "Importing firewall category")

	// Get category UUID from name
	tflog.Debug(ctx, "Getting category UUID", map[string]any{"name": req.ID})

	uuid, err := SearchCategory(r.client, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import category error", fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got category UUID", map[string]any{"success": true})

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), uuid)...)
	if resp.Diagnostics.HasError() {
		return
	}
}
