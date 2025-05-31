package alias

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &geoIpResource{}
	_ resource.ResourceWithConfigure   = &geoIpResource{}
	_ resource.ResourceWithImportState = &geoIpResource{}
)

// NewGeoIpResource is a helper function to simplify the provider implementation.
func NewGeoIpResource() resource.Resource {
	return &geoIpResource{}
}

// geoIpResource defines the resource implementation.
type geoIpResource struct {
	client *opnsense.Client
}

// geoIpResourceModel describes the resource data model.
type geoIpResourceModel struct {
	Url         types.String `tfsdk:"url"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

// Metadata returns the resource type name.
func (r *geoIpResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_geoip", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the resource.
func (r *geoIpResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "With GeoIP aliases you can select one or more countries or whole continents to block or allow. This resource allows you to configure the source for fetching GeoIP addresses.",

		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Required:    true,
				Description: " Location to fetch geoip address ranges from.",
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "DateTime when this resource was last updated.",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *geoIpResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*opnsense.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Type",
			fmt.Sprintf("Expected *opnsense.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *geoIpResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Creating %s configuration", geoipResourceName))

	// Read Terraform plan data into the model
	var plan geoIpResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set geoip config on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Setting %s configuration on OPNsense", geoipResourceName), map[string]any{"url": plan.Url.ValueString()})

	err := setGeoIp(r.client, plan.Url.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Set %s error", geoipResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Set %s error", geoipResourceName), fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	// Update plan last_updated field
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC3339))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully created %s configuration", geoipResourceName))
}

// Read resource information.
func (r *geoIpResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s configuration", geoipResourceName))

	// Read Terraform prior state data into the model
	var state geoIpResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get geoip configuration
	tflog.Debug(ctx, fmt.Sprintf("Getting %s configuration", geoipResourceName))

	geoip, err := getGeoIp(r.client)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", geoipResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully got %s configuration", geoipResourceName), map[string]any{"success": true})

	// Overwite items with refreshed state
	state.Url = types.StringValue(geoip.Url)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully read %s configuration", geoipResourceName))
}

// Update updates the resource on OPNsense and the Terraform state.
func (r *geoIpResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Updating %s configuration", geoipResourceName))

	// Read Terraform plan data into the model
	var plan geoIpResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current Terraform state data into the model
	var state geoIpResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update geoip on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Updating %s configuration on OPNsense", geoipResourceName), map[string]any{"url": plan.Url.ValueString()})

	err := setGeoIp(r.client, plan.Url.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Update %s error", geoipResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Update %s error", geoipResourceName), fmt.Sprintf("%s", err))
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

	tflog.Info(ctx, fmt.Sprintf("Successfully updated %s configuration", geoipResourceName))
}

// Delete removes the resource on OPNsense and from the Terraform state.
func (r *geoIpResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, fmt.Sprintf("Deleting %s configuration", geoipResourceName))

	// Read Terraform prior state data into the model
	var state geoIpResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Remove geoip configuration on OPNsense
	tflog.Debug(ctx, fmt.Sprintf("Removing %s configuration on OPNsense", geoipResourceName))

	err := setGeoIp(r.client, "")
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Delete %s error", geoipResourceName), fmt.Sprintf("%s", err))
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Apply configuration on OPNsense
	tflog.Debug(ctx, "Applying configuration on OPNsense")

	err = applyConfig(r.client)
	if err != nil {
		resp.Diagnostics.AddWarning(fmt.Sprintf("Delete %s error", geoipResourceName), fmt.Sprintf("%s", err))
	} else {
		tflog.Debug(ctx, "Successfully applied configuration on OPNsense", map[string]any{"success": true})
	}

	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully deleted %s configuration", geoipResourceName))
}

// ImportState imports the resource from OPNsense and enables Terraform to begin managing the resource.
func (r *geoIpResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	tflog.Info(ctx, fmt.Sprintf("Importing %s configuration", geoipResourceName))

	// Nothing special needs to be done since the geoip read function does not require any attributes.
	// Setting url to an empty string to prevent terraform from throwing a missing resource import state
	// error.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("url"), "")...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully imported %s configuration", geoipResourceName))
}
