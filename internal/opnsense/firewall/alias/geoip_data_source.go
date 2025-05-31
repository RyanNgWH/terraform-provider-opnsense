package alias

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &geoIpDataSource{}
	_ datasource.DataSourceWithConfigure = &geoIpDataSource{}
)

// NewGeoIpDataSource is a helper function to simplify the provider implementation.
func NewGeoIpDataSource() datasource.DataSource {
	return &geoIpDataSource{}
}

// geoIpDataSource defines the data source implementation.
type geoIpDataSource struct {
	client *opnsense.Client
}

// geoIpDataSourceModel describes the data source data model.
type geoIpDataSourceModel struct {
	AddressCount      types.Int64  `tfsdk:"address_count"`
	AddressSources    types.Object `tfsdk:"address_sources"`
	FileCount         types.Int64  `tfsdk:"file_count"`
	LocationsFilename types.String `tfsdk:"locations_filename"`
	Timestamp         types.String `tfsdk:"timestamp"`
	Url               types.String `tfsdk:"url"`
	Usages            types.Int64  `tfsdk:"usages"`
}

// Metadata returns the data source type name.
func (d *geoIpDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s_geoip", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the datasource.
func (d *geoIpDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about the firewall geoip configuration.",
		Attributes: map[string]schema.Attribute{
			"address_count": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of entries in the downloaded set.",
			},
			"address_sources": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "The sources of the GeoIP addresses.",
				Attributes: map[string]schema.Attribute{
					"ipv4": schema.StringAttribute{
						Computed:    true,
						Description: "The source of the IPv4 GeoIP addresses.",
					},
					"ipv6": schema.StringAttribute{
						Computed:    true,
						Description: "The source of the IPv6 GeoIP addresses.",
					},
				},
			},
			"file_count": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of files used to store all GeoIP addresses.",
			},
			"locations_filename": schema.StringAttribute{
				Computed:    true,
				Description: "The source of the location GeoIP addresses.",
			},
			"timestamp": schema.StringAttribute{
				Computed:    true,
				Description: "The date & time the GeoIP addresses were last updated (time the vendor created the list).",
			},
			"url": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The location to fetch GeoIP address ranges from (marked as sensitive as it typically stores the MaxMind license key).",
			},
			"usages": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of aliases using the GeoIP dataset.",
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *geoIpDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

	d.client = client
}

// Read refreshes the Terraform state with the latest data.
func (d *geoIpDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, fmt.Sprintf("Reading %s configuration", geoipResourceName))

	// Read Terraform configuration data into the model
	var data geoIpDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get geoip configuration
	geoip, err := getGeoIp(d.client)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Read %s error", geoipResourceName), fmt.Sprintf("%s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Map response to model
	tflog.Debug(ctx, fmt.Sprintf("Saving %s information to state", geoipResourceName), map[string]any{"geoip": geoip})

	data.AddressCount = types.Int64Value(geoip.AddressCount)

	addressSources, diags := types.ObjectValue(
		map[string]attr.Type{
			"ipv4": types.StringType,
			"ipv6": types.StringType,
		},
		map[string]attr.Value{
			"ipv4": types.StringValue(geoip.AddressSources.Ipv4),
			"ipv6": types.StringValue(geoip.AddressSources.Ipv6),
		},
	)
	resp.Diagnostics.Append(diags...)
	data.AddressSources = addressSources

	data.FileCount = types.Int64Value(geoip.FileCount)
	data.LocationsFilename = types.StringValue(geoip.LocationsFilename)
	data.Timestamp = types.StringValue(geoip.Timestamp)
	data.Url = types.StringValue(geoip.Url)
	data.Usages = types.Int64Value(geoip.Usages)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Saved %s information to state", geoipResourceName), map[string]any{"success": true})
	tflog.Info(ctx, fmt.Sprintf("Successfully read %s configuration", geoipResourceName), map[string]any{"success": true})
}
