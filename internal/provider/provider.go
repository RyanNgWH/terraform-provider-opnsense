package provider

import (
	"context"
	"os"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/alias"
	"terraform-provider-opnsense/internal/opnsense/firewall/automation/filter"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/opnsense/firewall/group"
	"terraform-provider-opnsense/internal/opnsense/firewall/nat/nptv6"
	"terraform-provider-opnsense/internal/opnsense/firewall/nat/onetoone"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper/pipes"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper/queues"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper/rules"
)

// Ensure OpnsenseProvider satisfies various provider interfaces.
var _ provider.Provider = &opnsenseProvider{}

// OpnsenseProvider defines the provider implementation.
type opnsenseProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// OpnsenseProviderModel describes the provider data model.
type opnsenseProviderModel struct {
	Endpoint  types.String `tfsdk:"endpoint"`
	ApiKey    types.String `tfsdk:"api_key"`
	ApiSecret types.String `tfsdk:"api_secret"`
	Timeout   types.Int32  `tfsdk:"timeout"`
	Insecure  types.Bool   `tfsdk:"insecure"`
}

// Metadata returns the provider type name.
func (p *opnsenseProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "opnsense"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *opnsenseProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The endpoint for the OPNsense API. This is typically `https://<your-opnsense-instance>`. Do not include the `/api` suffix. May also be provided via the `OPNSENSE_ENDPOINT` environment variable.",
			},
			"api_key": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The API key for the OPNsense API. May also be provided via the `OPNSENSE_API_KEY` environment variable.",
			},
			"api_secret": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The API secret for the OPNsense API. May also be provided via the `OPNSENSE_API_SECRET` environment variable.",
				Sensitive:           true,
			},
			"timeout": schema.Int32Attribute{
				Optional:            true,
				MarkdownDescription: "The duration before the request to the OPNsense API times out (in seconds). Defaults to `120`.",
			},
			"insecure": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether TLS verification of the OPNsense API should be skipped. Defaults to `false`. May also be provided via the `OPNSENSE_API_INSECURE` environment variable.",
			},
		},
	}
}

// Configure prepares an OPNsense API client for data sources and resources.
func (p *opnsenseProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Info(ctx, "Configuring OPNsense client")

	// Retrieve provider data from configuration
	var config opnsenseProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.
	if config.Endpoint.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoint"),
			"Unknown OPNsense API endpoint",
			"The provider cannot create the OPNsense API client as there is an unknown configuration value for the OPNsense API endpoint. "+"Either set the value statically in the configuration or use the OPNSENSE_ENDPOINT environment variable.",
		)
	}

	if config.ApiKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("apikey"),
			"Unknown OPNsense API key",
			"The provider cannot create the OPNsense API client as there is an unknown configuration value for the OPNsense API key. "+"Either set the value statically in the configuration or use the OPNSENSE_API_KEY environment variable.",
		)
	}

	if config.ApiSecret.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("apisecret"),
			"Unknown OPNsense API secret",
			"The provider cannot create the OPNsense API client as there is an unknown configuration value for the OPNsense API secret. "+"Either set the value statically in the configuration or use the OPNSENSE_API_SECRET environment variable.",
		)
	}

	if config.Timeout.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("timeout"),
			"Unknown OPNsense API timeout",
			"The provider cannot create the OPNsense API client as there is an unknown configuration value for the OPNsense API timeout. "+"Set the value statically in the configuration, otherwise, a default value will be used.",
		)
	}

	if config.Insecure.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("insecure"),
			"Unknown OPNsense API insecure value",
			"The provider cannot create the OPNsense API client as there is an unknown configuration value for the OPNsense API insecure attribute. "+"Set the value statically in the configuration or use the OPNSENSE_API_INSECURE, otherwise, a default value will be used.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables or predefined defaults, but override
	// with Terraform configuration value if set.
	endpoint := os.Getenv("OPNSENSE_ENDPOINT")
	apiKey := os.Getenv("OPNSENSE_API_KEY")
	apiSecret := os.Getenv("OPNSENSE_API_SECRET")
	insecureEnv := os.Getenv("OPNSENSE_API_INSECURE")

	var timeout int32 = 120
	var insecure bool = false
	if insecureEnv != "" {
		val, err := strconv.ParseBool(insecureEnv)
		if err != nil {
			resp.Diagnostics.AddAttributeWarning(
				path.Root("insecure"),
				"Invalid OPNsense API insecure value",
				"An invalid value has been set for the OPNSENSE_API_INSECURE environment variable. This value will be ignored. The OPNSENSE_API_INSECURE environment variable should only be a valid boolean value.",
			)
		}
		insecure = val
	}

	if !config.Endpoint.IsNull() {
		endpoint = config.Endpoint.ValueString()
	}
	if !config.ApiKey.IsNull() {
		apiKey = config.ApiKey.ValueString()
	}
	if !config.ApiSecret.IsNull() {
		apiSecret = config.ApiSecret.ValueString()
	}
	if !config.Timeout.IsNull() {
		timeout = config.Timeout.ValueInt32()
	}
	if !config.Insecure.IsNull() {
		insecure = config.Insecure.ValueBool()
	}

	// If any of the expected configurations are missing or invalid, return
	// errors with provider-specific guidance.
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoint"),
			"Missing OPNsense API endpoint",
			"The provider cannot create the OPNsense API client as there is a missing or empty value for the OPNsense API endpoint. "+"Set the endpoint value in the configuration or use the OPNSENSE_ENDPOINT environment variable. "+"If either is already set, ensure the value is not empty.",
		)
	}

	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("apikey"),
			"Missing OPNsense API key",
			"The provider cannot create the OPNsense API client as there is a missing or empty value for the OPNsense API key. "+"Set the endpoint value in the configuration or use the OPNSENSE_API_KEY environment variable. "+"If either is already set, ensure the value is not empty.",
		)
	}

	if apiSecret == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("apisecret"),
			"Missing OPNsense API secret",
			"The provider cannot create the OPNsense API client as there is a missing or empty value for the OPNsense API secret. "+"Set the endpoint value in the configuration or use the OPNSENSE_API_SECRET environment variable. "+"If either is already set, ensure the value is not empty.",
		)
	}

	if timeout < 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("timeout"),
			"Invalid OPNsense API timeout",
			"The provider cannot create the OPNsense API client as there is an invalid value for the OPNsense API timeout. "+"Ensure the value is 0 or greater.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "opnsense_endpoint", endpoint)
	ctx = tflog.SetField(ctx, "opnsense_api_key", apiKey)
	ctx = tflog.SetField(ctx, "opnsense_api_secret", apiSecret)
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "opnsense_api_secret")
	ctx = tflog.SetField(ctx, "opnsense_timeout", timeout)
	ctx = tflog.SetField(ctx, "opnsense_insecure", insecure)

	tflog.Debug(ctx, "Creating OPNsense client")

	// Create a new OPNsense client using the configuration values
	clientOpts := opnsense.ClientOpts{
		Endpoint:  endpoint,
		ApiKey:    apiKey,
		ApiSecret: apiSecret,
		Timeout:   timeout,
		Insecure:  insecure,
	}
	client, err := opnsense.NewClient(clientOpts)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to create the OPNsense API Client",
			"An unexpected error occurred when creating the OPNsense API client. "+"If the error is not clear, please contact the provider developers.\n\n"+"OPNsense Client Error: "+err.Error(),
		)
		return
	}

	// Make the OPNsense client available during DataSource and Resource
	// type Configure methods.
	resp.DataSourceData = client
	resp.ResourceData = client

	tflog.Info(ctx, "Configured OPNsense client", map[string]any{"success": true})
}

// Resources defines the resources implemented in the provider.
func (p *opnsenseProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		alias.NewAliasResource,
		alias.NewGeoIpResource,
		category.NewCategoryResource,
		filter.NewAutomationFilterResource,
		group.NewGroupResource,
		nptv6.NewNatNptv6Resource,
		onetoone.NewNatOneToOneResource,
		pipes.NewShaperPipesResource,
		queues.NewShaperQueuesResource,
		rules.NewShaperRulesResource,
	}
}

// DataSources defines the data sources implemented in the provider.
func (p *opnsenseProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		alias.NewAliasDataSource,
		alias.NewGeoIpDataSource,
		category.NewCategoryDataSource,
		filter.NewAutomationFilterDataSource,
		group.NewGroupDataSource,
		nptv6.NewOneToOneNatDataSource,
		onetoone.NewOneToOneNatDataSource,
		pipes.NewShaperPipesDataSource,
		queues.NewShaperQueuesDataSource,
		rules.NewShaperRulesDataSource,
	}
}

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &opnsenseProvider{
			version: version,
		}
	}
}
