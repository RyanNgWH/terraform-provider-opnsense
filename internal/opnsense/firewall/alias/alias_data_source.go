package alias

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall"
	"terraform-provider-opnsense/internal/utils"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &aliasDataSource{}
	_ datasource.DataSourceWithConfigure = &aliasDataSource{}
)

// NewAliasDataSource is a helper function to simplify the provider implementation.
func NewAliasDataSource() datasource.DataSource {
	return &aliasDataSource{}
}

// aliasDataSource defines the data source implementation.
type aliasDataSource struct {
	client *opnsense.Client
}

// aliasDataSourceModel describes the data source data model.
type aliasDataSourceModel struct {
	Id          types.String   `tfsdk:"id"`
	Enabled     types.Bool     `tfsdk:"enabled"`
	Name        types.String   `tfsdk:"name"`
	Type        types.String   `tfsdk:"type"`
	Counters    types.Bool     `tfsdk:"counters"`
	UpdateFreq  types.Object   `tfsdk:"updatefreq"`
	Description types.String   `tfsdk:"description"`
	Proto       types.Object   `tfsdk:"proto"`
	Categories  []types.String `tfsdk:"categories"`
	Content     []types.String `tfsdk:"content"`
	Interface   types.String   `tfsdk:"interface"`
}

// Metadata returns the data source type name.
func (d *aliasDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s_%s", req.ProviderTypeName, firewall.TypeName, controller)
}

// Schema defines the schema for the datasource.
func (d *aliasDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about a firewall alias",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Identifier of the alias",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the alias is enabled",
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The name of the alias",
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.Expressions{
						path.MatchRoot("id"),
					}...),
				},
			},
			"type": schema.StringAttribute{
				Computed:    true,
				Description: "The type of the alias",
			},
			"counters": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the statistics of the alias is enabled",
			},
			"updatefreq": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "[Only for `urltable` type] The update frequency of the alias. Days and hours are added together the determine the final update frequency",
				Attributes: map[string]schema.Attribute{
					"days": schema.Int32Attribute{
						Computed:    true,
						Description: "The number of days between updates",
					},
					"hours": schema.Float64Attribute{
						Computed:    true,
						Description: "The number of hours between updates",
					},
				},
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "The description of the alias",
			},
			"proto": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "[Only for `asn` & `geoip` types] The alias protocols",
				Attributes: map[string]schema.Attribute{
					"ipv4": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the alias applies to the IPv4 protocol",
					},
					"ipv6": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the alias applies to the IPv6 protocol",
					},
				},
			},
			"categories": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "The categories of the alias",
			},
			"content": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "The content of the alias",
			},
			"interface": schema.ListAttribute{
				Computed:    true,
				Description: "[Only for `dynipv6` type] The interface for the v6 dynamic IP.",
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *aliasDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *aliasDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Info(ctx, "Reading firewall alias")

	// Read Terraform configuration data into the model
	var data aliasDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get alias UUID
	if data.Id.IsNull() {
		tflog.Debug(ctx, "Getting alias UUID", map[string]interface{}{"name": data.Name.ValueString()})

		uuid, err := getAliasUuid(d.client, data.Name.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Read alias error", fmt.Sprintf("Failed to read alias - %s", err))
		}
		if resp.Diagnostics.HasError() {
			return
		}

		data.Id = types.StringValue(uuid)

		tflog.Debug(ctx, "Successfully got alias UUID", map[string]any{"success": true})
	}

	// Get alias
	tflog.Debug(ctx, "Getting alias information")
	tflog.SetField(ctx, "alias_name", data.Name.ValueString())

	alias, err := getAlias(d.client, data.Id.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read alias error", fmt.Sprintf("Failed to read alias - %s", err))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Successfully got alias information", map[string]any{"success": true})

	// Map response to model
	tflog.Debug(ctx, "Saving alias information to state", map[string]any{
		"enabled":     alias.Enabled,
		"name":        alias.Name,
		"type":        alias.Type,
		"counters":    alias.Counters,
		"updateFreq":  alias.UpdateFreq,
		"description": alias.Description,
		"proto":       alias.Proto,
		"categories":  alias.Categories,
		"content":     alias.Content,
		"interface":   alias.Interface,
	})

	data.Name = types.StringValue(alias.Name)
	data.Enabled = types.BoolValue(alias.Enabled)
	data.Name = types.StringValue(alias.Name)
	data.Type = types.StringValue(alias.Type)
	data.Counters = types.BoolValue(alias.Counters)

	updateFreq, diags := types.ObjectValue(
		map[string]attr.Type{
			"days":  types.Int32Type,
			"hours": types.Float64Type,
		},
		freqFloatToObject(alias.UpdateFreq),
	)
	resp.Diagnostics.Append(diags...)
	data.UpdateFreq = updateFreq

	data.Description = types.StringValue(alias.Description)

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
	data.Proto = proto

	data.Categories = utils.StringListGoToTerraform(alias.Categories)
	data.Content = utils.StringListGoToTerraform(alias.Content)
	data.Interface = types.StringValue(alias.Interface)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Saved alias information to state", map[string]any{"success": true})
	tflog.Info(ctx, "Successfully read firewall alias", map[string]any{"success": true})
}
