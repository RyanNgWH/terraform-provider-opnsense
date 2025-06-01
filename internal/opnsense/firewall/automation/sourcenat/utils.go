package sourcenat

import (
	"context"
	"fmt"
	"strings"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/category"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	sourceNatController = "source_nat"

	resourceName = "automation source nat rule"
)

type automationSourceNat struct {
	Enabled         bool
	NoNat           bool
	Sequence        int32
	Interface       string
	IpVersion       string
	Protocol        string
	Source          string
	SourceNot       bool
	SourcePort      string
	Destination     string
	DestinationNot  bool
	DestinationPort string
	Target          string
	TargetPort      string
	Log             bool
	Categories      *utils.Set
	Description     string
}

// Source nat values

func getIpVersions() []string {
	return ipVersions.GetAllKeys()
}

func getProtocols() []string {
	return []string{
		"any",
		"icmp",
		"igmp",
		"ggp",
		"ipencap",
		"st2",
		"tcp",
		"cbt",
		"egp",
		"igp",
		"bbn-rcc",
		"nvp",
		"pup",
		"argus",
		"emcon",
		"xnet",
		"chaos",
		"udp",
		"mux",
		"dcn",
		"hmp",
		"prm",
		"xns-idp",
		"trunk-1",
		"trunk-2",
		"leaf-1",
		"leaf-2",
		"rdp",
		"irtp",
		"iso-tp4",
		"netblt",
		"mfe-nsp",
		"merit-inp",
		"dccp",
		"3pc",
		"idpr",
		"xtp",
		"ddp",
		"idpr-cmtp",
		"tp++",
		"il",
		"ipv6",
		"sdrp",
		"idrp",
		"rsvp",
		"gre",
		"dsr",
		"bna",
		"esp",
		"ah",
		"i-nlsp",
		"swipe",
		"narp",
		"mobile",
		"tlsp",
		"skip",
		"ipv6-icmp",
		"cftp",
		"sat-expak",
		"kryptolan",
		"rvd",
		"ippc",
		"sat-mon",
		"visa",
		"ipcv",
		"cpnx",
		"cphb",
		"wsn",
		"pvp",
		"br-sat-mon",
		"sun-nd",
		"wb-mon",
		"wb-expak",
		"iso-ip",
		"vmtp",
		"secure-vmtp",
		"vines",
		"ttp",
		"nsfnet-igp",
		"dgp",
		"tcf",
		"eigrp",
		"ospf",
		"sprite-rpc",
		"larp",
		"mtp",
		"ax.25",
		"ipip",
		"micp",
		"scc-sp",
		"etherip",
		"encap",
		"gmtp",
		"ifmp",
		"pnni",
		"pim",
		"aris",
		"scps",
		"qnx",
		"a/n",
		"ipcomp",
		"snp",
		"compaq-peer",
		"ipx-in-ip",
		"carp",
		"pgm",
		"l2tp",
		"ddx",
		"iatp",
		"stp",
		"srp",
		"uti",
		"smp",
		"sm",
		"ptp",
		"isis",
		"crtp",
		"crudp",
		"sps",
		"pipe",
		"sctp",
		"fc",
		"rsvp-e2e-ignore",
		"udplite",
		"mpls-in-ip",
		"manet",
		"hip",
		"shim6",
		"wesp",
		"rohc",
		"pfsync",
		"divert",
	}
}

// Ip version mappings
const (
	ipv4 string = "ipv4"
	ipv6 string = "ipv6"
)

var ipVersionMappings = map[string]string{
	ipv4: "inet",
	ipv6: "inet6",
}

var ipVersions = getBidirectionalIpVersion()

func getBidirectionalIpVersion() *utils.BidirectionalMap {
	ipVersions := utils.NewBidirectionalMap()
	for key, value := range ipVersionMappings {
		ipVersions.Put(key, value)
	}
	return ipVersions
}

// Helper functions

// createAutomationSourceNat creates an automation source nat object based on the specified plan.
func createAutomationSourceNat(ctx context.Context, client *opnsense.Client, plan automationSourceNatResourceModel) (automationSourceNat, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Create automation source nat rule from plan
	tflog.Debug(ctx, fmt.Sprintf("Creating %s object from plan", resourceName), map[string]any{"plan": plan})

	// Verify interfaces
	tflog.Debug(ctx, "Verifying interface", map[string]any{"interface": plan.Interface})

	interfaceExist, err := overview.VerifyInterface(client, plan.Interface.ValueString())
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}
	if !interfaceExist {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), "The specified interface does not exist. Please verify that the specified interfaces exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interface", map[string]any{"success": true})

	// Verify all categories exist
	tflog.Debug(ctx, "Verifying categories", map[string]any{"categories": plan.Categories})

	categories, diags := utils.SetTerraformToGo(ctx, plan.Categories)
	diagnostics.Append(diags...)

	categoryUuids, err := category.GetCategoryUuids(client, categories)
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}

	tflog.Debug(ctx, "Successfully verified categories", map[string]any{"success": true})

	// IpVersion
	ipVersion, exists := ipVersions.GetByKey(plan.IpVersion.ValueString())
	if !exists {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("Ip version `%s` not supported. Please contact the provider maintainers if you believe this should be supported.", plan.IpVersion.ValueString()))
	}

	// Protocol
	protocol := plan.Protocol.ValueString()
	if protocol != "any" {
		protocol = strings.ToUpper(protocol)
	}

	automationSourceNat := automationSourceNat{
		Enabled:         plan.Enabled.ValueBool(),
		NoNat:           plan.NoNat.ValueBool(),
		Sequence:        plan.Sequence.ValueInt32(),
		Interface:       plan.Interface.ValueString(),
		IpVersion:       ipVersion,
		Protocol:        protocol,
		Source:          plan.Source.ValueString(),
		SourceNot:       plan.SourceNot.ValueBool(),
		SourcePort:      plan.SourcePort.ValueString(),
		Destination:     plan.Destination.ValueString(),
		DestinationNot:  plan.DestinationNot.ValueBool(),
		DestinationPort: plan.DestinationPort.ValueString(),
		Target:          plan.Target.ValueString(),
		TargetPort:      plan.TargetPort.ValueString(),
		Log:             plan.Log.ValueBool(),
		Categories:      categoryUuids,
		Description:     plan.Description.ValueString(),
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return automationSourceNat, diagnostics
}
