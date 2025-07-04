package rules

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper/pipes"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper/queues"
	"terraform-provider-opnsense/internal/opnsense/interfaces/overview"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	rulesController string = "rules"

	resourceName string = "traffic shaper rule"
)

type shaperRule struct {
	Enabled         bool
	Sequence        int32
	Interface       string
	Interface2      string
	Protocol        string
	MaxPacketLength int32
	Sources         *utils.Set
	SourceNot       bool
	SourcePort      string
	Destinations    *utils.Set
	DestinationNot  bool
	DestinationPort string
	Dscp            *utils.Set
	Direction       string
	Target          string
	Description     string
}

// Mappings
const (
	bestEffort          string = "best effort"
	expeditedForwarding string = "expedited forwarding"
	af11                string = "af11"
	af12                string = "af12"
	af13                string = "af13"
	af21                string = "af21"
	af22                string = "af22"
	af23                string = "af23"
	af31                string = "af31"
	af32                string = "af32"
	af33                string = "af33"
	af41                string = "af41"
	af42                string = "af42"
	cs1                 string = "cs1"
	cs2                 string = "cs2"
	cs3                 string = "cs3"
	cs4                 string = "cs4"
	cs5                 string = "cs5"
	cs6                 string = "cs6"
	cs7                 string = "cs7"
)

var dscpMappings = map[string]string{
	bestEffort:          "be",
	expeditedForwarding: "ef",
	af11:                "af11",
	af12:                "af12",
	af13:                "af13",
	af21:                "af21",
	af22:                "af22",
	af23:                "af23",
	af31:                "af31",
	af32:                "af32",
	af33:                "af33",
	af41:                "af41",
	af42:                "af42",
	cs1:                 "cs1",
	cs2:                 "cs2",
	cs3:                 "cs3",
	cs4:                 "cs4",
	cs5:                 "cs5",
	cs6:                 "cs6",
	cs7:                 "cs7",
}

var dscp = getBidirectionalDscp()

func getBidirectionalDscp() *utils.BidirectionalMap {
	dscp := utils.NewBidirectionalMap()
	for key, value := range dscpMappings {
		dscp.Put(key, value)
	}
	return dscp
}

const (
	both string = "both"
	in   string = "in"
	out  string = "out"
)

var directionMappings = map[string]string{
	both: "",
	in:   "in",
	out:  "out",
}

var directions = getBidirectionalDirection()

func getBidirectionalDirection() *utils.BidirectionalMap {
	directions := utils.NewBidirectionalMap()
	for key, value := range directionMappings {
		directions.Put(key, value)
	}
	return directions
}

// Rules values

func getProtocols() []string {
	return []string{
		"ip",
		"ipv4",
		"ipv6",
		"udp",
		"tcp",
		"tcp_ack",
		"tcp_ack_not",
		"icmp",
		"ipv6-icmp",
		"igmp",
		"esp",
		"ah",
		"gre",
	}
}

func getDirection() []string {
	return directions.GetAllKeys()
}

func getDscp() []string {
	return dscp.GetAllKeys()
}

// Helper functions

// createShaperRule creates a traffic shaper rule based on the specified plan.
func createShaperRule(ctx context.Context, client *opnsense.Client, plan shaperRulesResourceModel) (shaperRule, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify interfaces
	tflog.Debug(ctx, "Verifying interfaces", map[string]any{"interfaces": []string{plan.Interface.ValueString(), plan.Interface2.ValueString()}})

	interfaces := utils.NewSet()
	interfaces.Add(plan.Interface.ValueString())
	if plan.Interface2.ValueString() != "" {
		interfaces.Add(plan.Interface2.ValueString())
	}

	interfacesExist, err := overview.VerifyInterfaces(client, interfaces)
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}
	if !interfacesExist {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), "One or more interfaces not exist. Please verify that all specified interfaces exist on your OPNsense firewall")
	}

	tflog.Debug(ctx, "Successfully verified interfaces", map[string]any{"success": true})

	// Verify target exists
	tflog.Debug(ctx, "Verifying target", map[string]any{"target": plan.Target})

	pipeExists, err := pipes.VerifyShaperPipe(client, plan.Target.ValueString())
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}

	queueExists, err := queues.VerifyShaperQueue(client, plan.Target.ValueString())
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("%s", err))
	}

	if !pipeExists && !queueExists {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("Target pipe or queue with uuid %s does not exist. Please verify that the specified pipe or queue exists on your OPNsense firewall", plan.Target.ValueString()))
	}

	tflog.Debug(ctx, "Successfully verified target", map[string]any{"success": true})

	// Direction
	direction, exists := directions.GetByKey(plan.Direction.ValueString())
	if !exists {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("Direction `%s` not supported. Please contact the provider maintainers if you believe this should be supported.", plan.Direction.ValueString()))
	}

	// Dscp
	dscpValues := utils.NewSet()
	dscpSet, diags := utils.SetTerraformToGo(ctx, plan.Dscp)
	diagnostics.Append(diags...)

	for _, value := range dscpSet.Elements() {
		dscp, exists := dscp.GetByKey(value)
		if !exists {
			diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("Dscp value `%s` not supported. Please contact the provider maintainers if you believe this should be supported.", value))
		}
		dscpValues.Add(dscp)
	}

	// Create traffic shaper rule from plan
	tflog.Debug(ctx, fmt.Sprintf("Creating %s object from plan", resourceName), map[string]any{"plan": plan})

	sources, diags := utils.SetTerraformToGo(ctx, plan.Sources)
	diagnostics.Append(diags...)

	destinations, diags := utils.SetTerraformToGo(ctx, plan.Destinations)
	diagnostics.Append(diags...)

	shaperRule := shaperRule{
		Enabled:         plan.Enabled.ValueBool(),
		Sequence:        plan.Sequence.ValueInt32(),
		Interface:       plan.Interface.ValueString(),
		Interface2:      plan.Interface2.ValueString(),
		Protocol:        plan.Protocol.ValueString(),
		MaxPacketLength: plan.MaxPacketLength.ValueInt32(),
		Sources:         sources,
		SourceNot:       plan.SourceNot.ValueBool(),
		SourcePort:      plan.SourcePort.ValueString(),
		Destinations:    destinations,
		DestinationNot:  plan.DestinationNot.ValueBool(),
		DestinationPort: plan.DestinationPort.ValueString(),
		Dscp:            dscpValues,
		Target:          plan.Target.ValueString(),
		Direction:       direction,
		Description:     plan.Description.ValueString(),
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return shaperRule, diagnostics
}
