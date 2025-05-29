package queues

import (
	"context"
	"fmt"
	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/opnsense/firewall/shaper/pipes"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	queuesController string = "queues"
)

type shaperQueue struct {
	Enabled bool
	Weight  int32
	Pipe    string
	Mask    string
	Buckets int32
	Codel   struct {
		Enabled  bool
		Target   int32
		Interval int32
		Ecn      bool
	}
	Pie         bool
	Description string
}

// Queues values

func getMaskTypes() []string {
	return []string{
		"none",
		"src-ip",
		"dst-ip",
	}
}

// Helper functions

// createShaperQueue creates a traffic shaper queue based on the specified plan.
func createShaperQueue(ctx context.Context, client *opnsense.Client, plan shaperQueuesResourceModel) (shaperQueue, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Verify pipe exists
	tflog.Debug(ctx, "Verifying pipe", map[string]any{"pipe": plan.Pipe})

	pipeExists, err := pipes.VerifyShaperPipe(client, plan.Pipe.ValueString())
	if err != nil {
		diagnostics.AddError("Create traffic shaper queue error", fmt.Sprintf("%s", err))
	}
	if !pipeExists {
		diagnostics.AddError("Create traffic shaper queue error", fmt.Sprintf("Pipe with uuid %s does not exist. Please verify that the specified pipe exists on your OPNsense firewall", plan.Pipe.ValueString()))
	}

	tflog.Debug(ctx, "Successfully verified pipe", map[string]any{"success": true})

	// Create traffic shaper queue from plan
	tflog.Debug(ctx, "Creating traffic shaper queue object from plan", map[string]any{"plan": plan})

	// Codel
	var planCodel codelModel
	diags := plan.Codel.As(ctx, &planCodel, basetypes.ObjectAsOptions{})
	diagnostics.Append(diags...)

	codel := struct {
		Enabled  bool
		Target   int32
		Interval int32
		Ecn      bool
	}{
		Enabled:  planCodel.Enabled.ValueBool(),
		Target:   planCodel.Target.ValueInt32(),
		Interval: planCodel.Interval.ValueInt32(),
		Ecn:      planCodel.Ecn.ValueBool(),
	}

	shaperQueue := shaperQueue{
		Enabled:     plan.Enabled.ValueBool(),
		Pipe:        plan.Pipe.ValueString(),
		Weight:      plan.Weight.ValueInt32(),
		Mask:        plan.Mask.ValueString(),
		Buckets:     plan.Buckets.ValueInt32(),
		Codel:       codel,
		Pie:         plan.Pie.ValueBool(),
		Description: plan.Description.ValueString(),
	}

	tflog.Debug(ctx, "Successfully created traffic shaper queue object from plan", map[string]any{"success": true})

	return shaperQueue, diagnostics
}

// VerifyShaperQueue checks if the specified traffic shaper queue exist on the OPNsense firewall.
func VerifyShaperQueue(client *opnsense.Client, queue string) (bool, error) {
	queueExists, err := checkShaperQueueExists(client, queue)
	if err != nil {
		return false, fmt.Errorf("Verify traffic shaper queue exists error: %s", err)
	}

	if !queueExists {
		return false, nil
	}

	return true, nil
}
