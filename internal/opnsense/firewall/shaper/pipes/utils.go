package pipes

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	pipesController string = "pipes"
)

type shaperPipe struct {
	Enabled   bool
	Bandwidth struct {
		Value  int64
		Metric string
	}
	Queue     int32
	Mask      string
	Buckets   int32
	Scheduler string
	Codel     struct {
		Enabled  bool
		Target   int32
		Interval int32
		Ecn      bool
		Quantum  int32
		Limit    int32
		Flows    int32
	}
	Pie         bool
	Delay       int32
	Description string
}

// Scheduler mappings
const (
	weightedFairQueueing string = "weighted fair queuing"
	fifo                 string = "fifo"
	deficitRoundRobin    string = "deficit round robin"
	qfq                  string = "qfq"
	codel                string = "flowqueue-codel"
	pie                  string = "flowqueue-pie"
)

var schedulers = map[string]string{
	weightedFairQueueing: "",
	fifo:                 "fifo",
	deficitRoundRobin:    "rr",
	qfq:                  "qfq",
	codel:                "fq_codel",
	pie:                  "fq_pie",
}

// Pipes values

func getMetricValues() []string {
	return []string{
		"bit",
		"Kbit",
		"Mbit",
		"Gbit",
	}
}

func getMaskTypes() []string {
	return []string{
		"none",
		"src-ip",
		"dst-ip",
	}
}

func getSchedulers() []string {
	return []string{
		weightedFairQueueing,
		fifo,
		deficitRoundRobin,
		qfq,
		codel,
		pie,
	}
}

// Helper functions

// createShaperPipe creates a traffic shaper pip based on the specified plan.
func createShaperPipe(ctx context.Context, plan shaperPipesResourceModel) (shaperPipe, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Create traffic shaper pipe from plan
	tflog.Debug(ctx, "Creating traffic shaper pipe object from plan", map[string]any{"plan": plan})

	// Bandwidth
	var planBandwidth bandwidthModel
	diags := plan.Bandwidth.As(ctx, &planBandwidth, basetypes.ObjectAsOptions{})
	diagnostics.Append(diags...)

	bandwidth := struct {
		Value  int64
		Metric string
	}{
		Value:  planBandwidth.Value.ValueInt64(),
		Metric: planBandwidth.Metric.ValueString(),
	}

	// Codel
	var planCodel codelModel
	diags = plan.Codel.As(ctx, &planCodel, basetypes.ObjectAsOptions{})
	diagnostics.Append(diags...)

	codel := struct {
		Enabled  bool
		Target   int32
		Interval int32
		Ecn      bool
		Quantum  int32
		Limit    int32
		Flows    int32
	}{
		Enabled:  planCodel.Enabled.ValueBool(),
		Target:   planCodel.Target.ValueInt32(),
		Interval: planCodel.Interval.ValueInt32(),
		Ecn:      planCodel.Ecn.ValueBool(),
		Quantum:  planCodel.Quantum.ValueInt32(),
		Limit:    planCodel.Limit.ValueInt32(),
		Flows:    planCodel.Flows.ValueInt32(),
	}

	shaperPipe := shaperPipe{
		Enabled:     plan.Enabled.ValueBool(),
		Bandwidth:   bandwidth,
		Queue:       plan.Queue.ValueInt32(),
		Mask:        plan.Mask.ValueString(),
		Buckets:     plan.Buckets.ValueInt32(),
		Scheduler:   schedulers[plan.Scheduler.ValueString()],
		Codel:       codel,
		Pie:         plan.Pie.ValueBool(),
		Delay:       plan.Delay.ValueInt32(),
		Description: plan.Description.ValueString(),
	}

	tflog.Debug(ctx, "Successfully created traffic shaper pipe object from plan", map[string]any{"success": true})

	return shaperPipe, diagnostics
}
