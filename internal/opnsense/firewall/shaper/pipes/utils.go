package pipes

import (
	"context"
	"fmt"

	"terraform-provider-opnsense/internal/opnsense"
	"terraform-provider-opnsense/internal/utils"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	pipesController string = "pipes"

	resourceName string = "traffic shaper pipe"
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
	weightedFairQueueing string = "weighted fair queueing"
	fifo                 string = "fifo"
	deficitRoundRobin    string = "deficit round robin"
	qfq                  string = "qfq"
	codel                string = "flowqueue-codel"
	pie                  string = "flowqueue-pie"
)

var schedulerMappings = map[string]string{
	weightedFairQueueing: "",
	fifo:                 "fifo",
	deficitRoundRobin:    "rr",
	qfq:                  "qfq",
	codel:                "fq_codel",
	pie:                  "fq_pie",
}

var schedulers = getBidirectionalScheduler()

func getBidirectionalScheduler() *utils.BidirectionalMap {
	schedulers := utils.NewBidirectionalMap()
	for key, value := range schedulerMappings {
		schedulers.Put(key, value)
	}
	return schedulers
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
	return schedulers.GetAllKeys()
}

// Helper functions

// createShaperPipe creates a traffic shaper pipe based on the specified plan.
func createShaperPipe(ctx context.Context, plan shaperPipesResourceModel) (shaperPipe, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Create traffic shaper pipe from plan
	tflog.Debug(ctx, fmt.Sprintf("Creating %s object from plan", resourceName), map[string]any{"plan": plan})

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

	// Scheduler
	scheduler, exists := schedulers.GetByKey(plan.Scheduler.ValueString())
	if !exists {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("Scheduler `%s` not supported. Please contact the provider maintainers if you believe this should be supported.", plan.Scheduler.ValueString()))
	}

	shaperPipe := shaperPipe{
		Enabled:     plan.Enabled.ValueBool(),
		Bandwidth:   bandwidth,
		Queue:       plan.Queue.ValueInt32(),
		Mask:        plan.Mask.ValueString(),
		Buckets:     plan.Buckets.ValueInt32(),
		Scheduler:   scheduler,
		Codel:       codel,
		Pie:         plan.Pie.ValueBool(),
		Delay:       plan.Delay.ValueInt32(),
		Description: plan.Description.ValueString(),
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return shaperPipe, diagnostics
}

// VerifyShaperPipe checks if the specified traffic shaper pipe exist on the OPNsense firewall.
func VerifyShaperPipe(client *opnsense.Client, queue string) (bool, error) {
	queueExists, err := checkShaperPipeExists(client, queue)
	if err != nil {
		return false, fmt.Errorf("Verify %s exists error: %s", resourceName, err)
	}

	if !queueExists {
		return false, nil
	}

	return true, nil
}
