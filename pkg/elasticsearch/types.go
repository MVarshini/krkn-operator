/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package elasticsearch provides functionality for managing Elasticsearch
// connection configurations in the krkn-operator ecosystem. Configs are stored
// as Kubernetes Secrets with labeled metadata and are used to pre-populate
// scenario global parameters for chaos experiment runs.
package elasticsearch

import (
	"encoding/json"
	"fmt"
	"time"
)

// CreateElasticsearchConfigRequest represents the request to create an ES config
type CreateElasticsearchConfigRequest struct {
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	TelemetryIndex string `json:"telemetryIndex,omitempty"`
	MetricsIndex   string `json:"metricsIndex,omitempty"`
	AlertsIndex    string `json:"alertsIndex,omitempty"`
	GrafanaURL     string `json:"grafanaUrl,omitempty"`
	// CACert is an optional PEM-encoded CA certificate (or bundle) used to trust
	// a self-signed cluster while keeping TLS verification enabled.
	CACert string `json:"caCert,omitempty"`
	// InsecureSkipTLSVerify disables TLS certificate verification entirely. It is
	// a restricted last resort for self-signed clusters without CA material;
	// prefer CACert.
	InsecureSkipTLSVerify bool `json:"insecureSkipTlsVerify,omitempty"`
}

// UpdateElasticsearchConfigRequest represents the request to update an ES config
type UpdateElasticsearchConfigRequest struct {
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	TelemetryIndex string `json:"telemetryIndex,omitempty"`
	MetricsIndex   string `json:"metricsIndex,omitempty"`
	AlertsIndex    string `json:"alertsIndex,omitempty"`
	GrafanaURL     string `json:"grafanaUrl,omitempty"`
	// CACert is an optional PEM-encoded CA certificate (or bundle) used to trust
	// a self-signed cluster while keeping TLS verification enabled.
	CACert string `json:"caCert,omitempty"`
	// InsecureSkipTLSVerify disables TLS certificate verification entirely. It is
	// a restricted last resort for self-signed clusters without CA material;
	// prefer CACert.
	InsecureSkipTLSVerify bool `json:"insecureSkipTlsVerify,omitempty"`
}

// ElasticsearchConfigResponse represents an ES config in API responses.
// The password is never included; callers must re-supply it on update.
type ElasticsearchConfigResponse struct {
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username,omitempty"`
	TelemetryIndex string `json:"telemetryIndex,omitempty"`
	MetricsIndex   string `json:"metricsIndex,omitempty"`
	AlertsIndex    string `json:"alertsIndex,omitempty"`
	GrafanaURL     string `json:"grafanaUrl,omitempty"`
	CreatedAt      string `json:"createdAt,omitempty"`
	CreatedBy      string `json:"createdBy,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
	UpdatedBy      string `json:"updatedBy,omitempty"`
}

// ListElasticsearchConfigsResponse represents the response for listing ES configs
type ListElasticsearchConfigsResponse struct {
	Configs []ElasticsearchConfigResponse `json:"configs"`
	Total   int                           `json:"total"`
}

// CreateElasticsearchConfigResponse represents the response after creating an ES config
type CreateElasticsearchConfigResponse struct {
	Message string `json:"message"`
	Name    string `json:"name"`
}

// UpdateElasticsearchConfigResponse represents the response after updating an ES config
type UpdateElasticsearchConfigResponse struct {
	Message string `json:"message"`
	Name    string `json:"name"`
}

// DeleteElasticsearchConfigResponse represents the response after deleting an ES config
type DeleteElasticsearchConfigResponse struct {
	Message string `json:"message"`
}

// Query size bounds for telemetry searches. DefaultQuerySize is used when the
// request omits a size; MaxQuerySize caps how many documents a single request
// may return to protect the API server and browser.
const (
	DefaultQuerySize = 50
	MaxQuerySize     = 500
)

// QueryTelemetryRequest represents a request to query telemetry documents from
// the telemetry index of a saved Elasticsearch config. Credentials are resolved
// server-side from the named config; the client only references it by name.
type QueryTelemetryRequest struct {
	ConfigName string `json:"configName"`
	Size       int    `json:"size,omitempty"`
	// StartDate and EndDate bound the search by the document timestamp. They are
	// "yyyy-MM-dd" date strings (as produced by the UI date pickers). Empty
	// values fall back to a default trailing window in the query client.
	StartDate string `json:"startDate,omitempty"`
	EndDate   string `json:"endDate,omitempty"`
	// Filters narrows the search to documents matching selected facet values,
	// keyed by facet category (one of the keys in facetFields). The values for a
	// category are OR-ed together; different categories are AND-ed. Unknown
	// category keys are rejected by ValidateQueryRequest.
	Filters map[string][]string `json:"filters,omitempty"`
}

// ClusterMetadata holds the run-level cluster and infrastructure details
// surfaced alongside a telemetry run so the UI can render an expanded row. All
// fields come from the top level of the telemetry document _source and are
// optional: a missing field decodes to its zero value and is omitted from the
// response.
type ClusterMetadata struct {
	// KubernetesObjectsCount maps object kind (e.g. "Pod", "ConfigMap") to the
	// number of that kind present in the cluster at run time.
	KubernetesObjectsCount map[string]int `json:"kubernetes_objects_count,omitempty"`
	// NetworkPlugins lists the cluster network plugins (e.g. "OVNKubernetes").
	NetworkPlugins        []string `json:"network_plugins,omitempty"`
	TotalNodeCount        int      `json:"total_node_count,omitempty"`
	CloudInfrastructure   string   `json:"cloud_infrastructure,omitempty"`
	CloudType             string   `json:"cloud_type,omitempty"`
	ClusterVersion        string   `json:"cluster_version,omitempty"`
	MajorVersion          string   `json:"major_version,omitempty"`
	BuildURL              string   `json:"build_url,omitempty"`
	FIPSEnabled           bool     `json:"fips_enabled,omitempty"`
	Tag                   string   `json:"tag,omitempty"`
	EtcdEncryptionEnabled bool     `json:"etcd_encryption_enabled,omitempty"`
	IPSecEnabled          bool     `json:"ipsec_enabled,omitempty"`
	// NodeSummaryInfos lists one summary per distinct node group (role/shape) in
	// the cluster at run time; nil when the source document carried none.
	NodeSummaryInfos []NodeSummaryInfo `json:"node_summary_infos,omitempty"`
}

// NodeSummaryInfo holds the summary krkn records for one node group sharing a
// role and hardware/software shape. Count is how many nodes fall in the group;
// the remaining fields describe that group. All fields come from an element of
// the telemetry document's node_summary_infos array.
type NodeSummaryInfo struct {
	Count          int    `json:"count"`
	NodesType      string `json:"nodes_type"`
	Architecture   string `json:"architecture"`
	InstanceType   string `json:"instance_type"`
	KernelVersion  string `json:"kernel_version"`
	KubeletVersion string `json:"kubelet_version"`
	OSVersion      string `json:"os_version"`
}

// RecoveredPod holds the recovery timings krkn records for a single pod that came
// back after a pod_disruption scenario. Times are fractional seconds (e.g.
// 37.533992528915405), so they are represented as float64.
type RecoveredPod struct {
	PodName             string  `json:"pod_name"`
	Namespace           string  `json:"namespace"`
	TotalRecoveryTime   float64 `json:"total_recovery_time"`
	PodReadinessTime    float64 `json:"pod_readiness_time"`
	PodReschedulingTime float64 `json:"pod_rescheduling_time"`
}

// AffectedPods groups the pods a scenario disrupted. Only the recovered pods,
// which carry recovery timings, are surfaced for the pod-recovery chart.
type AffectedPods struct {
	Recovered []RecoveredPod `json:"recovered,omitempty"`
}

// ScenarioDetail describes a single scenario within a telemetry run. The
// Parameters field is passed through verbatim as raw JSON because its shape
// varies by scenario type (e.g. an application_outage block vs a pod-scenario
// config/id object), so a fixed struct cannot represent it.
type ScenarioDetail struct {
	ScenarioType   string          `json:"scenario_type"`
	StartTimestamp int64           `json:"start_timestamp"`
	EndTimestamp   int64           `json:"end_timestamp"`
	ExitStatus     int             `json:"exit_status"`
	Parameters     json.RawMessage `json:"parameters,omitempty"`
	// AffectedPods carries per-pod recovery timings for pod_disruption scenarios;
	// nil when the source document had none.
	AffectedPods *AffectedPods `json:"affected_pods,omitempty"`
}

// TelemetryDocument is the set of telemetry fields surfaced to the UI. Each
// document corresponds to one telemetry run. The scalar table columns (type,
// start/end, namespace) are taken from the run's first scenario for backward
// compatibility with the table view, while Metadata and Scenarios carry the
// full run detail used to render an expanded row.
type TelemetryDocument struct {
	RunUUID        string `json:"run_uuid"`
	ScenarioType   string `json:"scenario_type"`
	StartTimestamp int64  `json:"start_timestamp"`
	EndTimestamp   int64  `json:"end_timestamp"`
	Namespace      string `json:"namespace"`
	Status         bool   `json:"status"`
	// Metadata holds run-level cluster/infrastructure detail; nil when the
	// source document carried none of the metadata fields.
	Metadata *ClusterMetadata `json:"metadata,omitempty"`
	// Scenarios lists every scenario in the run, each with its raw parameters.
	Scenarios []ScenarioDetail `json:"scenarios,omitempty"`
}

// TelemetryStats summarizes run-level pass/fail counts across the entire matched
// time window (not just the size-capped documents page). Counts come from a terms
// aggregation on the run-level job_status boolean, so they intentionally do not
// apply the per-scenario exit_status downgrade that a document's status field uses.
type TelemetryStats struct {
	Pass        int     `json:"pass"`
	Fail        int     `json:"fail"`
	PassPercent float64 `json:"pass_percent"` // 0-100, rounded to 2 decimals; 0 when no runs
}

// FacetOption is one selectable value for a filter category, with the number of
// documents in the matched window that carry it. It populates the value
// multi-select in the UI.
type FacetOption struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// QueryTelemetryResponse wraps the telemetry documents returned to the client.
type QueryTelemetryResponse struct {
	Documents []TelemetryDocument `json:"documents"`
	Total     int                 `json:"total"`
	// Stats summarizes pass/fail across the whole matched window, so Stats.Pass +
	// Stats.Fail can exceed Total (which counts only the returned documents page).
	Stats TelemetryStats `json:"stats"`
	// Facets maps each filter category (a key from facetFields) to the available
	// values in the matched window, derived from a terms aggregation per category.
	// The UI uses it to populate the value multi-select. Because filters are
	// applied in the query, facets narrow as filters are selected.
	Facets map[string][]FacetOption `json:"facets,omitempty"`
}

// ValidateQueryRequest validates a QueryTelemetryRequest and normalizes the
// requested size into the supported bounds.
func ValidateQueryRequest(req *QueryTelemetryRequest) error {
	if req.ConfigName == "" {
		return fmt.Errorf("configName is required")
	}
	if req.Size < 0 {
		return fmt.Errorf("size must not be negative")
	}
	if req.Size == 0 {
		req.Size = DefaultQuerySize
	}
	if req.Size > MaxQuerySize {
		req.Size = MaxQuerySize
	}
	if err := validateDate("startDate", req.StartDate); err != nil {
		return err
	}
	if err := validateDate("endDate", req.EndDate); err != nil {
		return err
	}
	if req.StartDate != "" && req.EndDate != "" && req.StartDate > req.EndDate {
		return fmt.Errorf("startDate must not be after endDate")
	}
	if req.EndDate != "" && req.EndDate > time.Now().UTC().Format(dateLayout) {
		return fmt.Errorf("endDate must not be in the future")
	}
	if err := validateFilters(req.Filters); err != nil {
		return err
	}
	return nil
}

// validateFilters rejects filter categories that are not known facet fields.
// Empty value slices are dropped from the map so they never reach the query
// builder as no-op clauses.
func validateFilters(filters map[string][]string) error {
	for key, values := range filters {
		if !isFacetField(key) {
			return fmt.Errorf("unknown filter category %q", key)
		}
		if len(values) == 0 {
			delete(filters, key)
		}
	}
	return nil
}

// dateLayout is the date-only layout accepted for query bounds and understood by
// the Elasticsearch range filter's "yyyy-MM-dd" format.
const dateLayout = "2006-01-02"

// validateDate ensures an optional date string is empty or a valid yyyy-MM-dd
// date. field is used in the error message to identify the offending parameter.
func validateDate(field, value string) error {
	if value == "" {
		return nil
	}
	if _, err := time.Parse(dateLayout, value); err != nil {
		return fmt.Errorf("%s must be a valid yyyy-MM-dd date", field)
	}
	return nil
}
