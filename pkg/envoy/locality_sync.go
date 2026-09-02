// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type localitySyncerParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	JobGroup        job.Group
	DB              *statedb.DB
	Nodes           statedb.Table[*node.Node]
	Clientset       client.Clientset
	MetricsProvider workqueue.MetricsProvider
	XdsServer       XDSServer
	Config          config.ProxyConfig
	DaemonConfig    *option.DaemonConfig
	ClusterInfo     cmtypes.ClusterInfo
}

func registerLocalitySyncer(params localitySyncerParams) {
	if !params.Config.EnvoyNodeLocalityEnabled || !params.DaemonConfig.EnableL7Proxy || !params.Clientset.IsEnabled() {
		return
	}
	// Agent pod readiness does not tell us whether an on-demand embedded Envoy
	// is running. Only the dedicated DaemonSet has discoverable proxy membership.
	if !params.DaemonConfig.ExternalEnvoyProxy {
		return
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.PodList](params.Clientset.Slim().CoreV1().Pods(params.DaemonConfig.K8sNamespace)),
		func(opts *metav1.ListOptions) {
			opts.LabelSelector = "k8s-app=cilium-envoy"
		},
	)
	syncer := &localitySyncer{
		db:          params.DB,
		nodes:       params.Nodes,
		pods:        resource.New[*slim_corev1.Pod](params.Lifecycle, lw, params.MetricsProvider, resource.WithMetric("EnvoyLocalityPod")),
		xds:         params.XdsServer,
		clusterName: params.ClusterInfo.Name,
	}
	params.JobGroup.Add(job.OneShot("envoy-locality", syncer.run,
		job.WithRetry(-1, &job.ExponentialBackoff{Min: time.Second, Max: time.Minute}),
	))
}

// localitySyncer publishes the originating cluster's host distribution. Counting
// nodes alone would include nodes on which the Envoy DaemonSet is not scheduled.
type localitySyncer struct {
	db          *statedb.DB
	nodes       statedb.Table[*node.Node]
	pods        resource.Resource[*slim_corev1.Pod]
	xds         XDSServer
	clusterName string
}

func (s *localitySyncer) run(ctx context.Context, health cell.Health) error {
	// Cancel this subscription if a failed xDS update causes the job to retry.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	store, err := s.pods.Store(ctx)
	if err != nil {
		return err
	}
	events := s.pods.Events(ctx)
	// The initial events replay the whole store. Wait for Sync instead of
	// rebuilding the same assignment once for each pod in a large cluster.
	for synced := false; !synced; {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-events:
			if !ok {
				return nil
			}
			synced = event.Kind == resource.Sync
			event.Done(nil)
		}
	}

	var previous *envoy_config_endpoint.ClusterLoadAssignment
	for {
		txn := s.db.ReadTxn()
		_, nodeWatch := s.nodes.AllWatch(txn)
		assignment, localityErr := s.loadAssignment(txn, store.List())
		if !proto.Equal(previous, assignment) {
			// Publish even an empty assignment. Waiting for ready pods before
			// sending EDS can keep the bootstrap cluster warming, which in turn
			// prevents those same pods from becoming ready.
			err := s.xds.UpsertEnvoyResources(ctx, xds.Resources{
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{
					LocalityClusterName: assignment,
				},
			}, nil)
			if err != nil {
				return fmt.Errorf("publish Envoy locality endpoints: %w", err)
			}
			previous = assignment
		}
		if localityErr != nil {
			health.Degraded("Envoy locality is incomplete", localityErr)
		} else {
			health.OK("Envoy locality endpoints synchronized")
		}

		select {
		case <-ctx.Done():
			return nil
		case <-nodeWatch:
		case event, ok := <-events:
			if !ok {
				return nil
			}
			event.Done(nil)
		}
	}
}

func (s *localitySyncer) loadAssignment(txn statedb.ReadTxn, pods []*slim_corev1.Pod) (*envoy_config_endpoint.ClusterLoadAssignment, error) {
	assignment := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: LocalityClusterName}
	zones := map[string]string{}
	for n := range s.nodes.All(txn) {
		// A remote ClusterMesh node can have the same name as a local node.
		if n.Cluster == s.clusterName {
			zones[n.Name] = n.Labels[corev1.LabelTopologyZone]
		}
	}

	hosts := map[string]netip.Addr{}
	for _, pod := range pods {
		if pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != slim_corev1.PodRunning {
			continue
		}
		if !slices.ContainsFunc(pod.Status.Conditions, func(condition slim_corev1.PodCondition) bool {
			return condition.Type == slim_corev1.PodReady && condition.Status == slim_corev1.ConditionTrue
		}) {
			continue
		}
		if zones[pod.Spec.NodeName] == "" {
			// A partial distribution would skew the local/remote traffic split.
			// Leave the source cluster empty until every ready proxy has a zone,
			// so Envoy falls back to ordinary load balancing in the meantime.
			return assignment, fmt.Errorf("zone is unavailable for Envoy node %q", pod.Spec.NodeName)
		}
		addr, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil {
			return assignment, fmt.Errorf("invalid IP for Envoy pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		// Count a node once even if a DaemonSet rollout briefly has two ready
		// pods on it. Pick a stable address regardless of the store's order.
		if old, ok := hosts[pod.Spec.NodeName]; !ok || addr.Less(old) {
			hosts[pod.Spec.NodeName] = addr
		}
	}

	byZone := map[string][]*envoy_config_endpoint.LbEndpoint{}
	for _, name := range slices.Sorted(maps.Keys(hosts)) {
		byZone[zones[name]] = append(byZone[zones[name]], &envoy_config_endpoint.LbEndpoint{
			HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
				Endpoint: &envoy_config_endpoint.Endpoint{
					Hostname: name,
					Address: &envoy_config_core.Address{
						Address: &envoy_config_core.Address_SocketAddress{
							SocketAddress: &envoy_config_core.SocketAddress{
								Address: hosts[name].String(),
								// This cluster describes source capacity; Envoy never
								// connects to these endpoints.
								PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: 0},
							},
						},
					},
				},
			},
		})
	}
	for _, zone := range slices.Sorted(maps.Keys(byZone)) {
		assignment.Endpoints = append(assignment.Endpoints, &envoy_config_endpoint.LocalityLbEndpoints{
			Locality:    &envoy_config_core.Locality{Zone: zone},
			LbEndpoints: byZone[zone],
		})
	}
	return assignment, nil
}
