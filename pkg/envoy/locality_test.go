// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	envoy_config_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func TestAppendEmbeddedLocalityBootstrap(t *testing.T) {
	tests := []struct {
		name      string
		xdsMode   config.XDSMode
		assertEDS func(t *testing.T, edsConfig *corev3.ConfigSource)
	}{
		{
			name:    "split",
			xdsMode: config.EnvoyXDSModeSplit,
			assertEDS: func(t *testing.T, edsConfig *corev3.ConfigSource) {
				apiConfigSource := edsConfig.GetApiConfigSource()
				require.NotNil(t, apiConfigSource)
				require.NotEmpty(t, apiConfigSource.GetGrpcServices())
				require.Equal(t, CiliumXDSClusterName, apiConfigSource.GetGrpcServices()[0].GetEnvoyGrpc().GetClusterName())
				require.Nil(t, edsConfig.GetAds())
			},
		},
		{
			name:    "ads",
			xdsMode: config.EnvoyXDSModeADS,
			assertEDS: func(t *testing.T, edsConfig *corev3.ConfigSource) {
				require.NotNil(t, edsConfig.GetAds())
				require.Nil(t, edsConfig.GetApiConfigSource())
			},
		},
		{
			name:    "strict-ads",
			xdsMode: config.EnvoyXDSModeStrictADS,
			assertEDS: func(t *testing.T, edsConfig *corev3.ConfigSource) {
				require.NotNil(t, edsConfig.GetAds())
				require.Nil(t, edsConfig.GetApiConfigSource())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &envoy_config_bootstrap.Bootstrap{
				StaticResources: &envoy_config_bootstrap.Bootstrap_StaticResources{},
			}

			appendEmbeddedLocalityBootstrap(bs, tt.xdsMode, 7, "zone-a")

			require.Equal(t, LocalityClusterName, bs.GetClusterManager().GetLocalClusterName())
			require.Equal(t, "zone-a", bs.GetNode().GetLocality().GetZone())
			require.Len(t, bs.GetStaticResources().GetClusters(), 1)

			cluster := bs.GetStaticResources().GetClusters()[0]
			require.Equal(t, LocalityClusterName, cluster.GetName())
			require.Equal(t, envoy_config_cluster.Cluster_EDS, cluster.GetType())
			require.Equal(t, LocalityClusterName, cluster.GetEdsClusterConfig().GetServiceName())

			tt.assertEDS(t, cluster.GetEdsClusterConfig().GetEdsConfig())
		})
	}
}

func newLocalityPod(name, nodeName, ip string) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: "kube-system",
			Labels:    map[string]string{"k8s-app": "cilium-envoy"},
		},
		Spec: slim_corev1.PodSpec{NodeName: nodeName, HostNetwork: true},
		Status: slim_corev1.PodStatus{
			Phase: slim_corev1.PodRunning,
			PodIP: ip,
			Conditions: []slim_corev1.PodCondition{{
				Type:   slim_corev1.PodReady,
				Status: slim_corev1.ConditionTrue,
			}},
		},
	}
}

func newLocalityNode(name, cluster, zone string) *node.Node {
	return &node.Node{Node: nodetypes.Node{
		Name:    name,
		Cluster: cluster,
		Labels:  map[string]string{corev1.LabelTopologyZone: zone},
	}}
}

// localityHosts keeps assertions on the actual zone, node and address values,
// rather than the protobuf's generated bookkeeping fields.
func localityHosts(assignment *envoy_config_endpoint.ClusterLoadAssignment) map[string][]string {
	hosts := map[string][]string{}
	for _, group := range assignment.GetEndpoints() {
		for _, host := range group.LbEndpoints {
			ep := host.GetEndpoint()
			hosts[group.GetLocality().GetZone()] = append(hosts[group.GetLocality().GetZone()],
				ep.Hostname+"@"+ep.GetAddress().GetSocketAddress().GetAddress())
		}
	}
	return hosts
}

func TestLocalityLoadAssignment(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)
	txn := db.WriteTxn(nodes)
	for _, n := range []*node.Node{
		newLocalityNode("node-a", "test", "zone-a"),
		newLocalityNode("node-b", "test", "zone-b"),
		newLocalityNode("node-unused", "test", "zone-c"),
		newLocalityNode("node-no-zone", "test", ""),
		newLocalityNode("node-a", "remote", "wrong-zone"),
	} {
		_, _, err := nodes.Insert(txn, n)
		require.NoError(t, err)
	}
	txn.Commit()
	syncer := &localitySyncer{nodes: nodes, clusterName: "test"}

	unready := newLocalityPod("unready", "unknown-node", "192.0.2.30")
	unready.Status.Conditions[0].Status = slim_corev1.ConditionFalse
	terminating := newLocalityPod("terminating", "unknown-node", "192.0.2.40")
	terminating.DeletionTimestamp = &slim_metav1.Time{Time: time.Now()}
	pending := newLocalityPod("pending", "unknown-node", "")
	pending.Status.Phase = slim_corev1.PodPending

	pods := []*slim_corev1.Pod{
		newLocalityPod("envoy-b", "node-b", "2001:db8::2"),
		newLocalityPod("envoy-a", "node-a", "192.0.2.1"),
		newLocalityPod("envoy-a-rollout", "node-a", "192.0.2.11"),
		unready, terminating, pending,
	}
	assignment, err := syncer.loadAssignment(db.ReadTxn(), pods)
	require.NoError(t, err)
	require.NoError(t, assignment.ValidateAll())
	require.Equal(t, LocalityClusterName, assignment.ClusterName)
	require.Equal(t, map[string][]string{
		"zone-a": {"node-a@192.0.2.1"},
		"zone-b": {"node-b@2001:db8::2"},
	}, localityHosts(assignment))

	// Informer stores are unordered. A different iteration order must not
	// produce another xDS update or count a rollout pod twice.
	slices.Reverse(pods)
	reordered, err := syncer.loadAssignment(db.ReadTxn(), pods)
	require.NoError(t, err)
	require.True(t, proto.Equal(assignment, reordered))

	for _, tt := range []struct {
		name string
		pod  *slim_corev1.Pod
	}{
		{"node missing", newLocalityPod("missing", "unknown-node", "192.0.2.50")},
		{"zone missing", newLocalityPod("no-zone", "node-no-zone", "192.0.2.50")},
		{"IP missing", newLocalityPod("no-ip", "node-b", "")},
		{"IP invalid", newLocalityPod("bad-ip", "node-b", "not-an-ip")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Do not advertise the known subset as if it were the whole source
			// cluster. An empty assignment lets Envoy fall back safely.
			assignment, err := syncer.loadAssignment(db.ReadTxn(), append(slices.Clone(pods), tt.pod))
			require.Error(t, err)
			require.Empty(t, assignment.Endpoints)
		})
	}
}

type localityXdsServer struct {
	fakeXdsServer
	mu         sync.Mutex
	assignment *envoy_config_endpoint.ClusterLoadAssignment
	failures   int
}

func (s *localityXdsServer) UpsertEnvoyResources(_ context.Context, resources xds.Resources, _ *completion.WaitGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures > 0 {
		s.failures--
		return errors.New("locality update failed")
	}
	s.assignment = resources.Endpoints[LocalityClusterName]
	return nil
}

func (s *localityXdsServer) failNextUpdate() {
	s.mu.Lock()
	s.failures = 1
	s.mu.Unlock()
}

func (s *localityXdsServer) waitForHosts(t *testing.T, expected map[string][]string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if assert.NotNil(c, s.assignment) {
			assert.Equal(c, expected, localityHosts(s.assignment))
		}
	}, 5*time.Second, 10*time.Millisecond)
}

// Exercise registration, the pod informer, node watches and xDS retries together.
// In particular, an empty initial pod list must still produce EDS: otherwise the
// bootstrap cluster can wait on pod readiness while readiness waits on EDS.
func TestLocalitySyncer(t *testing.T) {
	var (
		db     *statedb.DB
		nodes  statedb.RWTable[*node.Node]
		client *k8sClient.FakeClientset
	)
	xdsServer := &localityXdsServer{}
	h := hive.New(
		k8sClient.FakeClientCell(),
		cell.Provide(
			node.NewNodeTable,
			statedb.RWTable[*node.Node].ToTable,
			func() XDSServer { return xdsServer },
			func() config.ProxyConfig { return config.ProxyConfig{EnvoyNodeLocalityEnabled: true} },
			func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{Name: "test"} },
			func() *option.DaemonConfig {
				return &option.DaemonConfig{EnableL7Proxy: true, ExternalEnvoyProxy: true, K8sNamespace: "kube-system"}
			},
		),
		cell.Invoke(registerLocalitySyncer),
		cell.Invoke(func(db_ *statedb.DB, nodes_ statedb.RWTable[*node.Node], client_ *k8sClient.FakeClientset) {
			db, nodes, client = db_, nodes_, client_
		}),
	)
	log := hivetest.Logger(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, h.Stop(log, stopCtx))
	})
	require.NoError(t, h.Start(log, ctx))
	xdsServer.waitForHosts(t, map[string][]string{})

	upsertNode := func(n *node.Node) {
		t.Helper()
		txn := db.WriteTxn(nodes)
		_, _, err := nodes.Insert(txn, n)
		require.NoError(t, err)
		txn.Commit()
	}
	upsertNode(newLocalityNode("node-a", "test", "zone-a"))
	upsertNode(newLocalityNode("unused", "test", "zone-unused"))
	pods := client.Slim().CoreV1().Pods("kube-system")
	// A similarly labelled pod in another namespace is not part of this
	// originating cluster, even when it is ready.
	otherNamespace := newLocalityPod("other-envoy", "unknown", "192.0.2.98")
	otherNamespace.Namespace = "other"
	_, err := client.Slim().CoreV1().Pods("other").Create(ctx, otherNamespace, metav1.CreateOptions{})
	require.NoError(t, err)
	podA, err := pods.Create(ctx, newLocalityPod("envoy-a", "node-a", "192.0.2.1"), metav1.CreateOptions{})
	require.NoError(t, err)
	xdsServer.waitForHosts(t, map[string][]string{"zone-a": {"node-a@192.0.2.1"}})

	// A node-only change must update EDS without another pod event.
	upsertNode(newLocalityNode("node-a", "test", "zone-c"))
	xdsServer.waitForHosts(t, map[string][]string{"zone-c": {"node-a@192.0.2.1"}})

	// Pod and node watches can arrive in either order. Clear a now-incomplete
	// distribution, then restore it when the missing node appears.
	_, err = pods.Create(ctx, newLocalityPod("envoy-b", "node-b", "192.0.2.2"), metav1.CreateOptions{})
	require.NoError(t, err)
	xdsServer.waitForHosts(t, map[string][]string{})
	upsertNode(newLocalityNode("node-b", "test", "zone-b"))
	xdsServer.waitForHosts(t, map[string][]string{
		"zone-b": {"node-b@192.0.2.2"},
		"zone-c": {"node-a@192.0.2.1"},
	})

	podA = podA.DeepCopy()
	podA.Status.Conditions[0].Status = slim_corev1.ConditionFalse
	podA, err = pods.UpdateStatus(ctx, podA, metav1.UpdateOptions{})
	require.NoError(t, err)
	xdsServer.waitForHosts(t, map[string][]string{"zone-b": {"node-b@192.0.2.2"}})

	// A failed publication must recover without requiring another Kubernetes
	// event. The retry creates a fresh subscription and republishes the store.
	xdsServer.failNextUpdate()
	podA = podA.DeepCopy()
	podA.Status.Conditions[0].Status = slim_corev1.ConditionTrue
	podA, err = pods.UpdateStatus(ctx, podA, metav1.UpdateOptions{})
	require.NoError(t, err)
	xdsServer.waitForHosts(t, map[string][]string{
		"zone-b": {"node-b@192.0.2.2"},
		"zone-c": {"node-a@192.0.2.1"},
	})

	require.NoError(t, pods.Delete(ctx, "envoy-b", metav1.DeleteOptions{}))
	xdsServer.waitForHosts(t, map[string][]string{"zone-c": {"node-a@192.0.2.1"}})
	podA = podA.DeepCopy()
	podA.DeletionTimestamp = &slim_metav1.Time{Time: time.Now()}
	_, err = pods.Update(ctx, podA, metav1.UpdateOptions{})
	require.NoError(t, err)
	xdsServer.waitForHosts(t, map[string][]string{})
}

func TestLocalitySyncerDisabled(t *testing.T) {
	for _, tt := range []struct {
		name        string
		locality    bool
		l7Proxy     bool
		external    bool
		k8sDisabled bool
	}{
		{name: "locality disabled", l7Proxy: true, external: true},
		{name: "L7 proxy disabled", locality: true, external: true},
		{name: "embedded Envoy", locality: true, l7Proxy: true},
		{name: "Kubernetes disabled", locality: true, l7Proxy: true, external: true, k8sDisabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := k8sClient.NewFakeClientset(hivetest.Logger(t))
			if tt.k8sDisabled {
				client.Disable()
			}
			// No lifecycle or job group is supplied: these paths must not
			// register another informer or start a locality publisher.
			registerLocalitySyncer(localitySyncerParams{
				Clientset: client,
				Config:    config.ProxyConfig{EnvoyNodeLocalityEnabled: tt.locality},
				DaemonConfig: &option.DaemonConfig{
					EnableL7Proxy:      tt.l7Proxy,
					ExternalEnvoyProxy: tt.external,
				},
			})
		})
	}
}
