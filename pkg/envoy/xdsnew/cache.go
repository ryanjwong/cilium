// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/davecgh/go-spew/spew"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	controlplanelog "github.com/envoyproxy/go-control-plane/pkg/log"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL      = "type.googleapis.com/cilium.NetworkPolicy"
	NetworkPolicyHostsTypeURL = "type.googleapis.com/cilium.NetworkPolicyHosts"
	logFieldComponent         = "component"
)

type Cache interface {
	cache.SnapshotCache

	GetVersion(resources *xds.Resources) string
	GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error)
	UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFunc func()) error
	SetResources(nodeID string, resources *xds.Resources)
	GetAllResources(nodeID string) *xds.Resources
	AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
}

type cacheImpl struct {
	cache.SnapshotCache

	// mutex protects accesses to the configuration resources below.
	mutex *lock.RWMutex
	// resourcesInSnapshot holds the last set of resources (keyed by nodeID) pushed to Envoy.
	resourcesInSnapshot map[string]*xds.Resources
	logger              *slog.Logger
	hasher              hash.Hash32
	completionCbs       *callbacks.CompletionCallbacks
	bootstrapEndpoints  []string
	strictAdsMode       bool
	bootstrapMutex      lock.Mutex
	bootstrapStreams    map[chan cache.Response]*bootstrapResponseStream
}

var _ Cache = &cacheImpl{}

// ciliumSnapshot implements go-control-plane's ResourceSnapshot interface for
// both Envoy core resources and Cilium-specific xDS resources.
type ciliumSnapshot struct {
	Resources  map[string]cache.Resources
	VersionMap map[string]map[string]string

	bootstrapEndpoints []string
}

// Ensure ciliumSnapshot implements cache.ResourceSnapshot.
var _ cache.ResourceSnapshot = &ciliumSnapshot{}
var _ interface{ Consistent() error } = &ciliumSnapshot{}

var snapshotResourceTypes = []envoy_resource.Type{
	envoy_resource.EndpointType,
	envoy_resource.ClusterType,
	envoy_resource.RouteType,
	envoy_resource.ListenerType,
	envoy_resource.SecretType,
	NetworkPolicyTypeURL,
	NetworkPolicyHostsTypeURL,
}

func newCiliumSnapshot(resources map[string]cache.Resources, bootstrapEndpoints []string) *ciliumSnapshot {
	w := &ciliumSnapshot{
		Resources:          make(map[string]cache.Resources, len(snapshotResourceTypes)),
		bootstrapEndpoints: bootstrapEndpoints,
	}
	for _, typeURL := range snapshotResourceTypes {
		w.Resources[typeURL] = resources[typeURL]
	}
	return w
}

func (w *ciliumSnapshot) GetVersion(typeURL string) string {
	group, ok := w.Resources[typeURL]
	if !ok {
		return ""
	}
	return group.Version
}

func (w *ciliumSnapshot) GetResources(typeURL string) map[string]cache_types.Resource {
	resources := w.GetResourcesAndTTL(typeURL)
	if len(resources) == 0 {
		return nil
	}
	out := make(map[string]cache_types.Resource, len(resources))
	for name, resource := range resources {
		out[name] = resource.Resource
	}
	return out
}

func (w *ciliumSnapshot) GetResourcesAndTTL(typeURL string) map[string]cache_types.ResourceWithTTL {
	group, ok := w.Resources[typeURL]
	if !ok {
		return nil
	}
	return group.Items
}

func (w *ciliumSnapshot) ConstructVersionMap() error {
	if w == nil {
		return fmt.Errorf("missing snapshot")
	}
	if w.VersionMap != nil {
		return nil
	}

	w.VersionMap = make(map[string]map[string]string, len(w.Resources))
	for typeURL, group := range w.Resources {
		if len(group.Items) == 0 {
			continue
		}
		w.VersionMap[typeURL] = make(map[string]string, len(group.Items))
		for name, resource := range group.Items {
			marshaledResource, err := cache.MarshalResource(resource.Resource)
			if err != nil {
				return err
			}
			w.VersionMap[typeURL][name] = cache.HashResource(marshaledResource)
		}
	}
	return nil
}

func (w *ciliumSnapshot) GetVersionMap(typeURL string) map[string]string {
	if w == nil || w.VersionMap == nil {
		return nil
	}
	return w.VersionMap[typeURL]
}

func (w *ciliumSnapshot) Consistent() error {
	if w == nil {
		return fmt.Errorf("nil snapshot")
	}

	var resourceGroups [cache_types.UnknownType]cache.Resources
	for typeURL, resources := range w.Resources {
		responseType := cache.GetResponseType(envoy_resource.Type(typeURL))
		if responseType == cache_types.UnknownType {
			continue
		}
		resourceGroups[responseType] = resources
	}

	referencedResources := cache.GetAllResourceReferences(resourceGroups)
	for _, responseType := range []cache_types.ResponseType{cache_types.Endpoint, cache_types.Route} {
		typeURL, err := cache.GetResponseTypeURL(responseType)
		if err != nil {
			return err
		}

		resources := resourceGroups[responseType]
		references := referencedResources[typeURL]
		if responseType == cache_types.Endpoint {
			// Bootstrap clusters do not appear in CDS, but can still
			// subscribe to EDS resources in this snapshot.
			for _, name := range w.bootstrapEndpoints {
				if _, exists := resources.Items[name]; exists {
					if references == nil {
						references = make(map[string]bool)
					}
					references[name] = true
				}
			}
		}
		if len(references) != len(resources.Items) {
			return fmt.Errorf("mismatched %q reference and resource lengths: len(%v) != %d",
				typeURL, references, len(resources.Items))
		}
		for name := range references {
			if _, ok := resources.Items[name]; !ok {
				return fmt.Errorf("inconsistent %q reference: missing resource %q", typeURL, name)
			}
		}
	}

	return nil
}

// CheckSnapshotConsistency verifies that a generated ADS snapshot has all referenced Envoy resources.
func CheckSnapshotConsistency(snapshot cache.ResourceSnapshot) error {
	checker, ok := snapshot.(interface{ Consistent() error })
	if !ok {
		return fmt.Errorf("snapshot %T does not support consistency checks", snapshot)
	}
	return checker.Consistent()
}

func snapshotCacheLogger(logger *slog.Logger) controlplanelog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(logFieldComponent, "go-control-plane-snapshot-cache")
	return controlplanelog.LoggerFuncs{
		DebugFunc: func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...))
		},
		InfoFunc: func(format string, args ...any) {
			// Consider using Debug here if Info is too chatty
			logger.Info(fmt.Sprintf(format, args...))
		},
		WarnFunc: func(format string, args ...any) {
			logger.Warn(fmt.Sprintf(format, args...))
		},
		ErrorFunc: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...))
		},
	}
}

// NewCache returns an ADS snapshot cache. bootstrapEndpoints names EDS resources
// referenced by static bootstrap clusters rather than CDS.
func NewCache(logger *slog.Logger, strictAdsMode bool, bootstrapEndpoints ...string) Cache {
	snapshotCache := cache.NewSnapshotCache(strictAdsMode, cache.IDHash{}, snapshotCacheLogger(logger))

	return &cacheImpl{
		SnapshotCache:       snapshotCache,
		mutex:               &lock.RWMutex{},
		resourcesInSnapshot: make(map[string]*xds.Resources),
		logger:              logger,
		hasher:              fnv.New32a(),
		completionCbs:       callbacks.NewCompletionCallbacks(logger),
		bootstrapEndpoints:  slices.Clone(bootstrapEndpoints),
		strictAdsMode:       strictAdsMode,
	}
}

func (c *cacheImpl) hash(resources map[string]string) string {
	hasher := fnv.New32a()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", resources)
	return rand.SafeEncodeString(fmt.Sprint(hasher.Sum32()))
}

func (c *cacheImpl) GetVersion(resources *xds.Resources) string {
	encodedResources, err := Marshal(resources)
	if err != nil {
		c.logger.Error(fmt.Sprintf("failed to marshal resources for versioning: %v", err))
		return ""
	}
	return c.hash(encodedResources)
}

func resourceGroup(version string, resources map[string]cache_types.Resource) cache.Resources {
	if len(resources) == 0 {
		return cache.Resources{Version: version}
	}
	items := make(map[string]cache_types.ResourceWithTTL, len(resources))
	for name, resource := range resources {
		items[name] = cache_types.ResourceWithTTL{Resource: resource}
	}
	return cache.Resources{
		Version: version,
		Items:   items,
	}
}

func addResourceReference(refs map[string]map[string]struct{}, parent, resource string) {
	if parent == "" || resource == "" {
		return
	}
	if refs[parent] == nil {
		refs[parent] = make(map[string]struct{})
	}
	refs[parent][resource] = struct{}{}
}

func resourceReferencesVersionContext(refs map[string]map[string]struct{}) string {
	parents := slices.Collect(maps.Keys(refs))
	slices.Sort(parents)

	var sb strings.Builder
	for _, parent := range parents {
		children := slices.Collect(maps.Keys(refs[parent]))
		slices.Sort(children)
		for _, child := range children {
			sb.WriteString(parent)
			sb.WriteByte(0)
			sb.WriteString(child)
			sb.WriteByte(0)
		}
	}
	return sb.String()
}

func edsClusterReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, cluster := range resources.Clusters {
		if cluster.GetType() != envoy_config_cluster.Cluster_EDS {
			continue
		}

		// Use the snapshot map key as the parent identity. CEC parsing may
		// qualify the snapshot resource key while leaving the inner Envoy name
		// or EDS service name shared across multiple generated clusters; the key
		// is what makes a newly introduced parent visible to versioning.
		serviceName := cluster.GetEdsClusterConfig().GetServiceName()
		if serviceName == "" {
			serviceName = cluster.GetName()
		}
		if serviceName == "" {
			serviceName = name
		}
		addResourceReference(refs, name, serviceName)
	}

	return resourceReferencesVersionContext(refs)
}

func httpConnectionManagerFromFilter(filter *envoy_config_listener.Filter) *envoy_config_http.HttpConnectionManager {
	typedConfig := filter.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	hcm, _ := msg.(*envoy_config_http.HttpConnectionManager)
	return hcm
}

func rdsListenerReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.Listeners {
		for _, filterChain := range listener.GetFilterChains() {
			for _, filter := range filterChain.GetFilters() {
				hcm := httpConnectionManagerFromFilter(filter)
				if hcm == nil {
					continue
				}
				addResourceReference(refs, name, hcm.GetRds().GetRouteConfigName())
			}
		}
	}

	return resourceReferencesVersionContext(refs)
}

func addSDSSecretConfigReference(refs map[string]map[string]struct{}, parent string, secretConfig *envoy_config_tls.SdsSecretConfig) {
	addResourceReference(refs, parent, secretConfig.GetName())
}

func addCommonTLSContextSDSReferences(refs map[string]map[string]struct{}, parent string, commonTLSContext *envoy_config_tls.CommonTlsContext) {
	if commonTLSContext == nil {
		return
	}
	for _, secretConfig := range commonTLSContext.GetTlsCertificateSdsSecretConfigs() {
		addSDSSecretConfigReference(refs, parent, secretConfig)
	}
	addSDSSecretConfigReference(refs, parent, commonTLSContext.GetValidationContextSdsSecretConfig())
	addSDSSecretConfigReference(refs, parent, commonTLSContext.GetCombinedValidationContext().GetValidationContextSdsSecretConfig())
}

func addDownstreamTLSContextSDSReferences(refs map[string]map[string]struct{}, parent string, downstreamTLSContext *envoy_config_tls.DownstreamTlsContext) {
	if downstreamTLSContext == nil {
		return
	}
	addCommonTLSContextSDSReferences(refs, parent, downstreamTLSContext.GetCommonTlsContext())
	addSDSSecretConfigReference(refs, parent, downstreamTLSContext.GetSessionTicketKeysSdsSecretConfig())
}

func addUpstreamTLSContextSDSReferences(refs map[string]map[string]struct{}, parent string, upstreamTLSContext *envoy_config_tls.UpstreamTlsContext) {
	if upstreamTLSContext == nil {
		return
	}
	addCommonTLSContextSDSReferences(refs, parent, upstreamTLSContext.GetCommonTlsContext())
}

func downstreamTLSContextFromTransportSocket(transportSocket *envoy_config_core.TransportSocket) *envoy_config_tls.DownstreamTlsContext {
	typedConfig := transportSocket.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	downstreamTLSContext, _ := msg.(*envoy_config_tls.DownstreamTlsContext)
	return downstreamTLSContext
}

func upstreamTLSContextFromTransportSocket(transportSocket *envoy_config_core.TransportSocket) *envoy_config_tls.UpstreamTlsContext {
	typedConfig := transportSocket.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	upstreamTLSContext, _ := msg.(*envoy_config_tls.UpstreamTlsContext)
	return upstreamTLSContext
}

func tcpProxyFromFilter(filter *envoy_config_listener.Filter) *envoy_extensions_filters_network_tcp_proxy.TcpProxy {
	typedConfig := filter.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	tcpProxy, _ := msg.(*envoy_extensions_filters_network_tcp_proxy.TcpProxy)
	return tcpProxy
}

func listenerClusterReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.Listeners {
		for _, filterChain := range listener.GetFilterChains() {
			for _, filter := range filterChain.GetFilters() {
				tcpProxy := tcpProxyFromFilter(filter)
				if tcpProxy == nil {
					continue
				}
				addResourceReference(refs, name, tcpProxy.GetCluster())
				for _, cluster := range tcpProxy.GetWeightedClusters().GetClusters() {
					addResourceReference(refs, name, cluster.GetName())
				}
			}
		}
	}
	return resourceReferencesVersionContext(refs)
}

func sdsReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.Listeners {
		for _, filterChain := range listener.GetFilterChains() {
			addDownstreamTLSContextSDSReferences(refs, name, downstreamTLSContextFromTransportSocket(filterChain.GetTransportSocket()))
		}
	}
	for name, cluster := range resources.Clusters {
		addUpstreamTLSContextSDSReferences(refs, name, upstreamTLSContextFromTransportSocket(cluster.GetTransportSocket()))
	}

	return resourceReferencesVersionContext(refs)
}

func (c *cacheImpl) resourceVersion(typeURL string, resources map[string]cache_types.Resource, versionContext ...string) (string, error) {
	keys := slices.Collect(maps.Keys(resources))
	slices.Sort(keys)
	var sb strings.Builder
	for _, name := range keys {
		encodedResource, err := marshal(resources[name])
		if err != nil {
			return "", err
		}
		sb.WriteString(name)
		sb.WriteString(encodedResource)
	}
	for _, context := range versionContext {
		if context == "" {
			continue
		}
		sb.WriteByte(0)
		sb.WriteString("version-context")
		sb.WriteByte(0)
		sb.WriteString(context)
	}
	return c.hash(map[string]string{typeURL: sb.String()}), nil
}

// normalizeSnapshotResources returns the resource view used to build an ADS
// snapshot.
//
// Envoy expects every EDS-backed cluster in an ADS snapshot to have a matching
// ClusterLoadAssignment resource, even when the cluster currently has no
// endpoints. If CDS references an EDS resource that is absent from EDS, Envoy
// keeps the cluster warming and may not finish initialization, which also
// prevents it from requesting later resource types such as LDS/RDS/NPDS.
//
// The synthetic empty ClusterLoadAssignments are snapshot-local only. They must
// not be written back to the authoritative xds.Resources state, otherwise Cilium
// could retain generated placeholders after the corresponding clusters are
// removed and produce misleading diffs/reverts.
func normalizeSnapshotResources(resources *xds.Resources) *xds.Resources {
	var normalized *xds.Resources

	for _, cluster := range resources.Clusters {
		if cluster.GetType() != envoy_config_cluster.Cluster_EDS {
			continue
		}

		name := cluster.GetEdsClusterConfig().GetServiceName()
		if name == "" {
			name = cluster.GetName()
		}
		if name == "" {
			continue
		}

		if _, exists := resources.Endpoints[name]; exists {
			continue
		}

		if normalized == nil {
			copy := *resources
			copy.Endpoints = maps.Clone(resources.Endpoints)
			if copy.Endpoints == nil {
				copy.Endpoints = make(map[string]*envoy_config_endpoint.ClusterLoadAssignment)
			}
			normalized = &copy
		}
		normalized.Endpoints[name] = &envoy_config_endpoint.ClusterLoadAssignment{
			ClusterName: name,
		}
	}

	if normalized == nil {
		return resources
	}
	return normalized
}

func (c *cacheImpl) GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error) {
	if resources == nil {
		empty := xds.NewResources()
		resources = &empty
	}

	resources = normalizeSnapshotResources(resources)
	endpoints := make(map[string]cache_types.Resource, len(resources.Endpoints))
	clusters := make(map[string]cache_types.Resource, len(resources.Clusters))
	routes := make(map[string]cache_types.Resource, len(resources.Routes))
	listeners := make(map[string]cache_types.Resource, len(resources.Listeners))
	networkPolicies := make(map[string]cache_types.Resource, len(resources.NetworkPolicies))
	networkPolicyHosts := make(map[string]cache_types.Resource, len(resources.NetworkPolicyHosts))
	secrets := make(map[string]cache_types.Resource, len(resources.Secrets))

	for name, r := range resources.Endpoints {
		// Skip wildcard :* endpoints that have no matching cluster,
		// as they cause snapshot inconsistency (EDS count > CDS references).
		// These are generated for backward compatibility with the old per-type
		// xDS caches but are not needed in the ADS snapshot.
		if _, hasCluster := resources.Clusters[name]; !hasCluster && len(name) > 2 && name[len(name)-2:] == ":*" {
			continue
		}
		endpoints[name] = r
	}
	for name, r := range resources.Clusters {
		clusters[name] = r
	}
	for name, r := range resources.Routes {
		routes[name] = r
	}
	for name, r := range resources.Listeners {
		listeners[name] = r
	}
	for name, r := range resources.NetworkPolicies {
		networkPolicies[name] = r
	}
	for name, r := range resources.NetworkPolicyHosts {
		networkPolicyHosts[name] = r
	}
	for name, r := range resources.Secrets {
		secrets[name] = r
	}

	resourceGroups := map[string]map[string]cache_types.Resource{
		envoy_resource.EndpointType: endpoints,
		envoy_resource.ClusterType:  clusters,
		envoy_resource.RouteType:    routes,
		envoy_resource.ListenerType: listeners,
		envoy_resource.SecretType:   secrets,
		NetworkPolicyTypeURL:        networkPolicies,
		NetworkPolicyHostsTypeURL:   networkPolicyHosts,
	}

	versionedResources := make(map[string]cache.Resources, len(resourceGroups))
	for typeURL, resourceMap := range resourceGroups {
		var versionContext string
		if typeURL == envoy_resource.EndpointType {
			// Envoy creates one EDS subscription per EDS-backed cluster. A new
			// parent can request a dependent resource that the ADS stream has already
			// seen at the current version, so go-control-plane may open the new watch
			// without replaying the cached resource. Include the parent reference sets
			// in dependent resource versions so new subscriptions receive the current
			// resource immediately.
			versionContext = edsClusterReferenceVersionContext(resources)
		} else if typeURL == envoy_resource.RouteType {
			versionContext = rdsListenerReferenceVersionContext(resources)
		} else if typeURL == envoy_resource.SecretType {
			versionContext = sdsReferenceVersionContext(resources)
		} else if typeURL == envoy_resource.ClusterType {
			versionContext = listenerClusterReferenceVersionContext(resources)
		}
		version, err := c.resourceVersion(typeURL, resourceMap, versionContext)
		if err != nil {
			return nil, err
		}
		versionedResources[typeURL] = resourceGroup(version, resourceMap)
	}

	return newCiliumSnapshot(versionedResources, c.bootstrapEndpoints), nil
}

func (c *cacheImpl) GetCompletionCallbacks() *callbacks.CompletionCallbacks {
	return c.completionCbs
}

func (c *cacheImpl) SetResources(nodeID string, resources *xds.Resources) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resourcesInSnapshot[nodeID] = resources
}

func (c *cacheImpl) UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFunc func()) error {
	type immediateCompletion struct {
		comp                      *completion.Completion
		typeURL                   string
		err                       error
		completeUnsentCompletions bool
	}

	completions := make([]*completion.Completion, 0, len(updatedTypeURLS))
	immediateCompletions := make([]immediateCompletion, 0, 1)
	if wg != nil && len(updatedTypeURLS) > 0 {
		oldSnapshot, _ := c.GetSnapshot(nodeID)
		for typeURL, completionCallback := range updatedTypeURLS {
			comp := wg.AddCompletionWithCallback(nil, completionCallback)
			if typeURL == NetworkPolicyTypeURL && len(newSnapshot.GetResources(NetworkPolicyTypeURL)) == 0 {
				immediateCompletions = append(immediateCompletions, immediateCompletion{comp: comp})
				continue
			}
			version := newSnapshot.GetVersion(typeURL)
			versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL) != version
			registered, err := c.completionCbs.AddTypeVersionCompletion(comp, version, typeURL, nodeID, versionChanged, revertFunc)
			if !registered {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:                      comp,
					typeURL:                   typeURL,
					err:                       err,
					completeUnsentCompletions: err == nil,
				})
				continue
			}
			completions = append(completions, comp)
		}
	}
	err := c.SetSnapshot(ctx, nodeID, newSnapshot)

	if err != nil {
		for _, comp := range completions {
			c.completionCbs.RemoveTypeVersionCompletion(comp)
		}
		return err
	}
	for _, completion := range immediateCompletions {
		if completion.completeUnsentCompletions {
			c.completionCbs.CompleteUnsentPendingCompletions(nodeID, completion.typeURL, nil)
		}
		completion.comp.Complete(completion.err)
	}

	return nil
}

func (c *cacheImpl) ClearSnapshot(nodeID string) {
	c.SnapshotCache.ClearSnapshot(nodeID)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resourcesInSnapshot[nodeID] = &xds.Resources{}
}

func normalizeCustomWildcardRequest(request *cache.Request, sub cache.Subscription) *cache.Request {
	if request == nil || sub == nil || !sub.IsWildcard() || len(request.GetResourceNames()) == 0 {
		return request
	}
	switch request.GetTypeUrl() {
	case NetworkPolicyTypeURL, NetworkPolicyHostsTypeURL:
		normalized := proto.Clone(request).(*cache.Request)
		normalized.ResourceNames = nil
		return normalized
	default:
		return request
	}
}

func (c *cacheImpl) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	if request != nil && request.GetTypeUrl() == envoy_resource.SecretType && len(request.GetResourceNames()) == 0 {
		c.logger.Debug("Ignoring empty ADS SDS watch")
		return func() {}, nil
	}
	request = normalizeCustomWildcardRequest(request, sub)
	if request != nil && c.strictAdsMode && len(c.bootstrapEndpoints) != 0 {
		return c.createBootstrapWatch(request, sub, respChan)
	}
	return c.SnapshotCache.CreateWatch(request, sub, respChan)
}

func (c *cacheImpl) normalizeBootstrapEndpointRequest(request *cache.Request, sub cache.Subscription) *cache.Request {
	if !c.strictAdsMode || len(c.bootstrapEndpoints) == 0 || request.GetTypeUrl() != envoy_resource.EndpointType || len(request.GetResourceNames()) == 0 {
		return request
	}
	if sub != nil && sub.IsWildcard() {
		return request
	}

	bootstrapOnly := true
	for _, name := range request.ResourceNames {
		if !slices.Contains(c.bootstrapEndpoints, name) {
			bootstrapOnly = false
			break
		}
	}
	if bootstrapOnly {
		// Static EDS clusters initialize before CDS. Waiting for every CDS
		// endpoint name here would keep the bootstrap cluster warming.
		normalized := proto.Clone(request).(*cache.Request)
		normalized.ResourceNames = nil
		return normalized
	}

	var normalized *cache.Request
	for _, name := range c.bootstrapEndpoints {
		if !slices.Contains(request.ResourceNames, name) {
			if normalized == nil {
				normalized = proto.Clone(request).(*cache.Request)
			}
			// A DaemonSet pod may still have the old bootstrap during rollout.
			// Exempt bootstrap names from the cache's completeness check, but
			// still require all ordinary backend names in a strict ADS request.
			normalized.ResourceNames = append(normalized.ResourceNames, name)
		}
	}
	if normalized != nil {
		return normalized
	}
	return request
}

// All resource types on an ADS stream must use the same relay. Relaying only
// bootstrap EDS would let later LDS responses overtake it during publication.
type bootstrapResponseStream struct {
	responses chan cache.Response
	done      chan struct{}
	stopped   chan struct{}
	watches   map[*cache.Request]*bootstrapResponseWatch // guarded by bootstrapMutex
}

type bootstrapResponseWatch struct {
	request   *cache.Request
	requested map[string]struct{}
	done      chan struct{}
	mutex     lock.Mutex
}

func (c *cacheImpl) createBootstrapWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (func(), error) {
	normalized := c.normalizeBootstrapEndpointRequest(request, sub)
	watch := &bootstrapResponseWatch{request: request, done: make(chan struct{})}
	if normalized == request {
		// A caller may reuse its request after cancellation. Give each cache
		// watch its own key so a queued old response cannot match the new watch.
		normalized = proto.Clone(request).(*cache.Request)
	} else {
		watch.requested = make(map[string]struct{}, len(request.ResourceNames))
		for _, name := range request.ResourceNames {
			watch.requested[name] = struct{}{}
		}
	}

	c.bootstrapMutex.Lock()
	if c.bootstrapStreams == nil {
		c.bootstrapStreams = make(map[chan cache.Response]*bootstrapResponseStream)
	}
	stream, exists := c.bootstrapStreams[respChan]
	if !exists {
		stream = &bootstrapResponseStream{
			responses: make(chan cache.Response, max(cap(respChan), int(cache_types.UnknownType))),
			done:      make(chan struct{}),
			stopped:   make(chan struct{}),
			watches:   make(map[*cache.Request]*bootstrapResponseWatch),
		}
		c.bootstrapStreams[respChan] = stream
	}
	stream.watches[normalized] = watch
	c.bootstrapMutex.Unlock()
	if !exists {
		go c.relayBootstrapResponses(stream, respChan)
	}

	cancelWatch, err := c.SnapshotCache.CreateWatch(normalized, sub, stream.responses)
	cancel := sync.OnceFunc(func() {
		close(watch.done)
		if cancelWatch != nil {
			cancelWatch()
		}
		// Ordered ADS drains queued responses after cancelling the old watch.
		// Wait for any in-flight send before that drain, even if other resource
		// watches keep this stream's relay alive.
		watch.mutex.Lock()
		watch.mutex.Unlock()
		c.bootstrapMutex.Lock()
		delete(stream.watches, normalized)
		last := len(stream.watches) == 0
		if last {
			delete(c.bootstrapStreams, respChan)
			close(stream.done)
		}
		c.bootstrapMutex.Unlock()
		if last {
			<-stream.stopped
		}
	})
	if err != nil {
		cancel()
		return nil, err
	}
	return cancel, nil
}

func (c *cacheImpl) relayBootstrapResponses(stream *bootstrapResponseStream, respChan chan cache.Response) {
	defer close(stream.stopped)
	for {
		select {
		case <-stream.done:
			return
		case response := <-stream.responses:
			c.bootstrapMutex.Lock()
			watch := stream.watches[response.GetRequest()]
			c.bootstrapMutex.Unlock()
			if watch != nil {
				watch.forward(response, respChan)
			}
		}
	}
}

func (w *bootstrapResponseWatch) forward(response cache.Response, respChan chan cache.Response) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	select {
	case <-w.done:
		return
	default:
	}
	select {
	case <-w.done:
	case respChan <- &bootstrapEndpointResponse{Response: response, request: w.request, requested: w.requested}:
	}
}

// bootstrapEndpointResponse restores the caller's request after normalization.
// When bootstrap names were added or removed, filter both the wire response and
// returned-resource bookkeeping back to the client's actual subscription.
type bootstrapEndpointResponse struct {
	cache.Response
	request   *cache.Request
	requested map[string]struct{}
}

func (r *bootstrapEndpointResponse) GetRequest() *cache.Request { return r.request }

func (r *bootstrapEndpointResponse) GetReturnedResources() map[string]string {
	if r.requested == nil {
		return r.Response.GetReturnedResources()
	}
	returned := maps.Clone(r.Response.GetReturnedResources())
	maps.DeleteFunc(returned, func(name, _ string) bool {
		_, requested := r.requested[name]
		return !requested
	})
	return returned
}

func (r *bootstrapEndpointResponse) GetDiscoveryResponse() (*discovery.DiscoveryResponse, error) {
	if r.requested == nil {
		return r.Response.GetDiscoveryResponse()
	}
	response, err := r.Response.GetDiscoveryResponse()
	if err != nil {
		return nil, err
	}
	for name := range r.Response.GetReturnedResources() {
		if _, requested := r.requested[name]; requested {
			continue
		}
		filtered := proto.Clone(response).(*discovery.DiscoveryResponse)
		filtered.Resources = filtered.Resources[:0]
		for _, resource := range response.Resources {
			var assignment envoy_config_endpoint.ClusterLoadAssignment
			if err := resource.UnmarshalTo(&assignment); err != nil {
				return nil, fmt.Errorf("decode bootstrap EDS response: %w", err)
			}
			if _, requested := r.requested[assignment.ClusterName]; requested {
				filtered.Resources = append(filtered.Resources, resource)
			}
		}
		return filtered, nil
	}
	return response, nil
}

func (c *cacheImpl) GetAllResources(nodeID string) *xds.Resources {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.resourcesInSnapshot[nodeID]
}

func (c *cacheImpl) AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool {
	for _, resourceType := range snapshotResourceTypes {
		if left.GetVersion(resourceType) != right.GetVersion(resourceType) {
			return true
		}
	}
	return false
}
