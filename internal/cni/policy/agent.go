package policy

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/ezgamehost/ezgh-cni/internal/cni/nft"
)

type Options struct {
	Kube      kubernetes.Interface
	Node      string // this node's name (the pod's spec.nodeName)
	Log       *slog.Logger
	ReadyFile string // exists while the last apply succeeded (the container's readiness probe); "" none

	// Zero values are the node's; tests set them.
	Veths     func() (map[netip.Addr]string, error) // nil: HostVeths
	Apply     func(context.Context, string) error   // nil: nft.Replace into Table
	Debounce  time.Duration                         // 0: 100 ms
	RetryBase time.Duration                         // a failed apply retries after this, doubling to 30 s; 0: 1 s
}

// vethRetry is how often a targeted local pod whose veth isn't found yet is looked for again.
const vethRetry = time.Second

// Run keeps the table in step with the API until ctx ends. Informers watch Pods, Namespaces and
// NetworkPolicies (no resync: nothing is listed on a timer), caching only what Compile reads, and
// an update that changes none of it is ignored. A change arms a 100 ms timer and the whole table is
// rebuilt and applied when it fires, once per batch, and only when it differs. The table stays in
// place when the agent stops, so policies hold across a restart.
func Run(ctx context.Context, o Options) error {
	if o.Veths == nil {
		o.Veths = HostVeths
	}
	if o.Apply == nil {
		o.Apply = func(ctx context.Context, rs string) error { return nft.Replace(ctx, Table, rs) }
	}
	if o.Debounce == 0 {
		o.Debounce = 100 * time.Millisecond
	}
	if o.RetryBase == 0 {
		o.RetryBase = time.Second
	}
	f := informers.NewSharedInformerFactoryWithOptions(o.Kube, 0, informers.WithTransform(transform))
	pods, nss, pols := f.Core().V1().Pods(), f.Core().V1().Namespaces(), f.Networking().V1().NetworkPolicies()
	kick := make(chan struct{}, 1)
	poke := func(any) {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	h := cache.ResourceEventHandlerFuncs{AddFunc: poke, DeleteFunc: poke, UpdateFunc: func(old, n any) {
		if changed(old, n) {
			poke(n)
		}
	}}
	for _, i := range []cache.SharedIndexInformer{pods.Informer(), nss.Informer(), pols.Informer()} {
		if _, err := i.AddEventHandler(h); err != nil {
			return err
		}
	}
	f.Start(ctx.Done())
	defer f.Shutdown()
	if !cache.WaitForCacheSync(ctx.Done(), pods.Informer().HasSynced, nss.Informer().HasSynced, pols.Informer().HasSynced) {
		return nil // ctx ended
	}
	poke(nil)

	timer := time.NewTimer(0)
	<-timer.C
	armed, last, backoff := false, "", o.RetryBase
	var lastMissing []string
	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-kick:
			if !armed {
				timer.Reset(o.Debounce)
				armed = true
			}
		case <-timer.C:
			armed = false
			rs, missing, err := build(o, pods.Lister(), nss.Lister(), pols.Lister())
			if err == nil && rs != last {
				err = o.Apply(ctx, rs)
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				o.Log.Error("policy: applying the table failed, retrying", "error", err.Error(), "retryIn", backoff.String())
				ready(o, false)
				timer.Reset(backoff)
				armed = true
				backoff = min(2*backoff, 30*time.Second)
				continue
			}
			last, backoff = rs, o.RetryBase
			ready(o, true)
			if !slices.Equal(missing, lastMissing) && len(missing) > 0 {
				o.Log.Warn("policy: no host veth yet for pods a policy targets; looking again each second", "pods", missing)
			}
			lastMissing = missing
			if len(missing) > 0 {
				timer.Reset(vethRetry)
				armed = true
			}
		}
	}
}

func ready(o Options, ok bool) {
	if o.ReadyFile == "" {
		return
	}
	var err error
	if ok {
		err = os.WriteFile(o.ReadyFile, nil, 0o644)
	} else if err = os.Remove(o.ReadyFile); errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		o.Log.Error("policy: readiness file", "error", err.Error())
	}
}

// build reads the informers' caches into a State and compiles it. missing names the local pods
// a policy targets whose host veth isn't found.
func build(o Options, pods corelisters.PodLister, nss corelisters.NamespaceLister, pols networkinglisters.NetworkPolicyLister) (string, []string, error) {
	veths, err := o.Veths()
	if err != nil {
		return "", nil, err
	}
	all, err := pods.List(labels.Everything())
	if err != nil {
		return "", nil, err
	}
	nsl, err := nss.List(labels.Everything())
	if err != nil {
		return "", nil, err
	}
	pl, err := pols.List(labels.Everything())
	if err != nil {
		return "", nil, err
	}
	s := State{Namespaces: map[string]map[string]string{}}
	for _, n := range nsl {
		s.Namespaces[n.Name] = n.Labels
	}
	for _, p := range pl {
		s.Policies = append(s.Policies, *p)
	}
	var missing []string
	for _, kp := range all {
		// A finished pod's address may already be another pod's.
		if kp.Status.Phase == corev1.PodSucceeded || kp.Status.Phase == corev1.PodFailed {
			continue
		}
		p := Pod{Namespace: kp.Namespace, Name: kp.Name, Labels: kp.Labels, HostNetwork: kp.Spec.HostNetwork}
		for _, ip := range kp.Status.PodIPs {
			if a, err := netip.ParseAddr(ip.IP); err == nil {
				p.IPs = append(p.IPs, a)
			}
		}
		// Named ports as upstream's FindPort: containers and restartable (sidecar) init containers.
		cs := slices.Clone(kp.Spec.Containers)
		for _, c := range kp.Spec.InitContainers {
			if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				cs = append(cs, c)
			}
		}
		for _, c := range cs {
			for _, cp := range c.Ports {
				if cp.Name != "" {
					p.Ports = append(p.Ports, NamedPort{Name: cp.Name, Protocol: string(cp.Protocol), Port: cp.ContainerPort})
				}
			}
		}
		s.All = append(s.All, p)
		if kp.Spec.NodeName == o.Node {
			for _, a := range p.IPs {
				if v, ok := veths[a]; ok {
					p.Veth = v
					break
				}
			}
			if p.Veth == "" && len(p.IPs) > 0 && Targeted(s.Policies, p) {
				missing = append(missing, p.Namespace+"/"+p.Name)
			}
			s.Local = append(s.Local, p)
		}
	}
	slices.Sort(missing)
	return Compile(s), missing, nil
}

// transform keeps only what build reads (plus the resource version), so the cluster-wide pod cache
// holds a few fields per pod. Init containers stay only when restartable (they serve named ports).
func transform(obj any) (any, error) {
	switch o := obj.(type) {
	case *corev1.Pod:
		p := &corev1.Pod{ObjectMeta: trimMeta(o.ObjectMeta),
			Spec:   corev1.PodSpec{NodeName: o.Spec.NodeName, HostNetwork: o.Spec.HostNetwork},
			Status: corev1.PodStatus{Phase: o.Status.Phase, PodIPs: o.Status.PodIPs}}
		for _, c := range o.Spec.Containers {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c.Name, Ports: c.Ports})
		}
		for _, c := range o.Spec.InitContainers {
			if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: c.Name, RestartPolicy: c.RestartPolicy, Ports: c.Ports})
			}
		}
		return p, nil
	case *corev1.Namespace:
		return &corev1.Namespace{ObjectMeta: trimMeta(o.ObjectMeta)}, nil
	case *networkingv1.NetworkPolicy:
		return &networkingv1.NetworkPolicy{ObjectMeta: trimMeta(o.ObjectMeta), Spec: o.Spec}, nil
	}
	return obj, nil
}

func trimMeta(m metav1.ObjectMeta) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: m.Name, Namespace: m.Namespace, Labels: m.Labels, ResourceVersion: m.ResourceVersion}
}

// changed reports whether an update touched anything transform keeps besides the resource version.
func changed(old, n any) bool {
	a, ok1 := old.(runtime.Object)
	b, ok2 := n.(runtime.Object)
	if !ok1 || !ok2 {
		return true
	}
	a, b = a.DeepCopyObject(), b.DeepCopyObject()
	for _, x := range []runtime.Object{a, b} {
		if m, err := meta.Accessor(x); err == nil {
			m.SetResourceVersion("")
		}
	}
	return !equality.Semantic.DeepEqual(a, b)
}
