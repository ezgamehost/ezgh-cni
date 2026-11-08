// Package ipamd is the node's address daemon (spec "Pod networking: ezgh-vpc-cni"): it assigns
// delegated prefixes to the node's private interface through network-api as the node's Bot,
// holds only what instance metadata reads back, hands pods addresses over a unix socket, and owns
// the base nftables table, the per-prefix policy rules and the pod identity link. One goroutine
// owns the pool; network calls run one at a time beside it, and a timer fires when the pool next
// has something to decide. Nothing is read periodically.
package ipamd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipam"
	"github.com/ezgamehost/ezgh-cni/internal/cni/netapi"
	"github.com/ezgamehost/ezgh-cni/internal/cni/nft"
	"github.com/ezgamehost/ezgh-cni/internal/nodeauth"
	"github.com/ezgamehost/ezgh-cni/internal/nodeauth/imds"
)

const (
	Dir      = "/run/ezgh-vpc-cni" // tmpfs: survives an ipamd restart, not a reboot
	Conflist = "/etc/cni/net.d/10-ezgh-vpc-cni.conflist"
)

// Netlink is what ipamd changes in the kernel besides nftables.
type Netlink interface {
	// LinkByMAC names the link with this MAC.
	LinkByMAC(mac string) (string, error)
	// EnsurePIA keeps dummy link ezgh-pia up with 169.254.170.23/32.
	EnsurePIA() error
	// SetPrefixRules makes the pref 1536 rules exactly `from <prefix> lookup <table> suppress_prefixlength 0`.
	SetPrefixRules(prefixes []netip.Prefix, table int) error
	// HostVeths maps each pod address to its host veth, from the plugin's `<addr> dev ezp…` routes.
	HostVeths() (map[netip.Addr]string, error)
}

// staleAfter is how old an allocation must be before a missing veth means its pod is gone: longer
// than an ADD can wait for its address plus a network operation, so a pod still being wired is kept.
func (t Timing) staleAfter() time.Duration { return t.AddWait + t.Realize }

// Timing is ipamd's waits; tests shorten them.
type Timing struct {
	AddWait     time.Duration // an ADD waits this long for a first prefix
	Realize     time.Duration // an operation plus metadata listing its result
	Poll        time.Duration // metadata, while waiting for a realized change
	BackoffBase time.Duration // doubling to BackoffCap, full jitter
	BackoffCap  time.Duration
	UnknownMin  time.Duration // metadata's delegatedPrefixes null: retry, doubling to UnknownMax
	UnknownMax  time.Duration
}

var (
	DefaultTiming = Timing{AddWait: time.Minute, Realize: 2 * time.Minute, Poll: 200 * time.Millisecond,
		BackoffBase: 10 * time.Second, BackoffCap: 5 * time.Minute, UnknownMin: time.Second, UnknownMax: 10 * time.Second}
	DefaultPool = ipam.Config{MaxPrefixes4: 7, Warm: 1, ReleaseAfter: 30 * time.Minute, Cooldown: 30 * time.Second}
)

type Options struct {
	IMDS   *imds.Client
	Kube   kubernetes.Interface                // events, when Events is nil
	Events record.EventRecorder                // on the Node
	Exec   Netlink                             // nil: the kernel
	NFT    func(context.Context, string) error // nil: nft.Apply
	Log    *slog.Logger

	// Zero values are the node's; tests set them.
	Facts     *nodeauth.JoinFacts // nil: nodeauth.ReadJoinFacts
	NetBase   string
	NetHTTP   *http.Client
	Dir       string
	Conflist  string
	Addresses ipam.Config // the pool's sizes and times
	Timing    Timing
	Jitter    func(time.Duration) time.Duration // nil: uniform in [0, d]
}

// Run starts ipamd and serves until ctx ends. A node it can't serve (not exactly one private
// interface, no cluster, no organization) is an error.
func Run(ctx context.Context, o Options) error {
	if o.Exec == nil {
		o.Exec = Kernel{}
	}
	if o.NFT == nil {
		o.NFT = nft.Apply
	}
	if o.Dir == "" {
		o.Dir = Dir
	}
	if o.Conflist == "" {
		o.Conflist = Conflist
	}
	if o.Addresses == (ipam.Config{}) {
		o.Addresses = DefaultPool
	}
	if o.Timing == (Timing{}) {
		o.Timing = DefaultTiming
	}
	if o.Jitter == nil {
		o.Jitter = func(d time.Duration) time.Duration { return rand.N(d + 1) }
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	facts := o.Facts
	if facts == nil {
		f, err := nodeauth.ReadJoinFacts()
		if err != nil {
			return fmt.Errorf("ipamd: the node's join facts: %w", err)
		}
		facts = &f
	}
	if !strings.HasPrefix(facts.Cluster, "kcl_") {
		return fmt.Errorf("ipamd: join facts name no cluster (%q)", facts.Cluster)
	}
	in, err := o.IMDS.Instance(ctx)
	if err != nil {
		return fmt.Errorf("ipamd: instance metadata: %w", err)
	}
	priv, err := privateInterface(in)
	if err != nil {
		return err
	}
	token, err := o.IMDS.Identity(ctx, "kubernetes:"+facts.Cluster)
	if err != nil {
		return fmt.Errorf("ipamd: identity token: %w", err)
	}
	org, err := orgClaim(token)
	if err != nil {
		return err
	}
	link, err := o.Exec.LinkByMAC(priv.MAC)
	if err != nil {
		return fmt.Errorf("ipamd: the private interface %s (%s): %w", priv.ID, priv.MAC, err)
	}
	if err := o.Exec.EnsurePIA(); err != nil {
		return fmt.Errorf("ipamd: link ezgh-pia: %w", err)
	}
	project := in.ProjectID
	if project == "" {
		project = in.Project
	}
	node := "ins-" + strings.TrimPrefix(in.ID, "ins_")
	events := o.Events
	if events == nil {
		b := record.NewBroadcaster(record.WithContext(ctx))
		defer b.Shutdown()
		if o.Kube != nil {
			b.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: o.Kube.CoreV1().Events("")})
		}
		events = b.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "ezgh-vpc-cni", Host: node})
	}
	d := &daemon{o: o, link: link, iface: priv, table: 100 + *priv.DeviceIndex, events: events,
		nodeRef: &corev1.ObjectReference{Kind: "Node", Name: node, UID: types.UID(node)},
		pool:    ipam.New(o.Addresses),
		net: &netapi.Client{Base: o.NetBase, Org: org, Project: project, HTTP: o.NetHTTP,
			Key: func(ctx context.Context) (string, error) {
				c, err := o.IMDS.Credentials(ctx)
				return c.APIKey, err
			}},
		reqs: make(chan request), results: make(chan result, 1),
		keys: map[string]string{}, backoff: map[string]time.Duration{}, notBefore: map[string]time.Time{},
		cause: map[string]*failure{}, episode: map[string]string{}}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return err
	}
	kept, err := d.load()
	if err != nil {
		return err
	}
	d.pool.Restore(kept.State)
	if u := kept.Unassign; u != nil {
		d.pool.Reserve(u.CIDR)
		d.unassigning, d.keys[unassign] = &u.Prefix, u.Key
	}
	d.reap(time.Now()) // after the unassign is back: its save keeps it
	// A conflist from an older ipamd is replaced once the pod network is up.
	b, err := os.ReadFile(o.Conflist)
	d.conflist = err == nil && string(b) == conflist
	d.apply(ctx, in)
	stop, err := d.serve(filepath.Join(o.Dir, "ipamd.sock"))
	if err != nil {
		return err
	}
	defer stop()
	o.Log.Info("ipamd serving", "interface", priv.ID, "link", link, "table", d.table)
	return d.loop(ctx)
}

func privateInterface(in imds.Instance) (imds.Interface, error) {
	var found []imds.Interface
	for _, i := range in.Interfaces {
		if i.Kind == "private" {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		return imds.Interface{}, fmt.Errorf("ipamd: a node needs exactly one private network interface, and %s has %d", in.ID, len(found))
	}
	if found[0].DeviceIndex == nil || found[0].Subnet == nil || found[0].MTU == 0 {
		return imds.Interface{}, fmt.Errorf("ipamd: metadata doesn't describe the private interface %s yet", found[0].ID)
	}
	return found[0], nil
}

// orgClaim reads the org claim of an identity token ipamd fetched from its own metadata: no
// signature check, since nothing else could have answered.
func orgClaim(token string) (string, error) {
	parts := strings.Split(token, ".")
	var claims struct {
		Org string `json:"org"`
	}
	if len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil && json.Unmarshal(b, &claims) == nil && claims.Org != "" {
			return claims.Org, nil
		}
	}
	return "", errors.New("ipamd: the identity token has no org claim")
}

type daemon struct {
	o       Options
	net     *netapi.Client
	events  record.EventRecorder
	nodeRef *corev1.ObjectReference
	link    string
	iface   imds.Interface
	table   int
	pool    *ipam.Pool

	known       bool // metadata listed the interface's prefixes (not null) and the kernel took them
	conflist    bool
	held6       *ipam.Prefix
	unknownWait time.Duration
	retryAt     time.Time // re-read metadata while !known

	reqs    chan request
	results chan result
	waiters []waiter
	busy    bool
	// unassigning is the prefix whose unassign is running or retried; it stays reserved.
	unassigning *ipam.Prefix
	keys        map[string]string // per intent kind: the Idempotency-Key across its retries
	backoff     map[string]time.Duration
	notBefore   map[string]time.Time
	cause       map[string]*failure // per family: why the last assign was refused
	episode     map[string]string   // per family: the event reason already recorded
	nextCheck   time.Time
}

// failure is a refused assign, as ADD and the Node's event name it.
type failure struct{ reason, message string }

type waiter struct {
	key      string
	deadline time.Time
	reply    chan reply
}

func (d *daemon) loop(ctx context.Context) error {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now := time.Now()
		if !d.known && !now.Before(d.retryAt) {
			if in, err := d.o.IMDS.Instance(ctx); err == nil {
				d.apply(ctx, in)
			} else {
				d.o.Log.Warn("instance metadata", "error", err)
				d.unknown(now)
			}
		}
		d.start(ctx, now)
		d.serveWaiters(now) // a DEL or a cooldown's end may have freed an address
		d.expire(now)
		timer.Reset(d.wake(now))
		select {
		case <-ctx.Done():
			for _, w := range d.waiters {
				w.reply <- reply{err: errors.New("ipamd is stopping")}
			}
			return nil
		case r := <-d.reqs:
			d.handle(r)
		case res := <-d.results:
			d.finish(ctx, res)
		case <-timer.C:
		}
	}
}

// wake is how long until the loop has something to do.
func (d *daemon) wake(now time.Time) time.Duration {
	next := now.Add(time.Hour)
	at := func(t time.Time) {
		if !t.IsZero() && t.Before(next) {
			next = t
		}
	}
	at(d.nextCheck)
	if !d.known {
		at(d.retryAt)
	}
	for _, t := range d.notBefore {
		at(t)
	}
	for _, w := range d.waiters {
		at(w.deadline)
	}
	return max(next.Sub(now), time.Millisecond)
}

// apply takes metadata's view of the interface: the pool holds exactly the realized prefixes,
// and the kernel's rules and table follow.
func (d *daemon) apply(ctx context.Context, in imds.Instance) {
	now := time.Now()
	var iface *imds.Interface
	for i := range in.Interfaces {
		if in.Interfaces[i].ID == d.iface.ID {
			iface = &in.Interfaces[i]
		}
	}
	if iface == nil || iface.DelegatedPrefixes == nil {
		d.unknown(now)
		return
	}
	var v4 []ipam.Prefix
	var v6 *ipam.Prefix
	var all, all4, all6 []netip.Prefix
	for _, o := range *iface.DelegatedPrefixes {
		pr, err := netip.ParsePrefix(o.Prefix)
		switch {
		case err != nil:
			continue
		case pr.Addr().Is4() && pr.Bits() == 28:
			v4 = append(v4, ipam.Prefix{CIDR: pr, Generation: o.Generation})
			all4 = append(all4, pr)
		case pr.Addr().Is6() && pr.Bits() == 80 && v6 == nil:
			v6 = &ipam.Prefix{CIDR: pr, Generation: o.Generation}
			all6 = append(all6, pr)
		default:
			continue
		}
		all = append(all, pr)
	}
	if err := d.o.Exec.SetPrefixRules(all, d.table); err != nil {
		d.o.Log.Error("policy rules", "error", err)
		d.unknown(now)
		return
	}
	if err := d.o.NFT(ctx, nft.Base(nft.Rules{PrivateLink: d.link, Prefixes4: all4, Prefixes6: all6})); err != nil {
		d.o.Log.Error("nftables", "error", err)
		d.unknown(now)
		return
	}
	d.pool.SetHeld(v4, v6, now)
	d.held6, d.known, d.unknownWait = v6, true, 0
	if !d.conflist && v6 != nil && len(v4) > 0 {
		if err := writeFile(d.o.Conflist, []byte(conflist), 0o644); err != nil {
			d.o.Log.Error("conflist", "error", err)
		} else {
			d.conflist = true
			d.o.Log.Info("ready", "conflist", d.o.Conflist)
		}
	}
	d.serveWaiters(now)
}

// reap releases the allocations whose pod is gone: no ezp* route on this node for its IPv4 and
// older than staleAfter. Nothing tells ipamd when a pod's wiring failed or a DEL never came; the
// missing route does. A failed route walk releases nothing. It reports whether it released any.
func (d *daemon) reap(now time.Time) bool {
	veths, err := d.o.Exec.HostVeths()
	if err != nil {
		d.o.Log.Warn("pod routes", "error", err)
		return false
	}
	released := false
	for key, a := range d.pool.State().Allocs {
		if _, ok := veths[a.V4]; ok || now.Sub(a.At) < d.o.Timing.staleAfter() {
			continue
		}
		d.pool.Release(key, now) // deleting during range is safe
		d.o.Log.Info("released the address of a gone pod", "allocation", key, "ipv4", a.V4.String())
		released = true
	}
	if released {
		if err := d.save(); err != nil {
			d.o.Log.Error("allocations", "error", err)
		}
	}
	return released
}

// unknown leaves the pool as it is and asks metadata again after 1 s, doubling to 10 s.
func (d *daemon) unknown(now time.Time) {
	d.known = false
	d.unknownWait = min(max(d.unknownWait*2, d.o.Timing.UnknownMin), d.o.Timing.UnknownMax)
	d.retryAt = now.Add(d.unknownWait)
}
