package ipamd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipam"
	"github.com/ezgamehost/ezgh-cni/internal/cni/netapi"
	"github.com/ezgamehost/ezgh-cni/internal/nodeauth/imds"
)

// Intent kinds: an assign per family, or the one unassign.
const (
	ipv4     = "ipv4"
	ipv6     = "ipv6"
	unassign = "unassign"
)

var errRealize = errors.New("metadata didn't show the change in time")

type result struct {
	kind string
	in   *imds.Instance // metadata after the change realized
	err  error
}

// start runs at most one network intent at a time: IPv6 first (a pod needs both), then IPv4,
// then a release.
func (d *daemon) start(ctx context.Context, now time.Time) {
	if !d.known {
		d.nextCheck = time.Time{}
		return
	}
	act := d.pool.Want(now)
	// Before asking for another /28, or while ADDs wait (at the cap no assign helps), take back gone pods' addresses.
	if (act.Assign4 || len(d.waiters) > 0) && d.reap(time.Now()) { // Release is stamped with the real time, not the loop's
		act = d.pool.Want(now)
	}
	d.nextCheck = act.NextCheck
	if d.busy {
		return
	}
	ready := func(kind string) bool { return !now.Before(d.notBefore[kind]) }
	switch {
	case act.Assign6 && ready(ipv6):
		d.launch(ctx, ipv6, nil)
	case act.Assign4 && ready(ipv4):
		d.launch(ctx, ipv4, nil)
	case d.unassigning != nil && ready(unassign):
		d.launch(ctx, unassign, d.unassigning)
	case act.Unassign != nil && ready(unassign):
		// Kept on disk with its key before the POST: a restarted ipamd fences and re-drives it.
		d.pool.Reserve(act.Unassign.CIDR)
		d.unassigning, d.keys[unassign] = act.Unassign, rand.Text()
		if err := d.save(); err != nil {
			d.o.Log.Error("keeping the unassign", "error", err)
			d.pool.Unreserve(act.Unassign.CIDR)
			d.unassigning = nil
			return
		}
		d.launch(ctx, unassign, act.Unassign)
	}
}

func (d *daemon) launch(ctx context.Context, kind string, pr *ipam.Prefix) {
	if d.keys[kind] == "" {
		d.keys[kind] = rand.Text()
	}
	key := d.keys[kind]
	d.busy = true
	go func() {
		ctx, cancel := context.WithTimeout(ctx, d.o.Timing.Realize)
		defer cancel()
		var op netapi.Operation
		var err error
		if pr == nil {
			op, err = d.net.Assign(ctx, d.iface.ID, kind, key)
		} else {
			op, err = d.net.Unassign(ctx, d.iface.ID, ipv4, pr.CIDR.String(), pr.Generation, key)
		}
		res := result{kind: kind, err: err}
		if err == nil {
			res.in, res.err = d.realize(ctx, op, pr == nil)
		}
		d.results <- res
	}()
}

// realize waits for the operation, honouring Retry-After, then for metadata to list its prefix
// (an assign) or no longer list it (an unassign). Only then does the pool change.
func (d *daemon) realize(ctx context.Context, op netapi.Operation, assign bool) (*imds.Instance, error) {
	sleep := func(t time.Duration) error {
		select {
		case <-ctx.Done():
			return errRealize
		case <-time.After(t):
			return nil
		}
	}
	for op.Status == "queued" || op.Status == "running" {
		if err := sleep(max(op.RetryAfter, d.o.Timing.Poll)); err != nil {
			return nil, err
		}
		var err error
		if op, err = d.net.Operation(ctx, op.ID); err != nil {
			return nil, err
		}
	}
	if op.Status != "succeeded" {
		return nil, fmt.Errorf("network operation %s ended %q", op.ID, op.Status)
	}
	want, err := netip.ParsePrefix(op.Address)
	if err != nil {
		return nil, fmt.Errorf("network operation %s names no prefix (%q)", op.ID, op.Address)
	}
	for {
		in, err := d.o.IMDS.Instance(ctx)
		if err == nil {
			for _, i := range in.Interfaces {
				if i.ID != d.iface.ID || i.DelegatedPrefixes == nil {
					continue
				}
				listed := false
				for _, o := range *i.DelegatedPrefixes {
					p, err := netip.ParsePrefix(o.Prefix)
					listed = listed || err == nil && p.Masked() == want.Masked()
				}
				if listed == assign {
					return &in, nil
				}
			}
		}
		if err := sleep(d.o.Timing.Poll); err != nil {
			return nil, err
		}
	}
}

func (d *daemon) finish(ctx context.Context, res result) {
	d.busy = false
	now := time.Now()
	kind := res.kind
	if res.err == nil {
		delete(d.keys, kind)
		delete(d.backoff, kind)
		delete(d.notBefore, kind)
		if kind == unassign {
			d.o.Log.Info("released a prefix", "prefix", d.unassigning.CIDR.String())
			d.unassigning = nil
			if err := d.save(); err != nil {
				d.o.Log.Error("allocations", "error", err)
			}
		} else {
			delete(d.cause, kind)
			delete(d.episode, kind)
		}
		d.apply(ctx, *res.in)
		return
	}
	var ae *netapi.APIError
	isAPI := errors.As(res.err, &ae)
	if isAPI && ae.Status == http.StatusTooManyRequests {
		// The same intent, its key kept, after the server's wait.
		d.notBefore[kind] = now.Add(max(ae.RetryAfter, time.Second))
		return
	}
	// No answer, a 5xx, or another operation on the interface: the same intent, its key kept,
	// after a backoff. Anything else was refused or failed: a retry is a new intent.
	transient := !isAPI || ae.Status >= 500 || ae.Code == "address_operation_in_progress"
	if !transient {
		delete(d.keys, kind)
	}
	d.backoff[kind] = min(max(d.backoff[kind]*2, d.o.Timing.BackoffBase), d.o.Timing.BackoffCap)
	d.notBefore[kind] = now.Add(d.o.Jitter(d.backoff[kind]))
	d.o.Log.Warn("prefix change failed", "kind", kind, "error", res.err, "retryIn", d.notBefore[kind].Sub(now).String())
	if transient {
		return // ADDs keep waiting; an unassign stays reserved
	}
	if kind == unassign {
		// The prefix is allocatable again; on a generation conflict, at metadata's generation.
		d.pool.Unreserve(d.unassigning.CIDR)
		d.unassigning = nil
		if err := d.save(); err != nil {
			d.o.Log.Error("allocations", "error", err)
		}
		if ae.Code == "address_generation_conflict" {
			delete(d.notBefore, kind)
			d.refresh(ctx)
		}
		return
	}
	f := d.describe(kind, ae)
	d.cause[kind] = f
	if d.episode[kind] != f.reason {
		d.episode[kind] = f.reason
		d.events.Event(d.nodeRef, corev1.EventTypeWarning, f.reason, f.message)
	}
	d.serveWaiters(now)
}

func (d *daemon) refresh(ctx context.Context) {
	in, err := d.o.IMDS.Instance(ctx)
	if err != nil {
		d.unknown(time.Now())
		return
	}
	d.apply(ctx, in)
}

func (d *daemon) describe(family string, ae *netapi.APIError) *failure {
	name, cidr, size := "IPv4", d.iface.Subnet.IPv4CIDR, "/28"
	if family == ipv6 {
		name, cidr, size = "IPv6", d.iface.Subnet.IPv6CIDR, "/80"
	}
	switch {
	case ae.Status == http.StatusForbidden:
		return &failure{"PrefixAssignDenied", fmt.Sprintf("no free %s address: the node's Bot may not assign prefixes (network.networkInterfaces.assignPrivatePrefix)", name)}
	case ae.Code == "prefix_unavailable":
		return &failure{"PrefixUnavailable", fmt.Sprintf("no free %s address: subnet %s has no free %s (prefix_unavailable)", name, cidr, size)}
	case ae.Code == "private_address_limit_exceeded":
		return &failure{"PrefixUnavailable", fmt.Sprintf("no free %s address: the network interface or its VPC holds its limit of delegated prefixes (private_address_limit_exceeded)", name)}
	default:
		return &failure{"PrefixAssignFailed", fmt.Sprintf("no free %s address: assigning a %s failed (%s)", name, size, ae.Code)}
	}
}
