// Package ipam is ipamd's address pool: pure and clock-injected. It decides which address a pod
// gets and which prefixes to assign or release; ipamd acts on its decisions. It only ever holds
// prefixes metadata has listed as realized (SetHeld).
package ipam

import (
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"time"
)

type Config struct {
	MaxPrefixes4, Warm     int           // 7, 1
	ReleaseAfter, Cooldown time.Duration // 30m, 30s
}

type Prefix struct {
	CIDR       netip.Prefix `json:"prefix"`
	Generation string       `json:"generation"`
}

type Alloc struct {
	V4 netip.Addr `json:"ipv4"`
	V6 netip.Addr `json:"ipv6"`
	At time.Time  `json:"at,omitempty"` // when Allocate made it; zero in state from an older ipamd
}

// Action is what the pool wants done; NextCheck is when to ask again (zero: only after a change).
type Action struct {
	Assign4, Assign6 bool
	Unassign         *Prefix
	NextCheck        time.Time
}

var ErrNoAddress = errors.New("no free address")

type Pool struct {
	c        Config
	v4       []Prefix
	v6       *Prefix
	allocs   map[string]Alloc
	cooling  map[netip.Addr]time.Time // until
	empty    map[netip.Prefix]time.Time
	reserved map[netip.Prefix]bool
	// surplus is since when more than Warm spares have been held without a break: a prefix is
	// released only after a whole ReleaseAfter of surplus, so a pod coming and going never churns.
	surplus time.Time
	next6   *big.Int
}

func New(c Config) *Pool {
	return &Pool{c: c, allocs: map[string]Alloc{}, cooling: map[netip.Addr]time.Time{}, empty: map[netip.Prefix]time.Time{},
		reserved: map[netip.Prefix]bool{}, next6: big.NewInt(1)}
}

// SetHeld replaces the held prefixes with metadata's realized ones.
func (p *Pool) SetHeld(v4 []Prefix, v6 *Prefix, now time.Time) {
	p.v4 = slices.Clone(v4)
	slices.SortFunc(p.v4, func(a, b Prefix) int { return a.CIDR.Addr().Compare(b.CIDR.Addr()) })
	p.v6 = v6
	held := map[netip.Prefix]bool{}
	for _, pr := range p.v4 {
		held[pr.CIDR] = true
		if _, ok := p.empty[pr.CIDR]; !ok && p.count(pr.CIDR) == 0 {
			p.empty[pr.CIDR] = now
		}
	}
	for pr := range p.empty {
		if !held[pr] {
			delete(p.empty, pr)
		}
	}
	for pr := range p.reserved {
		if !held[pr] {
			delete(p.reserved, pr)
		}
	}
	p.observe(now)
}

// Allocate gives key (containerId/ifName) an IPv4 and an IPv6 address; the same key gets the same
// ones back, dated now: a repeated ADD is wiring them again.
func (p *Pool) Allocate(key string, now time.Time) (Alloc, error) {
	if a, ok := p.allocs[key]; ok {
		a.At = now
		p.allocs[key] = a
		return a, nil
	}
	if p.v6 == nil {
		return Alloc{}, ErrNoAddress
	}
	used := map[netip.Addr]bool{}
	for _, a := range p.allocs {
		used[a.V4], used[a.V6] = true, true
	}
	free := func(a netip.Addr) bool { return !used[a] && !now.Before(p.cooling[a]) }
	// The fullest held /28 with a free address, so the others can empty.
	var v4 netip.Addr
	best := -1
	for _, pr := range p.v4 {
		if p.reserved[pr.CIDR] {
			continue
		}
		n := p.count(pr.CIDR)
		if n <= best {
			continue
		}
		for a := pr.CIDR.Addr(); pr.CIDR.Contains(a); a = a.Next() {
			if free(a) {
				v4, best = a, n
				break
			}
		}
	}
	if !v4.IsValid() {
		return Alloc{}, ErrNoAddress
	}
	v6 := netip.Addr{}
	for i := new(big.Int).Set(p.next6); ; i.Add(i, big.NewInt(1)) {
		a := nth(p.v6.CIDR, i)
		if !p.v6.CIDR.Contains(a) {
			return Alloc{}, ErrNoAddress
		}
		if free(a) {
			v6 = a
			p.next6 = i.Add(i, big.NewInt(1))
			break
		}
	}
	a := Alloc{V4: v4, V6: v6, At: now}
	p.allocs[key] = a
	delete(p.empty, prefixOf(p.v4, v4))
	p.observe(now)
	return a, nil
}

// Release frees key's addresses after Cooldown.
func (p *Pool) Release(key string, now time.Time) {
	a, ok := p.allocs[key]
	if !ok {
		return
	}
	delete(p.allocs, key)
	p.cooling[a.V4], p.cooling[a.V6] = now.Add(p.c.Cooldown), now.Add(p.c.Cooldown)
	if pr := prefixOf(p.v4, a.V4); pr.IsValid() && p.count(pr) == 0 {
		p.empty[pr] = now
	}
	p.observe(now)
}

// State is what ipamd keeps across a restart: the allocations and the addresses still cooling.
type State struct {
	Allocs  map[string]Alloc         `json:"allocations"`
	Cooling map[netip.Addr]time.Time `json:"cooling"`
}

// Restore brings back the state kept across an ipamd restart.
func (p *Pool) Restore(s State) {
	for k, a := range s.Allocs {
		p.allocs[k] = a
		delete(p.empty, prefixOf(p.v4, a.V4))
	}
	for a, until := range s.Cooling {
		p.cooling[a] = until
	}
	p.surplus = time.Time{}
}

// State is the pool's to persist.
func (p *Pool) State() State { return State{Allocs: p.allocs, Cooling: p.cooling} }

// Reserve stops allocating from pr while its unassign runs; SetHeld without pr ends it.
func (p *Pool) Reserve(pr netip.Prefix) { p.reserved[pr] = true }

// Unreserve ends a reservation whose unassign didn't happen.
func (p *Pool) Unreserve(pr netip.Prefix) { delete(p.reserved, pr) }

func (p *Pool) Want(now time.Time) Action {
	p.observe(now)
	var act Action
	spares := p.spares(now)
	act.Assign4 = len(spares) < p.c.Warm && len(p.v4) < p.c.MaxPrefixes4
	act.Assign6 = p.v6 == nil
	consider := func(t time.Time) {
		if t.After(now) && (act.NextCheck.IsZero() || t.Before(act.NextCheck)) {
			act.NextCheck = t
		}
	}
	for _, until := range p.cooling {
		consider(until)
	}
	if len(spares) > p.c.Warm && len(p.reserved) == 0 {
		// The longest-empty spare goes once both it and the surplus are ReleaseAfter old.
		oldest := spares[0]
		for _, pr := range spares[1:] {
			if p.empty[pr.CIDR].Before(p.empty[oldest.CIDR]) {
				oldest = pr
			}
		}
		due := p.empty[oldest.CIDR]
		if p.surplus.After(due) {
			due = p.surplus
		}
		due = due.Add(p.c.ReleaseAfter)
		if !now.Before(due) {
			act.Unassign = &oldest
		} else {
			consider(due)
		}
	}
	return act
}

// spares are held, unreserved /28s with no allocation and no cooling address.
func (p *Pool) spares(now time.Time) []Prefix {
	var out []Prefix
	for _, pr := range p.v4 {
		if p.reserved[pr.CIDR] || p.count(pr.CIDR) > 0 {
			continue
		}
		cool := false
		for a, until := range p.cooling {
			if pr.CIDR.Contains(a) && now.Before(until) {
				cool = true
			}
		}
		if !cool {
			out = append(out, pr)
		}
	}
	return out
}

func (p *Pool) observe(now time.Time) {
	for a, until := range p.cooling {
		if !now.Before(until) {
			delete(p.cooling, a)
		}
	}
	if len(p.spares(now)) <= p.c.Warm {
		p.surplus = time.Time{}
	} else if p.surplus.IsZero() {
		p.surplus = now
	}
}

func (p *Pool) count(pr netip.Prefix) int {
	n := 0
	for _, a := range p.allocs {
		if pr.Contains(a.V4) {
			n++
		}
	}
	return n
}

func prefixOf(held []Prefix, a netip.Addr) netip.Prefix {
	for _, pr := range held {
		if pr.CIDR.Contains(a) {
			return pr.CIDR
		}
	}
	return netip.Prefix{}
}

func nth(pr netip.Prefix, i *big.Int) netip.Addr {
	b := pr.Addr().As16()
	v := new(big.Int).Add(new(big.Int).SetBytes(b[:]), i)
	v.FillBytes(b[:])
	return netip.AddrFrom16(b)
}
