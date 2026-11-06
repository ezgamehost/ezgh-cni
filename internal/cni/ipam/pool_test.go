package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

var (
	t0  = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	cfg = Config{MaxPrefixes4: 7, Warm: 1, ReleaseAfter: 30 * time.Minute, Cooldown: 30 * time.Second}
	v6  = &Prefix{CIDR: netip.MustParsePrefix("fd00:1:2:3:4::/80"), Generation: "1"}
)

func p4(n int) Prefix {
	return Prefix{CIDR: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 1, byte(16 * n)}), 28), Generation: fmt.Sprint(n)}
}

func held(n ...int) []Prefix {
	var out []Prefix
	for _, i := range n {
		out = append(out, p4(i))
	}
	return out
}

func pool(v4 ...int) *Pool {
	p := New(cfg)
	p.SetHeld(held(v4...), v6, t0)
	return p
}

func TestFirstPodWaits(t *testing.T) {
	p := New(cfg)
	if _, err := p.Allocate("c/eth0", t0); !errors.Is(err, ErrNoAddress) {
		t.Fatal(err)
	}
	if a := p.Want(t0); !a.Assign4 || !a.Assign6 || a.Unassign != nil {
		t.Fatalf("%+v", a)
	}
}

func TestAll16Usable(t *testing.T) {
	p := pool(1)
	for i := range 16 {
		a, err := p.Allocate(fmt.Sprint(i), t0)
		if want := netip.AddrFrom4([4]byte{10, 0, 1, byte(16 + i)}); err != nil || a.V4 != want || !v6.CIDR.Contains(a.V6) {
			t.Fatalf("%d: %v %v", i, a, err)
		}
	}
	if _, err := p.Allocate("17", t0); !errors.Is(err, ErrNoAddress) {
		t.Fatal(err)
	}
}

func TestSameKeySameAlloc(t *testing.T) {
	p := pool(1)
	a, _ := p.Allocate("c/eth0", t0)
	b, _ := p.Allocate("c/eth0", t0)
	if a != b || a.V6 == (Alloc{}).V6 {
		t.Fatal(a, b)
	}
}

func TestOneSpareKept(t *testing.T) {
	p := pool(1)
	if a := p.Want(t0); a.Assign4 {
		t.Fatal("assign with a spare held")
	}
	p.Allocate("a", t0)
	if a := p.Want(t0); !a.Assign4 || a.Assign6 {
		t.Fatalf("%+v", a)
	}
}

func TestSevenIsTheCap(t *testing.T) {
	p := pool(1, 2, 3, 4, 5, 6, 7)
	for i := range 7 * 16 {
		if _, err := p.Allocate(fmt.Sprint(i), t0); err != nil {
			t.Fatal(i, err)
		}
	}
	if a := p.Want(t0); a.Assign4 {
		t.Fatal("assign past seven")
	}
	if _, err := p.Allocate("more", t0); !errors.Is(err, ErrNoAddress) {
		t.Fatal(err)
	}
}

func TestFullestFirst(t *testing.T) {
	p := pool(1, 2)
	// Fill a few of the second /28 by holding only it first.
	p.SetHeld(held(2), v6, t0)
	p.Allocate("x", t0)
	p.Allocate("y", t0)
	p.SetHeld(held(1, 2), v6, t0)
	a, _ := p.Allocate("z", t0)
	if !p4(2).CIDR.Contains(a.V4) {
		t.Fatalf("went to %v", a.V4)
	}
}

func TestCooldown(t *testing.T) {
	p := pool(1)
	a, _ := p.Allocate("a", t0)
	p.Release("a", t0)
	b, _ := p.Allocate("b", t0.Add(29*time.Second))
	if b.V4 == a.V4 || b.V6 == a.V6 {
		t.Fatal("reused while cooling")
	}
	p.Release("b", t0.Add(29*time.Second))
	c, _ := p.Allocate("c", t0.Add(30*time.Second))
	if c.V4 != a.V4 {
		t.Fatalf("%v not reused at 30 s (got %v)", a.V4, c.V4)
	}
}

func TestReleaseAfter30Min(t *testing.T) {
	p := pool(1, 2)
	if a := p.Want(t0.Add(30*time.Minute - time.Second)); a.Unassign != nil {
		t.Fatal("released early")
	}
	a := p.Want(t0.Add(30 * time.Minute))
	if a.Unassign == nil || a.Unassign.CIDR != p4(1).CIDR || a.Unassign.Generation != "1" {
		t.Fatalf("%+v", a)
	}
}

func TestNeverReleaseTheSpare(t *testing.T) {
	p := pool(1, 2)
	p.Allocate("a", t0)
	if a := p.Want(t0.Add(2 * time.Hour)); a.Unassign != nil || a.Assign4 {
		t.Fatalf("%+v", a)
	}
}

func TestNeverReleaseWithPodOrCooling(t *testing.T) {
	p := pool(1, 2, 3)
	p.Allocate("a", t0) // into 1
	p.SetHeld(held(2), v6, t0)
	p.Allocate("b", t0) // into 2
	p.SetHeld(held(1, 2, 3), v6, t0)
	p.Release("b", t0.Add(time.Hour)) // 2 cooling
	a := p.Want(t0.Add(time.Hour + time.Second))
	if a.Unassign != nil {
		t.Fatalf("released %v", a.Unassign.CIDR)
	}
	// 3 is the only spare while 2 cools, and 1 holds a pod; ipamd asks again at NextCheck.
	p.Want(a.NextCheck)
	if a := p.Want(t0.Add(3 * time.Hour)); a.Unassign == nil || a.Unassign.CIDR == p4(1).CIDR {
		t.Fatalf("%+v", a)
	}
}

func TestOneUnassignAtATime(t *testing.T) {
	p := pool(1, 2, 3)
	p.Reserve(p4(1).CIDR)
	if a := p.Want(t0.Add(time.Hour)); a.Unassign != nil {
		t.Fatal("second unassign while one runs")
	}
	p.SetHeld(held(2, 3), v6, t0.Add(time.Hour)) // the unassign realized
	if a := p.Want(t0.Add(2 * time.Hour)); a.Unassign == nil {
		t.Fatal("no unassign after the reservation ended")
	}
}

func TestV6NeverReleased(t *testing.T) {
	p := pool(1, 2)
	a := p.Want(t0.Add(48 * time.Hour))
	if a.Unassign == nil || a.Unassign.CIDR.Addr().Is6() {
		t.Fatalf("%+v", a)
	}
}

func TestNoChurn(t *testing.T) {
	p := pool(1, 2)
	unassigns := 0
	var unassignedAt time.Time
	for m := 0; m < 6*60; m++ {
		now := t0.Add(time.Duration(m) * time.Minute)
		if _, err := p.Allocate("pod", now); err != nil {
			t.Fatal(m, err)
		}
		if a := p.Want(now); a.Assign4 && !unassignedAt.IsZero() && now.Sub(unassignedAt) < 30*time.Minute {
			t.Fatalf("assign %v after an unassign", now.Sub(unassignedAt))
		}
		p.Release("pod", now.Add(10*time.Second))
		for _, at := range []time.Duration{20 * time.Second, 45 * time.Second} {
			if a := p.Want(now.Add(at)); a.Unassign != nil {
				unassigns++
				unassignedAt = now.Add(at)
				var keep []Prefix
				for _, pr := range p.v4 {
					if pr.CIDR != a.Unassign.CIDR {
						keep = append(keep, pr)
					}
				}
				p.SetHeld(keep, v6, now.Add(at))
			}
		}
	}
	if unassigns > 1 {
		t.Fatalf("%d unassigns", unassigns)
	}
}

func TestReservedNotAllocated(t *testing.T) {
	p := pool(1)
	p.Reserve(p4(1).CIDR)
	if _, err := p.Allocate("a", t0); !errors.Is(err, ErrNoAddress) {
		t.Fatal(err)
	}
	p.Unreserve(p4(1).CIDR)
	if _, err := p.Allocate("a", t0); err != nil {
		t.Fatal(err)
	}
}

func TestRestore(t *testing.T) {
	first := pool(1)
	a, _ := first.Allocate("a", t0)
	b, _ := first.Allocate("b", t0)
	p := New(cfg)
	p.Restore(State{Allocs: map[string]Alloc{"a": a, "b": b}})
	p.SetHeld(held(1), v6, t0)
	if got, _ := p.Allocate("a", t0); got != a {
		t.Fatal(got)
	}
	c, _ := p.Allocate("c", t0)
	if c.V4 == a.V4 || c.V4 == b.V4 || c.V6 == a.V6 || c.V6 == b.V6 {
		t.Fatalf("handed out twice: %v", c)
	}
	if a := p.Want(t0); !a.Assign4 {
		t.Fatal("restored pods' /28 counted as a spare")
	}
}

func TestNextCheck(t *testing.T) {
	p := pool(1, 2)
	p.Allocate("a", t0)
	p.Release("a", t0.Add(time.Minute))
	// 1 cools until 1m30s; the surplus starts then, so the release is due at 31m30s.
	if a := p.Want(t0.Add(time.Minute)); !a.NextCheck.Equal(t0.Add(90 * time.Second)) {
		t.Fatalf("%v", a.NextCheck.Sub(t0))
	}
	if a := p.Want(t0.Add(90 * time.Second)); !a.NextCheck.Equal(t0.Add(30*time.Minute + 90*time.Second)) {
		t.Fatalf("%v", a.NextCheck.Sub(t0))
	}
}

func TestRestoreKeepsCooling(t *testing.T) {
	first := pool(1)
	a, _ := first.Allocate("a", t0)
	first.Release("a", t0)
	saved, _ := json.Marshal(first.State())
	var st State
	if err := json.Unmarshal(saved, &st); err != nil {
		t.Fatal(err)
	}
	p := New(cfg)
	p.Restore(st)
	p.SetHeld(held(1), v6, t0.Add(time.Second))
	b, _ := p.Allocate("b", t0.Add(time.Second))
	if b.V4 == a.V4 || b.V6 == a.V6 {
		t.Fatalf("reused %v while it cools", b)
	}
	c, _ := p.Allocate("c", t0.Add(30*time.Second))
	if c.V4 != a.V4 {
		t.Fatalf("%v not reused once cooled (got %v)", a.V4, c.V4)
	}
}
