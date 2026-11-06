package ipamd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/tools/record"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipam"
	"github.com/ezgamehost/ezgh-cni/internal/nodeauth"
	"github.com/ezgamehost/ezgh-cni/internal/nodeauth/imds"
)

// Timing and pool at 1/200 of the node's, so ten fake minutes are three seconds.
var (
	fastTiming = Timing{AddWait: 2 * time.Second, Realize: time.Second, Poll: 5 * time.Millisecond,
		BackoffBase: 50 * time.Millisecond, BackoffCap: 1500 * time.Millisecond, UnknownMin: 5 * time.Millisecond, UnknownMax: 50 * time.Millisecond}
	fastPool = ipam.Config{MaxPrefixes4: 7, Warm: 1, ReleaseAfter: 9 * time.Second, Cooldown: 150 * time.Millisecond}
)

const v6Prefix = "fd12:3456:789a:2800:c4a4::/80"

type refusal struct {
	status     int
	code       string
	retryAfter string
	times      int // 0: always
}

type unassignCall struct{ prefix, generation, key string }

// cloud fakes instance metadata and network-api for one node.
type cloud struct {
	mu        sync.Mutex
	privates  int
	prefixes  *[]imds.Ownership // nil: metadata answers null
	hidden    map[string]bool   // assigned, not yet listed
	hideNew   bool
	refuse    map[string]*refusal
	assigns   []string // idempotency keys
	assignAt  []time.Time
	opGets    []time.Time
	unassigns []unassignCall
	conflict  bool
	queued    int // GETs an operation answers queued
	retry     string
	creds     int
	calls     int // network-api requests
	audience  string
	paths     []string
	next4     int
	byKey     map[string]string // an assign's prefix by Idempotency-Key, as network replays it
	opPrefix  string
	pending   string // an unassigned prefix metadata lists until its operation succeeds
	expand    bool   // operations name the /80 uncompressed, as text network could send
}

func (c *cloud) remove(prefix string) {
	var keep []imds.Ownership
	for _, o := range *c.prefixes {
		if o.Prefix != prefix {
			keep = append(keep, o)
		}
	}
	*c.prefixes = keep
}

func newCloud(prefixes ...string) *cloud {
	c := &cloud{privates: 1, hidden: map[string]bool{}, refuse: map[string]*refusal{}, next4: 1, byKey: map[string]string{}}
	list := []imds.Ownership{}
	for _, p := range prefixes {
		list = append(list, imds.Ownership{Prefix: p, Generation: "1"})
	}
	c.prefixes = &list
	return c
}

func (c *cloud) show(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.hidden, prefix)
}

func (c *cloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	answer := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	fail := func(status int, code string) {
		answer(status, map[string]any{"error": map[string]string{"code": code, "message": code + " message"}})
	}
	p := r.URL.Path
	if strings.HasPrefix(p, "/v1/") {
		c.calls++
		c.paths = append(c.paths, p)
		if r.Header.Get("Authorization") != fmt.Sprintf("Bearer ezgh_key%d", c.creds) {
			fail(401, "unauthenticated")
			return
		}
	}
	switch {
	case p == "/ezgh/v1/token":
		fmt.Fprint(w, "session")
	case p == "/ezgh/v1/instance":
		var list any
		if c.prefixes != nil {
			l := []imds.Ownership{}
			for _, o := range *c.prefixes {
				if !c.hidden[o.Prefix] {
					l = append(l, o)
				}
			}
			list = l
		}
		ifaces := []map[string]any{{"id": "eni_pub", "kind": "public", "mac": "02:00:00:00:00:01", "deviceIndex": 0, "mtu": 1500,
			"subnet": nil, "privateIpv4": nil, "delegatedPrefixes": []any{}}}
		for i := range c.privates {
			ifaces = append(ifaces, map[string]any{"id": fmt.Sprintf("eni_priv%d", i), "kind": "private", "mac": "02:00:00:00:00:02", "deviceIndex": 1 + i, "mtu": 8900,
				"subnet": map[string]string{"ipv4Cidr": "10.240.1.0/24", "ipv6Cidr": "fd12:3456:789a:2800::/64"}, "privateIpv4": "10.240.1.5", "delegatedPrefixes": list})
		}
		answer(200, map[string]any{"id": "ins_abc", "projectId": "prj-uuid", "region": "us-west-1", "interfaces": ifaces})
	case p == "/ezgh/v1/identity":
		c.audience = r.URL.Query().Get("audience")
		claims, _ := json.Marshal(map[string]any{"org": "org-uuid", "sub": "ins_abc", "aud": c.audience})
		answer(200, map[string]string{"token": "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"})
	case p == "/ezgh/v1/credentials":
		c.creds++
		answer(200, map[string]string{"apiKey": fmt.Sprintf("ezgh_key%d", c.creds), "bot": "bot_n", "expiresAt": "2026-11-06T10:00:00.000Z"})
	case strings.HasSuffix(p, "/private-prefixes/assign"):
		var in struct{ Family string }
		json.NewDecoder(r.Body).Decode(&in)
		c.assigns = append(c.assigns, r.Header.Get("Idempotency-Key"))
		c.assignAt = append(c.assignAt, time.Now())
		if ref := c.refuse[in.Family]; ref != nil {
			if ref.times > 0 {
				if ref.times--; ref.times == 0 {
					delete(c.refuse, in.Family)
				}
			}
			if ref.retryAfter != "" {
				w.Header().Set("Retry-After", ref.retryAfter)
			}
			fail(ref.status, ref.code)
			return
		}
		if prefix, ok := c.byKey[r.Header.Get("Idempotency-Key")]; ok {
			c.operation(w, prefix)
			return
		}
		prefix := v6Prefix
		if in.Family == "ipv4" {
			prefix = fmt.Sprintf("10.240.1.%d/28", 16*c.next4)
			c.next4++
		}
		if c.prefixes == nil {
			c.prefixes = &[]imds.Ownership{}
		}
		*c.prefixes = append(*c.prefixes, imds.Ownership{Prefix: prefix, Generation: "1"})
		if c.hideNew {
			c.hidden[prefix] = true
		}
		c.byKey[r.Header.Get("Idempotency-Key")] = prefix
		c.operation(w, prefix)
	case strings.HasSuffix(p, "/private-prefixes/unassign"):
		var in struct{ Prefix, ExpectedGeneration string }
		json.NewDecoder(r.Body).Decode(&in)
		c.unassigns = append(c.unassigns, unassignCall{in.Prefix, in.ExpectedGeneration, r.Header.Get("Idempotency-Key")})
		if c.conflict {
			c.conflict = false
			for i := range *c.prefixes {
				if (*c.prefixes)[i].Prefix == in.Prefix {
					(*c.prefixes)[i].Generation = "2"
				}
			}
			fail(409, "address_generation_conflict")
			return
		}
		if c.queued > 0 {
			c.pending = in.Prefix
		} else {
			c.remove(in.Prefix)
		}
		c.operation(w, in.Prefix)
	case strings.Contains(p, "/private-address-operations/"):
		c.opGets = append(c.opGets, time.Now())
		status := "succeeded"
		if c.queued > 0 {
			c.queued--
			status = "running"
		} else if c.pending != "" {
			c.remove(c.pending)
			c.pending = ""
		}
		answer(200, map[string]any{"id": "op1", "status": status, "address": c.opAddress(), "generation": "1", "error": nil})
	default:
		fail(404, "not_found")
	}
}

// operation answers 202 with an operation that is queued while c.queued lasts.
func (c *cloud) operation(w http.ResponseWriter, prefix string) {
	status := "succeeded"
	if c.queued > 0 {
		status = "queued"
		w.Header().Set("Retry-After", c.retry)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	c.opPrefix = prefix
	json.NewEncoder(w).Encode(map[string]any{"id": "op1", "status": status, "address": c.opAddress(), "generation": "1", "error": nil})
}

func (c *cloud) opAddress() string {
	if c.expand && c.opPrefix == v6Prefix {
		return "fd12:3456:789a:2800:c4a4:0:0:0/80"
	}
	return c.opPrefix
}

type fakeNL struct {
	mu    sync.Mutex
	pia   int
	rules []netip.Prefix
	table int
}

func (f *fakeNL) LinkByMAC(mac string) (string, error) {
	if mac != "02:00:00:00:00:02" {
		return "", fmt.Errorf("no link %s", mac)
	}
	return "enp2s0", nil
}
func (f *fakeNL) EnsurePIA() error { f.mu.Lock(); f.pia++; f.mu.Unlock(); return nil }
func (f *fakeNL) SetPrefixRules(p []netip.Prefix, table int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules, f.table = p, table
	return nil
}
func (f *fakeNL) get() []netip.Prefix { f.mu.Lock(); defer f.mu.Unlock(); return f.rules }

type node struct {
	cloud   *cloud
	nl      *fakeNL
	events  *record.FakeRecorder
	dir     string
	ipamd   Client
	logs    *bytes.Buffer
	nftText func() string
	done    chan error
	cancel  context.CancelFunc
}

func start(t *testing.T, c *cloud, mods ...func(*Options)) *node {
	t.Helper()
	ts := httptest.NewServer(c)
	t.Cleanup(ts.Close)
	dir, _ := os.MkdirTemp("", "ipamd")
	t.Cleanup(func() { os.RemoveAll(dir) })
	n := &node{cloud: c, nl: &fakeNL{}, events: record.NewFakeRecorder(100), logs: &bytes.Buffer{}, done: make(chan error, 1)}
	var mu sync.Mutex
	var nftText string
	n.nftText = func() string { mu.Lock(); defer mu.Unlock(); return nftText }
	o := Options{IMDS: &imds.Client{Base4: ts.URL, Base6: ts.URL}, Events: n.events, Exec: n.nl,
		NFT:   func(_ context.Context, s string) error { mu.Lock(); nftText = s; mu.Unlock(); return nil },
		Log:   slog.New(slog.NewTextHandler(&lockedWriter{w: n.logs}, nil)),
		Facts: &nodeauth.JoinFacts{Cluster: "kcl_test"}, NetBase: ts.URL, Dir: dir, Conflist: filepath.Join(dir, "conflist"),
		Addresses: fastPool, Timing: fastTiming, Jitter: func(d time.Duration) time.Duration { return d }}
	for _, m := range mods {
		m(&o)
	}
	n.dir, n.ipamd = o.Dir, Client{Socket: filepath.Join(o.Dir, "ipamd.sock")}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	go func() { n.done <- Run(ctx, o) }()
	t.Cleanup(func() { cancel(); <-n.done })
	return n
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func (n *node) add(t *testing.T, id string) (AddResponse, error) {
	t.Helper()
	eventually(t, "the socket", func() bool {
		conn, err := net.Dial("unix", n.ipamd.Socket)
		if err == nil {
			conn.Close()
		}
		return err == nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return n.ipamd.Add(ctx, AddRequest{ContainerID: id, IfName: "eth0", Netns: "/var/run/netns/x", Namespace: "default", Pod: id})
}

func (n *node) ready() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return n.ipamd.Ready(ctx)
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	// Generous: it returns as soon as f holds, and -race on a two-core runner is slow.
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("never: %s", what)
}

func in(p string, a netip.Addr) bool { return netip.MustParsePrefix(p).Contains(a) }

func (c *cloud) counts() (assigns, unassigns int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.assigns), len(c.unassigns)
}

func TestTwoPrivateInterfacesRefused(t *testing.T) {
	c := newCloud()
	c.privates = 2
	n := start(t, c)
	err := <-n.done
	n.done <- err
	if err == nil || !strings.Contains(err.Error(), "exactly one private network interface") {
		t.Fatal(err)
	}
}

func TestOrgFromIdentityClaim(t *testing.T) {
	c := newCloud()
	n := start(t, c)
	eventually(t, "ready", n.ready)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.audience != "kubernetes:kcl_test" || len(c.paths) == 0 {
		t.Fatal(c.audience, c.paths)
	}
	for _, p := range c.paths {
		if !strings.HasPrefix(p, "/v1/organizations/org-uuid/projects/prj-uuid/") {
			t.Fatal(p)
		}
	}
}

func TestPIALink(t *testing.T) {
	n := start(t, newCloud("10.240.1.16/28", v6Prefix))
	eventually(t, "ready", n.ready)
	if n.nl.pia != 1 {
		t.Fatal(n.nl.pia)
	}
}

func TestRebootAdoptsHeldPrefixes(t *testing.T) {
	c := newCloud("10.240.1.16/28", "10.240.1.32/28", v6Prefix)
	n := start(t, c)
	eventually(t, "ready", n.ready)
	a, err := n.add(t, "c1")
	if err != nil || !in("10.240.1.16/28", a.IPv4) || !in(v6Prefix, a.IPv6) || a.MTU != 8900 || a.HostTable != 101 {
		t.Fatalf("%+v %v", a, err)
	}
	time.Sleep(50 * time.Millisecond)
	if as, _ := c.counts(); as != 0 {
		t.Fatalf("%d assigns", as)
	}
	if got := n.nl.get(); len(got) != 3 || n.nl.table != 101 {
		t.Fatal(got, n.nl.table)
	}
	if !strings.Contains(n.nftText(), "elements = { 10.240.1.16/28, 10.240.1.32/28 }") || !strings.Contains(n.nftText(), `oifname "enp2s0" return`) {
		t.Fatal(n.nftText())
	}
}

func TestRestartKeepsAllocations(t *testing.T) {
	c := newCloud("10.240.1.16/28", "10.240.1.32/28", v6Prefix)
	n := start(t, c)
	eventually(t, "ready", n.ready)
	a, _ := n.add(t, "c1")
	n.cancel()
	<-n.done
	n.done <- nil
	m := start(t, c, func(o *Options) { o.Dir = n.dir })
	eventually(t, "ready again", m.ready)
	again, _ := m.add(t, "c1")
	other, _ := m.add(t, "c2")
	if again != a || other.IPv4 == a.IPv4 || other.IPv6 == a.IPv6 {
		t.Fatal(a, again, other)
	}
}

func TestNullDelegatedPrefixesChangesNothing(t *testing.T) {
	c := newCloud()
	c.prefixes = nil
	n := start(t, c)
	time.Sleep(150 * time.Millisecond)
	if as, us := c.counts(); as+us != 0 || n.ready() {
		t.Fatalf("assigns %d unassigns %d ready %v", as, us, n.ready())
	}
	c.mu.Lock()
	c.prefixes = &[]imds.Ownership{{Prefix: "10.240.1.16/28", Generation: "1"}, {Prefix: v6Prefix, Generation: "1"}}
	c.mu.Unlock()
	eventually(t, "ready once metadata knows", n.ready)
}

func TestUsesPrefixOnlyAfterMetadataLists(t *testing.T) {
	c := newCloud()
	c.hideNew = true
	n := start(t, c)
	got := make(chan AddResponse)
	go func() { a, _ := n.add(t, "c1"); got <- a }()
	eventually(t, "the IPv6 assign", func() bool { as, _ := c.counts(); return as == 1 })
	c.show(v6Prefix)
	eventually(t, "the IPv4 assign", func() bool { as, _ := c.counts(); return as == 2 })
	select {
	case a := <-got:
		t.Fatalf("handed out %v before metadata listed it", a)
	case <-time.After(100 * time.Millisecond):
	}
	c.show("10.240.1.16/28")
	if a := <-got; !in("10.240.1.16/28", a.IPv4) {
		t.Fatal(a)
	}
}

func TestOperationWaitHonoursRetryAfter(t *testing.T) {
	c := newCloud("10.240.1.16/28")
	c.queued, c.retry = 1, "1"
	n := start(t, c, func(o *Options) { o.Timing.Realize = 3 * time.Second })
	eventually(t, "ready", n.ready)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.opGets) == 0 || c.opGets[0].Sub(c.assignAt[0]) < time.Second {
		t.Fatal(c.opGets, c.assignAt)
	}
}

func TestRealizeTimeout120s(t *testing.T) {
	c := newCloud("10.240.1.16/28")
	c.hideNew = true
	n := start(t, c, func(o *Options) { o.Timing.Realize = 100 * time.Millisecond })
	eventually(t, "a retry", func() bool { as, _ := c.counts(); return as >= 2 })
	c.mu.Lock()
	if c.assigns[0] != c.assigns[1] || len(c.unassigns) != 0 || c.next4 != 1 {
		t.Fatalf("keys %v unassigns %v", c.assigns, c.unassigns)
	}
	c.mu.Unlock()
	c.show(v6Prefix)
	eventually(t, "ready once listed", n.ready)
}

func TestReleaseRunsUnassign(t *testing.T) {
	c := newCloud("10.240.1.16/28", "10.240.1.32/28", "10.240.1.48/28", v6Prefix)
	(*c.prefixes)[1].Generation = "7"
	n := start(t, c, func(o *Options) { o.Addresses.ReleaseAfter = 300 * time.Millisecond })
	eventually(t, "ready", n.ready)
	if _, err := n.add(t, "c1"); err != nil { // into .16; .32 and .48 spare
		t.Fatal(err)
	}
	eventually(t, "one unassign", func() bool { _, us := c.counts(); return us == 1 })
	c.mu.Lock()
	u := c.unassigns[0]
	c.mu.Unlock()
	if u.prefix != "10.240.1.32/28" || u.generation != "7" || u.key == "" {
		t.Fatalf("%+v", u)
	}
	eventually(t, "rule removed", func() bool { return len(n.nl.get()) == 3 })
	time.Sleep(300 * time.Millisecond)
	if _, us := c.counts(); us != 1 {
		t.Fatalf("%d unassigns: released the last spare", us)
	}
}

func TestGenerationConflictRereads(t *testing.T) {
	c := newCloud("10.240.1.16/28", "10.240.1.32/28", v6Prefix)
	c.conflict = true
	n := start(t, c, func(o *Options) { o.Addresses.ReleaseAfter = 50 * time.Millisecond })
	eventually(t, "two unassigns", func() bool { _, us := c.counts(); return us == 2 })
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.unassigns[0].generation != "1" || c.unassigns[1].generation != "2" || c.unassigns[0].key == c.unassigns[1].key {
		t.Fatalf("%+v", c.unassigns)
	}
	_ = n
}

func TestReservedDuringUnassign(t *testing.T) {
	c := newCloud("10.240.1.16/28", "10.240.1.32/28", v6Prefix)
	c.queued, c.retry = 1000, "0"
	n := start(t, c, func(o *Options) { o.Addresses.ReleaseAfter = 50 * time.Millisecond })
	eventually(t, "unassign running", func() bool { _, us := c.counts(); return us == 1 })
	for i := range 16 {
		a, err := n.add(t, fmt.Sprint("c", i))
		if err != nil || !in("10.240.1.32/28", a.IPv4) {
			t.Fatalf("%d: %v %v", i, a, err)
		}
	}
}

func TestOneKeyPerCallNeverOnDisk(t *testing.T) {
	c := newCloud()
	c.queued, c.retry = 2, "0"
	n := start(t, c)
	eventually(t, "ready", n.ready)
	n.add(t, "c1")
	// A background call may have fetched its key but not yet reached the cloud: wait for it.
	eventually(t, "one key per call", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.creds == c.calls && c.calls >= 4
	})
	filepath.Walk(n.dir, func(p string, _ os.FileInfo, _ error) error {
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("ezgh_")) {
			t.Errorf("%s holds a key", p)
		}
		return nil
	})
	if strings.Contains(n.logs.String(), "ezgh_") {
		t.Fatal(n.logs.String())
	}
}

func refuse(c *cloud, family string, r *refusal) {
	c.mu.Lock()
	c.refuse[family] = r
	c.mu.Unlock()
}

func TestAddFailsNamingPrefixUnavailable(t *testing.T) {
	c := newCloud(v6Prefix)
	refuse(c, "ipv4", &refusal{status: 409, code: "prefix_unavailable"})
	n := start(t, c)
	_, err := n.add(t, "c1")
	if err == nil || err.Error() != "ezgh-vpc-cni: no free IPv4 address: subnet 10.240.1.0/24 has no free /28 (prefix_unavailable)" {
		t.Fatal(err)
	}
}

func TestPrefixUnavailableBacksOffNeverChurns(t *testing.T) {
	c := newCloud("10.240.1.16/28", "10.240.1.32/28", v6Prefix)
	refuse(c, "ipv4", &refusal{status: 409, code: "prefix_unavailable"})
	n := start(t, c)
	eventually(t, "ready", n.ready)
	given := map[string]AddResponse{}
	failed := 0
	begin := time.Now()
	for i := range 40 {
		id := fmt.Sprint("c", i)
		if a, err := n.add(t, id); err == nil {
			given[id] = a
		} else if strings.Contains(err.Error(), "prefix_unavailable") {
			failed++
		} else {
			t.Fatal(err)
		}
		time.Sleep(75 * time.Millisecond) // 40 ADDs over ten fake minutes
	}
	time.Sleep(3*time.Second - time.Since(begin))
	as, us := c.counts()
	if len(given) != 32 || failed != 8 || as > 7 || us != 0 {
		t.Fatalf("given %d failed %d assigns %d unassigns %d", len(given), failed, as, us)
	}
	if len(n.events.Events) != 1 {
		t.Fatalf("%d events", len(n.events.Events))
	}
	if e := <-n.events.Events; !strings.HasPrefix(e, "Warning PrefixUnavailable ") || !strings.Contains(e, "prefix_unavailable") {
		t.Fatal(e)
	}
	for id, a := range given {
		if again, err := n.add(t, id); err != nil || again != a {
			t.Fatalf("%s moved: %v %v", id, again, err)
		}
	}
	refuse(c, "ipv4", nil)
	recovered := time.Now()
	eventually(t, "an ADD after recovery", func() bool { _, err := n.add(t, "late"); return err == nil })
	if time.Since(recovered) > fastTiming.BackoffCap+500*time.Millisecond {
		t.Fatalf("recovered after %v", time.Since(recovered))
	}
}

func TestLimitExceededSamePath(t *testing.T) {
	c := newCloud(v6Prefix)
	refuse(c, "ipv4", &refusal{status: 409, code: "private_address_limit_exceeded"})
	n := start(t, c)
	if _, err := n.add(t, "c1"); err == nil || !strings.Contains(err.Error(), "(private_address_limit_exceeded)") {
		t.Fatal(err)
	}
	if e := <-n.events.Events; !strings.HasPrefix(e, "Warning PrefixUnavailable ") {
		t.Fatal(e)
	}
}

func TestAccessDeniedNamesAction(t *testing.T) {
	c := newCloud(v6Prefix)
	refuse(c, "ipv4", &refusal{status: 403, code: "forbidden"})
	n := start(t, c)
	if _, err := n.add(t, "c1"); err == nil || !strings.Contains(err.Error(), "network.networkInterfaces.assignPrivatePrefix") {
		t.Fatal(err)
	}
	if e := <-n.events.Events; !strings.HasPrefix(e, "Warning PrefixAssignDenied ") || !strings.Contains(e, "network.networkInterfaces.assignPrivatePrefix") {
		t.Fatal(e)
	}
}

func Test429WaitsRetryAfter(t *testing.T) {
	c := newCloud(v6Prefix)
	refuse(c, "ipv4", &refusal{status: 429, code: "rate_limited", retryAfter: "1", times: 1})
	n := start(t, c)
	eventually(t, "ready", n.ready)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.assigns) != 2 || c.assigns[0] != c.assigns[1] || c.assignAt[1].Sub(c.assignAt[0]) < time.Second {
		t.Fatal(c.assigns, c.assignAt)
	}
}

func TestAddWaitsForFirstPrefix(t *testing.T) {
	c := newCloud()
	c.hideNew = true
	n := start(t, c, func(o *Options) { o.Timing.AddWait = 200 * time.Millisecond })
	begin := time.Now()
	_, err := n.add(t, "c1")
	if err == nil || !strings.Contains(err.Error(), "no free address yet") || time.Since(begin) < 200*time.Millisecond {
		t.Fatal(err, time.Since(begin))
	}
}

func TestConflistOnlyWhenReady(t *testing.T) {
	c := newCloud()
	c.hideNew = true
	n := start(t, c)
	conflist := filepath.Join(n.dir, "conflist")
	eventually(t, "the IPv6 assign", func() bool { as, _ := c.counts(); return as == 1 })
	c.show(v6Prefix)
	eventually(t, "the IPv4 assign", func() bool { as, _ := c.counts(); return as == 2 })
	if _, err := os.Stat(conflist); err == nil || n.ready() {
		t.Fatal("conflist before a /28 is realized")
	}
	c.show("10.240.1.16/28")
	eventually(t, "ready", n.ready)
	if b, err := os.ReadFile(conflist); err != nil || !strings.Contains(string(b), `"socket":"/run/ezgh-vpc-cni/ipamd.sock"`) {
		t.Fatal(string(b), err)
	}
}

func TestRealizeComparesPrefixes(t *testing.T) {
	c := newCloud("10.240.1.16/28")
	c.expand = true
	n := start(t, c)
	eventually(t, "ready with the /80 named uncompressed", n.ready)
}

func TestWaitingAddServedWhenCooled(t *testing.T) {
	var list []string
	for i := 1; i <= 7; i++ {
		list = append(list, fmt.Sprintf("10.240.1.%d/28", 16*i))
	}
	c := newCloud(append(list, v6Prefix)...)
	n := start(t, c)
	eventually(t, "ready", n.ready)
	var first AddResponse
	for i := range 7 * 16 {
		a, err := n.add(t, fmt.Sprint("c", i))
		if err != nil {
			t.Fatal(i, err)
		}
		if i == 0 {
			first = a
		}
	}
	got := make(chan AddResponse, 1)
	go func() { a, _ := n.add(t, "late"); got <- a }()
	time.Sleep(20 * time.Millisecond)
	if err := n.ipamd.Del(context.Background(), "c0", "eth0"); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	select {
	case a := <-got:
		if a.IPv4 != first.IPv4 || time.Since(begin) < fastPool.Cooldown-20*time.Millisecond {
			t.Fatalf("%v after %v", a, time.Since(begin))
		}
	case <-time.After(fastTiming.AddWait / 2):
		t.Fatal("the waiting ADD wasn't served once the address cooled")
	}
}

func TestRestartKeepsCooling(t *testing.T) {
	c := newCloud("10.240.1.16/28", v6Prefix)
	slow := func(o *Options) { o.Addresses.Cooldown = 5 * time.Second }
	n := start(t, c, slow)
	eventually(t, "ready", n.ready)
	a, _ := n.add(t, "c1")
	if err := n.ipamd.Del(context.Background(), "c1", "eth0"); err != nil {
		t.Fatal(err)
	}
	n.cancel()
	<-n.done
	n.done <- nil
	m := start(t, c, slow, func(o *Options) { o.Dir = n.dir })
	eventually(t, "ready again", m.ready)
	b, err := m.add(t, "c2")
	if err != nil || b.IPv4 == a.IPv4 || b.IPv6 == a.IPv6 {
		t.Fatalf("%v %v reused %v", b, err, a)
	}
}

func TestUnassignResumesAfterRestart(t *testing.T) {
	c := newCloud("10.240.1.16/28", "10.240.1.32/28", v6Prefix)
	c.queued, c.retry = 1<<20, "0"
	n := start(t, c, func(o *Options) { o.Addresses.ReleaseAfter = 50 * time.Millisecond })
	eventually(t, "an unassign in flight", func() bool { _, us := c.counts(); return us >= 1 })
	n.cancel()
	<-n.done
	n.done <- nil
	b, _ := os.ReadFile(filepath.Join(n.dir, "allocations.json"))
	c.mu.Lock()
	first := c.unassigns[0]
	c.queued = 0
	c.mu.Unlock()
	if !strings.Contains(string(b), first.key) || !strings.Contains(string(b), first.prefix) {
		t.Fatalf("the unassign isn't kept: %s", b)
	}
	m := start(t, c, func(o *Options) { o.Dir = n.dir; o.Addresses.ReleaseAfter = time.Hour })
	a, err := m.add(t, "c1")
	if err != nil || in(first.prefix, a.IPv4) {
		t.Fatalf("%v %v: allocated from the prefix being unassigned", a, err)
	}
	eventually(t, "the unassign re-driven", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		last := c.unassigns[len(c.unassigns)-1]
		listed := false
		for _, o := range *c.prefixes {
			listed = listed || o.Prefix == first.prefix
		}
		return last.key == first.key && last.prefix == first.prefix && !listed
	})
}

func TestOperationInProgressIsTransient(t *testing.T) {
	c := newCloud(v6Prefix)
	refuse(c, "ipv4", &refusal{status: 409, code: "address_operation_in_progress", times: 1})
	n := start(t, c)
	if _, err := n.add(t, "c1"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.assigns) != 2 || c.assigns[0] != c.assigns[1] || len(n.events.Events) != 0 {
		t.Fatalf("assigns %v, %d events", c.assigns, len(n.events.Events))
	}
}
