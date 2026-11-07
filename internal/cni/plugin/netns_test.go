//go:build netns && linux

package plugin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/ezgamehost/ezgh-cni/internal/cni/cnitest"
	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
)

// fakeIpamd answers ADDs with .16 + n of the test prefixes, and records DELs.
type fakeIpamd struct {
	socket string
	mu     sync.Mutex
	n      int
	dels   []string
}

func newIpamd(t *testing.T) *fakeIpamd {
	dir, _ := os.MkdirTemp("", "cni")
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeIpamd{socket: filepath.Join(dir, "ipamd.sock")}
	l, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/add", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		a := ipamd.AddResponse{IPv4: netip.MustParseAddr(fmt.Sprintf("10.240.1.%d", 16+f.n)), IPv6: netip.MustParseAddr(fmt.Sprintf("fdcc:1:2:1:c4a4::%x", 16+f.n)), MTU: 8900, HostTable: 101}
		f.n++
		json.NewEncoder(w).Encode(a)
	})
	mux.HandleFunc("POST /v1/del", func(w http.ResponseWriter, r *http.Request) {
		var in ipamd.AddRequest
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.dels = append(f.dels, in.ContainerID+"/"+in.IfName)
		f.mu.Unlock()
		w.Write([]byte("{}"))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return f
}

func conf(f *fakeIpamd, prev string) []byte {
	c := fmt.Sprintf(`{"cniVersion":"1.0.0","name":"ezgh-vpc-cni","type":"ezgh-vpc-cni","socket":%q`, f.socket)
	if prev != "" {
		c += `,"prevResult":` + prev
	}
	return []byte(c + "}")
}

type setup struct {
	node *cnitest.Node
	ipam *fakeIpamd
}

func newSetup(t *testing.T) *setup {
	s := &setup{node: cnitest.NewNode(t, 1500), ipam: newIpamd(t)}
	cnitest.Sh(t, s.node.NS, "ip rule add from "+cnitest.Prefix4+" lookup 101 suppress_prefixlength 0 pref 1536; ip -6 rule add from "+cnitest.Prefix6+" lookup 101 suppress_prefixlength 0 pref 1536")
	return s
}

// add runs ADD for a new pod netns and answers it with the result's JSON.
func (s *setup) add(t *testing.T, id string, pod ns.NetNS) string {
	t.Helper()
	var out []byte
	cnitest.Do(t, s.node.NS, func() error {
		c, err := parse(&skel.CmdArgs{StdinData: conf(s.ipam, "")})
		if err != nil {
			return err
		}
		r, err := Add(c, &skel.CmdArgs{ContainerID: id, IfName: "eth0", Netns: pod.Path(), Args: "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=" + id})
		if err != nil {
			return err
		}
		out, err = json.Marshal(r)
		return err
	})
	cnitest.WaitUp(t, pod, "eth0")
	cnitest.WaitUp(t, s.node.NS, VethName(id, "eth0"))
	return string(out)
}

func (s *setup) run(t *testing.T, f func(*skel.CmdArgs) error, id string, pod ns.NetNS, prev string) error {
	var err error
	cnitest.Do(t, s.node.NS, func() error {
		err = f(&skel.CmdArgs{ContainerID: id, IfName: "eth0", Netns: pod.Path(), StdinData: conf(s.ipam, prev)})
		return nil
	})
	return err
}

func has(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Fatalf("no %q in\n%s", w, out)
		}
	}
}

func TestAddWiresPod(t *testing.T) {
	s := newSetup(t)
	pod := cnitest.NS(t)
	s.add(t, "c1", pod)
	host, mac := VethName("c1", "eth0"), HostMAC("c1", "eth0").String()
	has(t, cnitest.Sh(t, s.node.NS, "ip -d link show "+host), "link/ether "+mac, "mtu 8900")
	// The MAC was set, not generated: udev's persistent policy leaves it alone.
	if got := strings.TrimSpace(cnitest.Sh(t, s.node.NS, "ip netns exec "+cnitest.Name(s.node.NS)+" cat /sys/class/net/"+host+"/addr_assign_type")); got != "3" {
		t.Fatalf("addr_assign_type %s", got)
	}
	has(t, cnitest.Sh(t, s.node.NS, "ip -6 addr show dev "+host), "inet6 fe80::1/64 scope link nodad")
	has(t, cnitest.Sh(t, s.node.NS, "ip route show 10.240.1.16/32; ip -6 route show fdcc:1:2:1:c4a4::10/128"),
		"10.240.1.16 dev "+host+" scope link", "fdcc:1:2:1:c4a4::10 dev "+host)
	has(t, cnitest.Sh(t, s.node.NS, "ip rule show pref 512; ip -6 rule show pref 512"),
		"512:	from all to 10.240.1.16 lookup main", "512:	from all to fdcc:1:2:1:c4a4::10 lookup main")
	has(t, cnitest.Sh(t, pod, "ip addr show dev eth0"), "inet 10.240.1.16/32", "inet6 fdcc:1:2:1:c4a4::10/128 scope global nodad", "mtu 8900")
	has(t, cnitest.Sh(t, pod, "ip route; ip -6 route show default; ip neigh show 169.254.1.1"),
		"default via 169.254.1.1 dev eth0", "169.254.1.1 dev eth0 scope link", "default via fe80::1 dev eth0", "169.254.1.1 dev eth0 lladdr "+mac+" PERMANENT")
	// And it carries traffic, both families, with the pod's own source.
	for _, peer := range []string{cnitest.VPCPeer4 + ":8080", "[" + cnitest.VPCPeer6 + "]:8080"} {
		peers := cnitest.Listen(t, s.node.VPC, peer)
		c, err := cnitest.Dial(pod, peer, 5*time.Second)
		if err != nil {
			t.Fatal(peer, err)
		}
		c.Close()
		if p := (<-peers).(*net.TCPAddr).IP.String(); p != "10.240.1.16" && p != "fdcc:1:2:1:c4a4::10" {
			t.Fatal(p)
		}
	} // And into the pod from the VPC: the node solicits the pod from the host veth's nodad fe80::1 while
	// the veth's own link-local may still be tentative.
	for _, l := range []string{"10.240.1.16:80", "[fdcc:1:2:1:c4a4::10]:80"} {
		peers := cnitest.Listen(t, pod, l)
		c, err := cnitest.Dial(s.node.VPC, l, 5*time.Second)
		if err != nil {
			t.Fatal(l, err)
		}
		c.Close()
		if p := (<-peers).(*net.TCPAddr).IP.String(); p != cnitest.VPCPeer4 && p != cnitest.VPCPeer6 && p != "10.240.1.1" && p != "fdcc:1:2:1::1" {
			t.Fatal("pod saw", p)
		}
	}
}

func TestMTUFromInterface(t *testing.T) {
	s := newSetup(t)
	pod := cnitest.NS(t)
	s.add(t, "c1", pod)
	has(t, cnitest.Sh(t, pod, "ip link show eth0"), "mtu 8900")
	has(t, cnitest.Sh(t, s.node.NS, "ip link show "+VethName("c1", "eth0")), "mtu 8900")
}

func TestLocalPodToPodStaysLocal(t *testing.T) {
	s := newSetup(t)
	a, b := cnitest.NS(t), cnitest.NS(t)
	s.add(t, "a", a)
	s.add(t, "b", b) // 10.240.1.17
	tx := func() uint64 {
		var n uint64
		cnitest.Do(t, s.node.NS, func() error {
			l, err := netlink.LinkByName(cnitest.Private)
			if err == nil {
				n = l.Attrs().Statistics.TxPackets
			}
			return err
		})
		return n
	}
	peers := cnitest.Listen(t, b, "10.240.1.17:8080")
	before := tx()
	for range 10 {
		c, err := cnitest.Dial(a, "10.240.1.17:8080", 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		<-peers
	}
	if d := tx() - before; d > 2 {
		t.Fatalf("%d packets left by %s", d, cnitest.Private)
	}
}

func TestDelIdempotent(t *testing.T) {
	s := newSetup(t)
	pod := cnitest.NS(t)
	prev := s.add(t, "c1", pod)
	for range 2 {
		if err := s.run(t, cmdDel, "c1", pod, prev); err != nil {
			t.Fatal(err)
		}
	}
	if out := cnitest.Sh(t, s.node.NS, "ip link show; ip rule show pref 512; ip -6 rule show pref 512"); strings.Contains(out, "ezp") || strings.Contains(out, "10.240.1.16") {
		t.Fatal(out)
	}
	// The netns gone too.
	gone := cnitest.NS(t)
	s.add(t, "c2", gone)
	gone.Close()
	if err := s.run(t, cmdDel, "c2", gone, ""); err != nil {
		t.Fatal(err)
	}
}

func TestDelReleases(t *testing.T) {
	s := newSetup(t)
	pod := cnitest.NS(t)
	prev := s.add(t, "c1", pod)
	if err := s.run(t, cmdDel, "c1", pod, prev); err != nil {
		t.Fatal(err)
	}
	if len(s.ipam.dels) != 1 || s.ipam.dels[0] != "c1/eth0" {
		t.Fatal(s.ipam.dels)
	}
}

func TestCheckFindsMissingRule(t *testing.T) {
	s := newSetup(t)
	pod := cnitest.NS(t)
	prev := s.add(t, "c1", pod)
	if err := s.run(t, cmdCheck, "c1", pod, prev); err != nil {
		t.Fatal(err)
	}
	cnitest.Sh(t, s.node.NS, "ip rule del to 10.240.1.16 lookup main pref 512")
	if err := s.run(t, cmdCheck, "c1", pod, prev); err == nil || !strings.Contains(err.Error(), "rule to 10.240.1.16 lookup main pref 512 missing") {
		t.Fatal(err)
	}
}

func TestAddAfterFailedAddCleansUp(t *testing.T) {
	s := newSetup(t)
	pod := cnitest.NS(t)
	host := VethName("c1", "eth0")
	cnitest.Sh(t, s.node.NS, "ip link add "+host+" type veth peer name stale0")
	cnitest.Sh(t, pod, "ip link add eth0 type veth peer name stale1")
	s.add(t, "c1", pod)
	has(t, cnitest.Sh(t, s.node.NS, "ip link show "+host), "link/ether "+HostMAC("c1", "eth0").String())
	has(t, cnitest.Sh(t, pod, "ip -d link show eth0"), "veth")
	if strings.Contains(cnitest.Sh(t, s.node.NS, "ip link show"), "stale0") {
		t.Fatal("stale peer left")
	}
}

// hostPort: upstream portmap, chained after ezgh-vpc-cni as the conflist has it, DNATs a node port
// to the pod from this plugin's result. EZGH_CNI_PORTMAP is the binary (test.sh and CI build it at
// go.mod's plugins version).
func TestHostPortReachesPod(t *testing.T) {
	bin := os.Getenv("EZGH_CNI_PORTMAP")
	if bin == "" {
		if os.Getenv(cnitest.Required) == "required" {
			t.Fatal("EZGH_CNI_PORTMAP isn't set")
		}
		t.Skip("EZGH_CNI_PORTMAP isn't set")
	}
	s := newSetup(t)
	pod := cnitest.NS(t)
	prev := s.add(t, "c1", pod)
	conf := `{"cniVersion":"1.0.0","name":"ezgh-vpc-cni","type":"portmap","backend":"nftables","capabilities":{"portMappings":true},` +
		`"runtimeConfig":{"portMappings":[{"hostPort":30080,"containerPort":80,"protocol":"tcp"}]},"prevResult":` + prev + `}`
	portmap := func(command string) {
		t.Helper()
		var out []byte
		err := s.node.NS.Do(func(ns.NetNS) error {
			cmd := exec.Command(bin)
			cmd.Env = append(os.Environ(), "CNI_COMMAND="+command, "CNI_CONTAINERID=c1", "CNI_NETNS="+pod.Path(), "CNI_IFNAME=eth0", "CNI_PATH="+filepath.Dir(bin))
			cmd.Stdin = strings.NewReader(conf)
			var err error
			out, err = cmd.CombinedOutput()
			return err
		})
		if err != nil {
			t.Fatalf("portmap %s: %v\n%s", command, err, out)
		}
	}
	portmap("ADD")
	peers := cnitest.Listen(t, pod, "10.240.1.16:80")
	c, err := cnitest.Dial(s.node.Inet, cnitest.NodePub4+":30080", 5*time.Second)
	if err != nil {
		t.Fatalf("hostPort: %v\n%s", err, cnitest.Sh(t, s.node.NS, "nft list ruleset"))
	}
	c.Close()
	if p := (<-peers).(*net.TCPAddr).IP.String(); p != "203.0.113.1" {
		t.Fatalf("pod saw %s", p)
	}
	portmap("CHECK")
	if err := s.run(t, cmdCheck, "c1", pod, prev); err != nil {
		t.Fatal(err)
	}
	portmap("DEL")
	if err := s.run(t, cmdDel, "c1", pod, prev); err != nil {
		t.Fatal(err)
	}
	if c, err := cnitest.Dial(s.node.Inet, cnitest.NodePub4+":30080", time.Second); err == nil {
		c.Close()
		t.Fatal("hostPort still open after DEL")
	}
}
