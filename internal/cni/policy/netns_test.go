//go:build netns && linux

package policy

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/ezgamehost/ezgh-cni/internal/cni/cnitest"
	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
	"github.com/ezgamehost/ezgh-cni/internal/cni/nft"
	"github.com/ezgamehost/ezgh-cni/internal/cni/plugin"
)

// kernelNode is cnitest's node with ipamd's base table and three pods in shop wired by the plugin:
// web .16, db .17, other .18.
type kernelNode struct {
	*cnitest.Node
	pods map[string]ns.NetNS
	ips  map[string][]netip.Addr
}

func newKernelNode(t *testing.T) *kernelNode {
	n := &kernelNode{Node: cnitest.NewNode(t, 1500), pods: map[string]ns.NetNS{}, ips: map[string][]netip.Addr{}}
	p4, p6 := netip.MustParsePrefix(cnitest.Prefix4), netip.MustParsePrefix(cnitest.Prefix6)
	cnitest.Do(t, n.NS, func() error {
		if err := (ipamd.Kernel{}).SetPrefixRules([]netip.Prefix{p4, p6}, cnitest.Table); err != nil {
			return err
		}
		return nft.Apply(context.Background(), nft.Base(nft.Rules{PrivateLink: cnitest.Private, Prefixes4: []netip.Prefix{p4}, Prefixes6: []netip.Prefix{p6}}))
	})
	for i, name := range []string{"web", "db", "other"} {
		pod := cnitest.NS(t)
		ip4, ip6 := netip.AddrFrom4([4]byte{10, 240, 1, byte(16 + i)}), netip.MustParseAddr("fdcc:1:2:1:c4a4::"+string(rune('a'+i)))
		cnitest.Do(t, n.NS, func() error {
			_, err := plugin.Wire(pod.Path(), name, "eth0", ipamd.AddResponse{IPv4: ip4, IPv6: ip6, MTU: 8900, HostTable: cnitest.Table})
			return err
		})
		cnitest.WaitUp(t, pod, "eth0")
		cnitest.WaitUp(t, n.NS, plugin.VethName(name, "eth0"))
		n.pods[name], n.ips[name] = pod, []netip.Addr{ip4, ip6}
	}
	return n
}

// enforce compiles pols for the node's pods, veths found as the agent finds them, and applies it.
func (n *kernelNode) enforce(t *testing.T, pols ...networkingv1.NetworkPolicy) {
	t.Helper()
	cnitest.Do(t, n.NS, func() error {
		veths, err := HostVeths()
		if err != nil {
			return err
		}
		s := State{Namespaces: map[string]map[string]string{"shop": {"kubernetes.io/metadata.name": "shop"}}, Policies: pols}
		for name, ips := range n.ips {
			p := Pod{Namespace: "shop", Name: name, Veth: veths[ips[0]], Labels: map[string]string{"app": name}, IPs: ips,
				Ports: []NamedPort{{"http", "TCP", 8080}}}
			if p.Veth != plugin.VethName(name, "eth0") {
				t.Fatalf("%s: veth %q", name, p.Veth)
			}
			s.Local, s.All = append(s.Local, p), append(s.All, p)
		}
		return nft.Replace(context.Background(), Table, Compile(s))
	})
}

func (n *kernelNode) addr(name string, family int, port string) string {
	a := n.ips[name][family]
	if a.Is6() {
		return "[" + a.String() + "]:" + port
	}
	return a.String() + ":" + port
}

func connects(t *testing.T, from ns.NetNS, addr string) {
	t.Helper()
	c, err := cnitest.Dial(from, addr, 5*time.Second)
	if err != nil {
		t.Fatalf("%s: %v", addr, err)
	}
	c.Close()
}

// refused: the reject answers at once, so nothing waits on a timeout.
func refused(t *testing.T, from ns.NetNS, addr string) {
	t.Helper()
	start := time.Now()
	c, err := cnitest.Dial(from, addr, 3*time.Second)
	if err == nil {
		c.Close()
		t.Fatalf("%s connected", addr)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("%s: %v after %v", addr, err, d)
	}
}

var fromWebOnHTTP = pol("db", sel("app", "db"), ingress, []networkingv1.NetworkPolicyIngressRule{{
	From:  []networkingv1.NetworkPolicyPeer{{PodSelector: sel("app", "web")}},
	Ports: []networkingv1.NetworkPolicyPort{port(tcp, intstr.FromString("http"), 0)},
}}, nil)

func TestGoldensLoad(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.nft")
	n := cnitest.NS(t)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		cnitest.Do(t, n, func() error { return nft.Replace(context.Background(), Table, string(raw)) })
	}
	if len(files) < 10 {
		t.Fatal(files)
	}
}

func TestDenyThenAllow(t *testing.T) {
	n := newKernelNode(t)
	for _, fam := range []int{0, 1} {
		cnitest.Listen(t, n.pods["db"], n.addr("db", fam, "8080"))
		connects(t, n.pods["other"], n.addr("db", fam, "8080"))
	}
	n.enforce(t, fromWebOnHTTP)
	for _, fam := range []int{0, 1} {
		refused(t, n.pods["other"], n.addr("db", fam, "8080"))
		connects(t, n.pods["web"], n.addr("db", fam, "8080"))
	}
}

func TestRepliesFlow(t *testing.T) {
	n := newKernelNode(t)
	cnitest.Listen(t, n.pods["db"], n.addr("db", 0, "8080"))
	cnitest.Listen(t, n.pods["web"], n.addr("web", 0, "8080"))
	n.enforce(t, pol("db", sel("app", "db"), egress, nil, nil))
	// db can't open a connection, but its replies to one it accepted flow.
	connects(t, n.pods["web"], n.addr("db", 0, "8080"))
	refused(t, n.pods["db"], n.addr("web", 0, "8080"))
}

func TestServiceTrafficFilteredAfterDNAT(t *testing.T) {
	n := newKernelNode(t)
	cnitest.Sh(t, n.NS, `nft -f - <<'EOF'
table ip svc {
	chain pre { type nat hook prerouting priority dstnat; ip daddr 10.100.0.60 tcp dport 80 dnat to 10.240.1.17:8080; }
}
EOF`)
	cnitest.Listen(t, n.pods["db"], n.addr("db", 0, "8080"))
	n.enforce(t, fromWebOnHTTP)
	refused(t, n.pods["other"], "10.100.0.60:80")
	connects(t, n.pods["web"], "10.100.0.60:80")
}

func TestNodeReachesIsolatedPod(t *testing.T) {
	n := newKernelNode(t)
	n.enforce(t, pol("db", sel("app", "db"), ingress, nil, nil))
	for _, fam := range []int{0, 1} {
		cnitest.Listen(t, n.pods["db"], n.addr("db", fam, "8080"))
		connects(t, n.NS, n.addr("db", fam, "8080"))
		refused(t, n.pods["web"], n.addr("db", fam, "8080"))
	}
}
