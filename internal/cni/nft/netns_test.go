//go:build netns && linux

package nft_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"

	"github.com/ezgamehost/ezgh-cni/internal/cni/cnitest"
	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
	"github.com/ezgamehost/ezgh-cni/internal/cni/nft"
	"github.com/ezgamehost/ezgh-cni/internal/cni/plugin"
)

const pod4, pod6 = "10.240.1.16", "fdcc:1:2:1:c4a4::16"

// node is cnitest's node with ipamd's kernel state and one pod wired by the plugin.
func node(t *testing.T, pubMTU int) (*cnitest.Node, ns.NetNS) {
	n := cnitest.NewNode(t, pubMTU)
	p4, p6 := netip.MustParsePrefix(cnitest.Prefix4), netip.MustParsePrefix(cnitest.Prefix6)
	cnitest.Do(t, n.NS, func() error {
		if err := (ipamd.Kernel{}).SetPrefixRules([]netip.Prefix{p4, p6}, cnitest.Table); err != nil {
			return err
		}
		return nft.Apply(context.Background(), nft.Base(nft.Rules{PrivateLink: cnitest.Private, Prefixes4: []netip.Prefix{p4}, Prefixes6: []netip.Prefix{p6}}))
	})
	pod := cnitest.NS(t)
	cnitest.Do(t, n.NS, func() error {
		_, err := plugin.Wire(pod.Path(), "pod1", "eth0", ipamd.AddResponse{IPv4: netip.MustParseAddr(pod4), IPv6: netip.MustParseAddr(pod6), MTU: 8900, HostTable: cnitest.Table})
		return err
	})
	cnitest.WaitUp(t, pod, "eth0")
	cnitest.WaitUp(t, n.NS, plugin.VethName("pod1", "eth0"))
	return n, pod
}

func noPeer(t *testing.T, peers <-chan net.Addr) {
	t.Helper()
	select {
	case p := <-peers:
		t.Fatalf("a connection arrived from %v", p)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestGoldenLoads(t *testing.T) {
	n := cnitest.NS(t)
	raw, err := os.ReadFile("testdata/base.nft")
	if err != nil {
		t.Fatal(err)
	}
	cnitest.Do(t, n, func() error {
		// Twice: the second replaces the first whole.
		if err := nft.Apply(context.Background(), string(raw)); err != nil {
			return err
		}
		return nft.Apply(context.Background(), string(raw))
	})
	out := cnitest.Sh(t, n, "nft list table inet ezgh_cni")
	for _, want := range []string{"hook forward priority filter - 10", "masquerade fully-random", "reject with tcp reset", "10.240.1.32/28"} {
		if !strings.Contains(out, want) {
			t.Fatalf("no %q in\n%s", want, out)
		}
	}
}

func TestMetadataDropBeforeMasquerade(t *testing.T) {
	n, pod := node(t, 1500)
	for _, addr := range []string{"169.254.169.254:80", "[fd65:7a67:6800::254]:80"} {
		peers := cnitest.Listen(t, n.Inet, addr)
		if c, err := cnitest.Dial(pod, addr, time.Second); err == nil {
			c.Close()
			t.Fatalf("pod reached %s", addr)
		}
		noPeer(t, peers)
		// hostNetwork: the node itself still reaches metadata.
		c, err := cnitest.Dial(n.NS, addr, 5*time.Second)
		if err != nil {
			t.Fatalf("node to %s: %v", addr, err)
		}
		c.Close()
		<-peers
	}
}

// The control: without the two drop rules, the masquerade makes the pod the node, which metadata
// admits. IPv6 is still refused, by the IPv6-to-internet reset.
func TestMetadataReachableWithoutDrop(t *testing.T) {
	n, pod := node(t, 1500)
	cnitest.Sh(t, n.NS, `for h in $(nft -a list chain inet ezgh_cni forward | awk '/daddr (169.254.169.254|fd65:7a67:6800::254) drop/ {print $NF}'); do
  nft delete rule inet ezgh_cni forward handle $h
done
! nft list chain inet ezgh_cni forward | grep -q ' drop'`)
	peers := cnitest.Listen(t, n.Inet, "169.254.169.254:80")
	c, err := cnitest.Dial(pod, "169.254.169.254:80", 5*time.Second)
	if err != nil {
		t.Fatalf("without the drop: %v", err)
	}
	c.Close()
	if p := (<-peers).(*net.TCPAddr); p.IP.String() != cnitest.NodePub4 {
		t.Fatalf("metadata saw %s, want the node's %s", p.IP, cnitest.NodePub4)
	}
	cnitest.Listen(t, n.Inet, "[fd65:7a67:6800::254]:80")
	if _, err := cnitest.Dial(pod, "[fd65:7a67:6800::254]:80", 5*time.Second); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("IPv6 metadata without the drop: %v", err)
	}
}

func TestServiceDNATToMetadataDropped(t *testing.T) {
	n, pod := node(t, 1500)
	cnitest.Sh(t, n.NS, `nft -f - <<'EOF'
table ip svc {
	chain pre { type nat hook prerouting priority dstnat; ip daddr 10.100.0.50 tcp dport 80 dnat to 169.254.169.254:80; }
}
EOF`)
	peers := cnitest.Listen(t, n.Inet, "169.254.169.254:80")
	if c, err := cnitest.Dial(pod, "10.100.0.50:80", time.Second); err == nil {
		c.Close()
		t.Fatal("pod reached metadata through a Service")
	}
	noPeer(t, peers)
}

func TestMasqueradeOnlyOffPrivate(t *testing.T) {
	n, pod := node(t, 1500)
	for _, tc := range []struct {
		ns     ns.NetNS
		listen string
		source string
	}{
		{n.Inet, cnitest.Inet4 + ":8080", cnitest.NodePub4},
		{n.VPC, cnitest.VPCPeer4 + ":8080", pod4},
		{n.VPC, "[" + cnitest.VPCPeer6 + "]:8080", pod6},
	} {
		peers := cnitest.Listen(t, tc.ns, tc.listen)
		c, err := cnitest.Dial(pod, tc.listen, 5*time.Second)
		if err != nil {
			t.Fatalf("%s: %v\nnode:\n%s\nvpc:\n%s\npod:\n%s", tc.listen, err,
				cnitest.Sh(t, n.NS, "ip -6 addr; ip -6 rule; ip -6 route show table all; ip -6 neigh; nft list ruleset"),
				cnitest.Sh(t, n.VPC, "ip -6 addr; ip -6 route; ip -6 neigh"), cnitest.Sh(t, pod, "ip -6 addr; ip -6 route; ip -6 neigh"))
		}
		c.Close()
		if p := (<-peers).(*net.TCPAddr); p.IP.String() != tc.source {
			t.Fatalf("%s saw %s, want %s", tc.listen, p.IP, tc.source)
		}
	}
}

func TestIPv6InternetRejected(t *testing.T) {
	n, pod := node(t, 1500)
	peers := cnitest.Listen(t, n.Inet, "["+cnitest.Inet6+"]:8080")
	start := time.Now()
	_, err := cnitest.Dial(pod, "["+cnitest.Inet6+"]:8080", 3*time.Second)
	if err == nil || time.Since(start) > 500*time.Millisecond || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	noPeer(t, peers)
	// IPv4 to the internet isn't reset.
	cnitest.Listen(t, n.Inet, cnitest.Inet4+":8080")
	c, err := cnitest.Dial(pod, cnitest.Inet4+":8080", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestPodIdentityIsLocal(t *testing.T) {
	cnitest.NeedDummy(t)
	n, pod := node(t, 1500)
	cnitest.Do(t, n.NS, ipamd.Kernel{}.EnsurePIA)
	peers := cnitest.Listen(t, n.NS, ipamd.PIAAddress+":80")
	c, err := cnitest.Dial(pod, ipamd.PIAAddress+":80", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if p := (<-peers).(*net.TCPAddr); p.IP.String() != pod4 {
		t.Fatalf("agent saw %s", p.IP)
	}
	if out := cnitest.Sh(t, n.NS, "ip -6 addr show dev ezgh-pia scope global"); out != "" {
		t.Fatalf("ezgh-pia holds IPv6: %s", out)
	}
}

func TestMSSClamped(t *testing.T) {
	n, pod := node(t, 1400)
	var l net.Listener
	cnitest.Do(t, n.Inet, func() (err error) { l, err = net.Listen("tcp", cnitest.Inet4+":8080"); return err })
	defer l.Close()
	mss := make(chan int, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			mss <- -1
			return
		}
		defer c.Close()
		raw, _ := c.(*net.TCPConn).SyscallConn()
		raw.Control(func(fd uintptr) {
			v, _ := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
			mss <- v
		})
	}()
	c, err := cnitest.Dial(pod, cnitest.Inet4+":8080", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := <-mss; got <= 0 || got > 1360 {
		t.Fatalf("MSS %d through a 1400 MTU", got)
	}
}

// TestNewNodeNoTentative: cnitest's node is past duplicate address detection, as a real node is long
// before its first pod. While the private link's link-local is tentative the kernel sends no neighbour
// solicitation for forwarded traffic (ndisc_send_ns needs a usable link-local source), so the pod's
// IPv6 into the VPC in TestMasqueradeOnlyOffPrivate failed "no route to host" when the runner was slow.
func TestNewNodeNoTentative(t *testing.T) {
	n := cnitest.NewNode(t, 1500)
	for name, x := range map[string]ns.NetNS{"node": n.NS, "vpc": n.VPC, "inet": n.Inet} {
		if out := cnitest.Sh(t, x, "ip -6 addr show tentative"); out != "" {
			t.Errorf("%s has tentative addresses:\n%s", name, out)
		}
	}
}
