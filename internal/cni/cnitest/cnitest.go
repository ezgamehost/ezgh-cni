//go:build linux

// Package cnitest builds throwaway network namespaces for the kernel tests (build tag netns, as
// root: CI's netns job, or scripts/netns-test.sh in Apple container on a Mac). Nothing touches the
// namespace the tests run in.
package cnitest

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

// Required is set to "required" by CI and test.sh: a kernel test that would skip fails instead.
const Required = "EZGH_CNI_KERNEL_TESTS"

// NS is a new namespace, removed when the test ends.
func NS(t *testing.T) ns.NetNS {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv(Required) == "required" {
			t.Fatal("kernel tests need root")
		}
		t.Skip("needs root (sudo go test -tags netns)")
	}
	n, err := testutils.NewNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close(); _ = testutils.UnmountNS(n) })
	Sh(t, n, "ip link set lo up")
	return n
}

// NeedDummy skips a test that makes a dummy link where the kernel has none (Apple container's;
// test.sh sets EZGH_CNI_NO_DUMMY): CI's runner and the node image have them.
func NeedDummy(t *testing.T) {
	t.Helper()
	if os.Getenv("EZGH_CNI_NO_DUMMY") == "1" {
		t.Skip("this kernel has no dummy links; CI's netns job runs this test")
	}
}

// Name is the namespace's name for `ip netns exec` and `ip link … netns`.
func Name(n ns.NetNS) string { return filepath.Base(n.Path()) }

// Sh runs script in n.
func Sh(t *testing.T, n ns.NetNS, script string) string {
	t.Helper()
	var out []byte
	err := n.Do(func(ns.NetNS) error {
		var err error
		out, err = exec.Command("sh", "-ec", script).CombinedOutput()
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
	return string(out)
}

// Do runs f in n.
func Do(t *testing.T, n ns.NetNS, f func() error) {
	t.Helper()
	if err := n.Do(func(ns.NetNS) error { return f() }); err != nil {
		t.Fatal(err)
	}
}

// Listen opens a TCP listener in n that accepts and records each peer's address.
func Listen(t *testing.T, n ns.NetNS, addr string) <-chan net.Addr {
	t.Helper()
	var l net.Listener
	Do(t, n, func() (err error) { l, err = net.Listen("tcp", addr); return err })
	t.Cleanup(func() { l.Close() })
	peers := make(chan net.Addr, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			peers <- c.RemoteAddr()
			c.Close()
		}
	}()
	return peers
}

// Dial connects from n.
func Dial(n ns.NetNS, addr string, timeout time.Duration) (net.Conn, error) {
	var c net.Conn
	err := n.Do(func(ns.NetNS) (err error) { c, err = net.DialTimeout("tcp", addr, timeout); return err })
	return c, err
}

// Node is a node's namespace beside a VPC peer and the internet:
//
//	node enp2s0 10.240.1.5/24 fdcc:1:2:1::5/64 (MTU 8900) ── vpc 10.240.1.1, fdcc:1:2:1::1; lo 10.240.2.10, fdcc:1:2:2::10
//	node pub 203.0.113.2/24 2001:db8::2/64 (default) ────── inet 203.0.113.1, 2001:db8::1; lo 198.51.100.7,
//	                                                          2001:db8:ffff::7 and the metadata addresses
//
// Table 101 holds only the VPC's routes, as the seed renders it for a private interface at device
// index 1; main has them too. The VPC routes the delegated prefixes to the node (netd's job).
type Node struct{ NS, VPC, Inet ns.NetNS }

const (
	Private  = "enp2s0"
	Prefix4  = "10.240.1.16/28"
	Prefix6  = "fdcc:1:2:1:c4a4::/80"
	Table    = 101
	VPCPeer4 = "10.240.2.10"
	VPCPeer6 = "fdcc:1:2:2::10"
	Inet4    = "198.51.100.7"
	Inet6    = "2001:db8:ffff::7"
	NodePub4 = "203.0.113.2"
)

func NewNode(t *testing.T, pubMTU int) *Node {
	t.Helper()
	n := &Node{NS: NS(t), VPC: NS(t), Inet: NS(t)}
	Sh(t, n.NS, `
sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv4.conf.all.arp_announce=2 net.ipv4.conf.default.arp_announce=2
ip link add `+Private+` mtu 8900 type veth peer name eth0 mtu 8900 netns `+Name(n.VPC)+`
ip link add pub mtu `+strconv.Itoa(pubMTU)+` type veth peer name eth0 mtu 9000 netns `+Name(n.Inet)+`
ip addr add 10.240.1.5/24 dev `+Private+`
ip -6 addr add fdcc:1:2:1::5/64 dev `+Private+` nodad
ip addr add `+NodePub4+`/24 dev pub
ip -6 addr add 2001:db8::2/64 dev pub nodad
ip link set `+Private+` up
ip link set pub up
ip route add default via 203.0.113.1
ip -6 route add default via 2001:db8::1
for t in main 101; do
  ip route add 10.240.0.0/16 via 10.240.1.1 table $t
  ip -6 route add fdcc:1:2::/56 via fdcc:1:2:1::1 table $t
done`)
	Sh(t, n.VPC, `
ip addr add 10.240.1.1/24 dev eth0
ip -6 addr add fdcc:1:2:1::1/64 dev eth0 nodad
ip link set eth0 up
ip addr add `+VPCPeer4+`/32 dev lo
ip -6 addr add `+VPCPeer6+`/128 dev lo
ip route add `+Prefix4+` via 10.240.1.5
ip -6 route add `+Prefix6+` via fdcc:1:2:1::5`)
	Sh(t, n.Inet, `
ip addr add 203.0.113.1/24 dev eth0
ip -6 addr add 2001:db8::1/64 dev eth0 nodad
ip link set eth0 up
for a in 169.254.169.254 `+Inet4+`; do ip addr add $a/32 dev lo; done
for a in fd65:7a67:6800::254 `+Inet6+`; do ip -6 addr add $a/128 dev lo; done`)
	for _, l := range []struct {
		ns   ns.NetNS
		link string
	}{{n.NS, Private}, {n.NS, "pub"}, {n.VPC, "eth0"}, {n.Inet, "eth0"}} {
		WaitUp(t, l.ns, l.link)
	}
	return n
}

// WaitUp waits for link's carrier: a new veth carries nothing until linkwatch brings it up.
func WaitUp(t *testing.T, n ns.NetNS, link string) {
	t.Helper()
	Sh(t, n, "for i in $(seq 100); do ip link show "+link+" | grep -q 'state UP' && exit 0; sleep 0.05; done; exit 1")
}
