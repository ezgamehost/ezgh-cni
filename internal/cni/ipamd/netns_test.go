//go:build netns && linux

package ipamd

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ezgamehost/ezgh-cni/internal/cni/cnitest"
)

func TestKernelPIALink(t *testing.T) {
	cnitest.NeedDummy(t)
	n := cnitest.NS(t)
	cnitest.Do(t, n, Kernel{}.EnsurePIA)
	cnitest.Sh(t, n, "ip link del "+PIALink) // gone, as after a reboot: recreated
	cnitest.Do(t, n, Kernel{}.EnsurePIA)
	cnitest.Do(t, n, Kernel{}.EnsurePIA)
	out := cnitest.Sh(t, n, "ip -o addr show dev "+PIALink+" scope global")
	if strings.Count(out, "inet") != 1 || !strings.Contains(out, "inet "+PIAAddress+"/32") {
		t.Fatal(out)
	}
	if !strings.Contains(cnitest.Sh(t, n, "ip -o link show "+PIALink), "UP") {
		t.Fatal("ezgh-pia down")
	}
}

func TestKernelPrefixRules(t *testing.T) {
	n := cnitest.NS(t)
	a, b, v6 := netip.MustParsePrefix("10.240.1.16/28"), netip.MustParsePrefix("10.240.1.32/28"), netip.MustParsePrefix("fdcc:1:2:1:c4a4::/80")
	cnitest.Do(t, n, func() error { return Kernel{}.SetPrefixRules([]netip.Prefix{a, b, v6}, 101) })
	cnitest.Do(t, n, func() error { return Kernel{}.SetPrefixRules([]netip.Prefix{a, b, v6}, 101) })
	got := cnitest.Sh(t, n, "ip rule show pref 1536; ip -6 rule show pref 1536")
	for _, want := range []string{"from 10.240.1.16/28 lookup 101 suppress_prefixlength 0", "from 10.240.1.32/28 lookup 101 suppress_prefixlength 0", "from fdcc:1:2:1:c4a4::/80 lookup 101 suppress_prefixlength 0"} {
		if strings.Count(got, want) != 1 {
			t.Fatalf("want one %q in\n%s", want, got)
		}
	}
	cnitest.Do(t, n, func() error { return Kernel{}.SetPrefixRules([]netip.Prefix{b}, 101) })
	if got := cnitest.Sh(t, n, "ip rule show pref 1536; ip -6 rule show pref 1536"); strings.Count(got, "from") != 1 || !strings.Contains(got, "10.240.1.32/28") {
		t.Fatal(got)
	}
}

func TestHostVethsSeesPodRoute(t *testing.T) {
	n := cnitest.NS(t)
	// A pod's veth and /32 as the plugin leaves them, beside a non-pod link and a non-host route.
	cnitest.Sh(t, n, `ip link add ezp0123456789ab type veth peer name pod0
ip link add other0 type veth peer name other1
ip link set ezp0123456789ab up; ip link set pod0 up; ip link set other0 up; ip link set other1 up
ip route add 10.240.1.17/32 dev ezp0123456789ab
ip route add 10.240.1.18/32 dev other0
ip route add 10.240.2.0/24 dev ezp0123456789ab`)
	var got map[netip.Addr]string
	cnitest.Do(t, n, func() (err error) { got, err = Kernel{}.HostVeths(); return err })
	if len(got) != 1 || got[netip.MustParseAddr("10.240.1.17")] != "ezp0123456789ab" {
		t.Fatal(got)
	}
	cnitest.Sh(t, n, "ip link del ezp0123456789ab") // the pod is gone: so is its route
	cnitest.Do(t, n, func() (err error) { got, err = Kernel{}.HostVeths(); return err })
	if len(got) != 0 {
		t.Fatal(got)
	}
}
