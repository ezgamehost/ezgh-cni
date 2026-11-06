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
