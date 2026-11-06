package plugin

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"

	"github.com/ezgamehost/ezgh-cni/internal/cni/ipamd"
)

func TestVethName(t *testing.T) {
	n := VethName("0123456789abcdef", "eth0")
	if !regexp.MustCompile(`^ezp[0-9a-f]{12}$`).MatchString(n) || len(n) != 15 || n != VethName("0123456789abcdef", "eth0") || n == VethName("0123456789abcdef", "eth1") {
		t.Fatal(n)
	}
	mac := HostMAC("0123456789abcdef", "eth0")
	// Locally administered, unicast, and from the same hash as the name.
	if len(mac) != 6 || mac[0] != 0x0e || mac[0]&1 != 0 || mac[0]&2 == 0 || mac.String() == HostMAC("x", "eth0").String() {
		t.Fatal(mac)
	}
}

func TestResultShape(t *testing.T) {
	r := result("c1", "eth0", "/var/run/netns/p", HostMAC("p", "eth0"), ipamd.AddResponse{IPv4: netip.MustParseAddr("10.240.1.16"), IPv6: netip.MustParseAddr("fdcc::1:0:0:5"), MTU: 8900, HostTable: 101})
	if len(r.IPs) != 2 || r.IPs[0].Address.String() != "10.240.1.16/32" || r.IPs[0].Gateway.String() != "169.254.1.1" ||
		r.IPs[1].Address.String() != "fdcc::1:0:0:5/128" || r.IPs[1].Gateway.String() != "fe80::1" || *r.IPs[0].Interface != 1 {
		b, _ := json.Marshal(r)
		t.Fatal(string(b))
	}
	if r.Interfaces[0].Name != VethName("c1", "eth0") || r.Interfaces[1].Sandbox != "/var/run/netns/p" {
		t.Fatalf("%+v", r.Interfaces)
	}
}

func TestIpamdDownIsAnError(t *testing.T) {
	c := &NetConf{Socket: "/nonexistent/ipamd.sock"}
	_, err := Add(c, &skel.CmdArgs{ContainerID: "c1", IfName: "eth0", Netns: "/nonexistent/netns", Args: "K8S_POD_NAMESPACE=default;K8S_POD_NAME=p"})
	if err == nil || !strings.Contains(err.Error(), "/nonexistent/ipamd.sock") || !strings.HasPrefix(err.Error(), "ezgh-vpc-cni: ") {
		t.Fatal(err)
	}
}
