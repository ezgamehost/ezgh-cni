package ipamd

import (
	"os"
	"testing"

	"github.com/containernetworking/cni/libcni"
)

// The node's conflist: ezgh-vpc-cni, then upstream portmap for hostPort (nftables).
func TestConflistGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/10-ezgh-vpc-cni.conflist")
	if err != nil || conflist != string(want) {
		t.Fatalf("%v\n%s", err, conflist)
	}
	l, err := libcni.NetworkConfFromBytes([]byte(conflist))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Plugins) != 2 || l.Plugins[0].Network.Type != "ezgh-vpc-cni" || l.Plugins[1].Network.Type != "portmap" ||
		!l.Plugins[1].Network.Capabilities["portMappings"] {
		t.Fatalf("%+v", l.Plugins)
	}
}
