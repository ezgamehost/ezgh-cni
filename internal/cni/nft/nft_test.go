package nft

import (
	"net/netip"
	"os"
	"testing"
)

var golden = Rules{
	PrivateLink: "enp2s0",
	Prefixes4:   []netip.Prefix{netip.MustParsePrefix("10.240.1.16/28"), netip.MustParsePrefix("10.240.1.32/28")},
	Prefixes6:   []netip.Prefix{netip.MustParsePrefix("fd12:3456:789a:2800:c4a4::/80")},
}

func TestBaseGolden(t *testing.T) {
	for file, r := range map[string]Rules{"testdata/base.nft": golden, "testdata/base-empty.nft": {PrivateLink: "enp2s0"}} {
		want, err := os.ReadFile(file)
		if os.Getenv("UPDATE_GOLDEN") != "" {
			err = os.WriteFile(file, []byte(Base(r)), 0o644)
			want = []byte(Base(r))
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := Base(r); got != string(want) {
			t.Fatalf("%s:\n%s", file, got)
		}
	}
}
