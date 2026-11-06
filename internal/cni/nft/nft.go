// Package nft is the node's base nftables table, inet ezgh_cni, which ipamd owns: pods never reach
// instance metadata (the drop sits in forward, ahead of the masquerade in postrouting, so a
// Service DNAT or the node's SNAT can't carry a pod there), pod IPv4 to the internet SNATs to the
// node (DP5), pod IPv6 reaches the VPC only and anything else is refused at once, and SYNs leaving
// off the private interface clamp their MSS to the route's MTU.
package nft

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

const Table = "ezgh_cni"

// Rules are the node's facts the table depends on.
type Rules struct {
	PrivateLink          string
	Prefixes4, Prefixes6 []netip.Prefix
}

// Base is the whole table, applied in one transaction.
func Base(r Rules) string {
	set := func(name, typ string, ps []netip.Prefix) string {
		s := fmt.Sprintf("\tset %s {\n\t\ttype %s\n\t\tflags interval\n", name, typ)
		if len(ps) > 0 {
			var el []string
			for _, p := range ps {
				el = append(el, p.String())
			}
			s += "\t\telements = { " + strings.Join(el, ", ") + " }\n"
		}
		return s + "\t}\n"
	}
	off := fmt.Sprintf(`oifname != "%s" oifname != "ezp*"`, r.PrivateLink)
	return "table inet " + Table + " {\n" +
		set("prefixes4", "ipv4_addr", r.Prefixes4) +
		set("prefixes6", "ipv6_addr", r.Prefixes6) +
		"\tchain forward {\n" +
		"\t\ttype filter hook forward priority -10; policy accept;\n" +
		"\t\tiifname \"ezp*\" ip daddr 169.254.169.254 drop\n" +
		"\t\tiifname \"ezp*\" ip6 daddr fd65:7a67:6800::254 drop\n" +
		"\t\tiifname \"ezp*\" " + off + " meta nfproto ipv6 meta l4proto tcp reject with tcp reset\n" +
		"\t\tiifname \"ezp*\" " + off + " meta nfproto ipv6 reject with icmpv6 type admin-prohibited\n" +
		"\t\t" + off + " tcp flags syn tcp option maxseg size set rt mtu\n" +
		"\t}\n" +
		"\tchain postrouting {\n" +
		"\t\ttype nat hook postrouting priority srcnat; policy accept;\n" +
		fmt.Sprintf("\t\toifname \"%s\" return\n", r.PrivateLink) +
		"\t\toifname \"ezp*\" return\n" +
		"\t\tip saddr @prefixes4 masquerade fully-random\n" +
		"\t}\n" +
		"}\n"
}

// Apply replaces the table with ruleset in one nft transaction.
func Apply(ctx context.Context, ruleset string) error { return Replace(ctx, Table, ruleset) }

// Script is what nft reads to replace inet table with ruleset: the old table goes and the new one
// lands in the same transaction.
func Script(table, ruleset string) string {
	return "table inet " + table + " {}\ndelete table inet " + table + "\n" + ruleset
}

// Replace replaces inet table with ruleset in one nft transaction.
func Replace(ctx context.Context, table, ruleset string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(Script(table, ruleset))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	return nil
}
