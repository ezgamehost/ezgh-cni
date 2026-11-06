//go:build linux

package ipamd

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
)

func (Kernel) LinkByMAC(mac string) (string, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", err
	}
	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}
	for _, l := range links {
		if bytes.Equal(l.Attrs().HardwareAddr, hw) && !strings.HasPrefix(l.Attrs().Name, "ezp") {
			return l.Attrs().Name, nil
		}
	}
	return "", errors.New("no link has that MAC")
}

func (Kernel) EnsurePIA() error {
	l, err := netlink.LinkByName(PIALink)
	if _, missing := err.(netlink.LinkNotFoundError); missing {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: PIALink}}); err != nil {
			return err
		}
		l, err = netlink.LinkByName(PIALink)
	}
	if err != nil {
		return err
	}
	addr, _ := netlink.ParseAddr(PIAAddress + "/32")
	if err := netlink.AddrReplace(l, addr); err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

func (Kernel) SetPrefixRules(prefixes []netip.Prefix, table int) error {
	want := map[netip.Prefix]bool{}
	for _, p := range prefixes {
		want[p] = true
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleListFiltered(family, &netlink.Rule{Priority: PrefixRulePref}, netlink.RT_FILTER_PRIORITY)
		if err != nil {
			return err
		}
		for _, r := range rules {
			var src netip.Prefix
			if r.Src != nil {
				a, _ := netip.AddrFromSlice(r.Src.IP)
				ones, _ := r.Src.Mask.Size()
				src = netip.PrefixFrom(a.Unmap(), ones)
			}
			if want[src] && r.Table == table && r.SuppressPrefixlen == 0 {
				delete(want, src)
				continue
			}
			if err := netlink.RuleDel(&r); err != nil {
				return fmt.Errorf("delete rule %v: %w", r, err)
			}
		}
	}
	for p := range want {
		r := netlink.NewRule()
		r.Family = netlink.FAMILY_V4
		if p.Addr().Is6() {
			r.Family = netlink.FAMILY_V6
		}
		r.Src = &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
		r.Table, r.Priority, r.SuppressPrefixlen = table, PrefixRulePref, 0
		if err := netlink.RuleAdd(r); err != nil {
			return fmt.Errorf("add rule from %s: %w", p, err)
		}
	}
	return nil
}
